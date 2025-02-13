package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	quic "github.com/quic-go/quic-go"
)

// Config holds all parameters loaded from the config file.
type Config struct {
	LocalProxyAddr string   `json:"local_proxy_addr"` // e.g., "127.0.0.1:8443"
	OOBPort        string   `json:"oob_port"`         // e.g., "[::]:8008"
	OOBPeers       []string `json:"oob_peers"`        // list of OOB peer addresses (Yggdrasil addresses)
	FakeSNI        string   `json:"fake_sni"`         // what the client sees (e.g., "harvard.edu")
	RealSNI        string   `json:"real_sni"`         // actual target (e.g., "wikipedia.org")
}

var config Config
var currentOOBPeer int = 0

func main() {
	// Read configuration file from command-line flag
	configPath := flag.String("config", "config.json", "Path to configuration file")
	flag.Parse()

	if err := loadConfig(*configPath); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Start both TLS proxy and OOB listener concurrently.
	go startTLSProxy()
	go startOOBListener()

	// Run indefinitely.
	select {}
}

func loadConfig(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	return decoder.Decode(&config)
}

// startTLSProxy listens for incoming TLS connections.
func startTLSProxy() {
	listener, err := net.Listen("tcp", config.LocalProxyAddr)
	if err != nil {
		log.Fatalf("❌ Failed to start TLS Proxy: %v", err)
	}
	defer listener.Close()
	fmt.Println("🔹 TLS Proxy listening on", config.LocalProxyAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("❌ Connection error:", err)
			continue
		}
		go handleTLSConnection(conn)
	}
}

// handleTLSConnection processes an incoming TLS connection.
func handleTLSConnection(clientConn net.Conn) {
	defer clientConn.Close()
	fmt.Println("🔹 Incoming TLS connection")

	// In our design the client sends a TLS handshake with the fake SNI.
	// We also want to send the real SNI via the OOB channel.
	go sendOOBMessage(config.RealSNI)

	// Now, make a direct TLS connection to the remote server using fake SNI.
	// (The idea is that the remote peer—using the OOB info—will know to dial config.RealSNI.)
	targetConn, err := tls.Dial("tcp", config.FakeSNI+":443", &tls.Config{ServerName: config.FakeSNI})
	if err != nil {
		log.Println("❌ ERROR: Failed to connect to remote server (fake SNI):", err)
		return
	}
	defer targetConn.Close()

	fmt.Println("🔹 Connected to remote server using fake SNI:", config.FakeSNI)
	// Relay data bi-directionally.
	go io.Copy(targetConn, clientConn)
	io.Copy(clientConn, targetConn)
}

// startOOBListener starts a QUIC listener on the configured OOB port.
func startOOBListener() {
	// Bind to all IPv6 interfaces so that we pick up our Yggdrasil interface.
	listener, err := quic.ListenAddr(config.OOBPort, generateTLSConfig(), nil)
	if err != nil {
		log.Fatalf("❌ ERROR: Failed to start OOB listener: %v", err)
	}
	fmt.Println("🔹 OOB Listener started on", config.OOBPort)

	for {
		session, err := listener.Accept(context.Background())
		if err != nil {
			log.Println("❌ ERROR: Failed to accept OOB session:", err)
			continue
		}
		fmt.Println("🔹 OOB session established")
		go handleOOBSession(session)
	}
}

// handleOOBSession reads the real SNI from an incoming QUIC stream.
func handleOOBSession(session quic.Connection) {
	stream, err := session.AcceptStream(context.Background())
	if err != nil {
		log.Println("❌ ERROR: Failed to accept OOB stream:", err)
		return
	}
	defer stream.Close()

	buf := make([]byte, 256)
	n, err := stream.Read(buf)
	if err != nil {
		log.Println("❌ ERROR: Reading OOB message failed:", err)
		return
	}
	receivedSNI := string(buf[:n])
	fmt.Println("🔹 Received real SNI via OOB:", receivedSNI)
	// Here you might update internal state or rotate peers as needed.
	// For demonstration, we simply log it.
}

// sendOOBMessage sends the real SNI to one of the configured OOB peers.
// It rotates through the list in case of failure.
func sendOOBMessage(realSNI string) {
	ctx := context.Background()
	peer := config.OOBPeers[currentOOBPeer]
	fmt.Println("🔹 Attempting to send real SNI via OOB to peer:", peer)
	session, err := quic.DialAddr(ctx, peer, &tls.Config{InsecureSkipVerify: true}, nil)
	if err != nil {
		log.Println("❌ ERROR: Failed to open OOB channel to", peer, ":", err)
		// Rotate to next peer
		currentOOBPeer = (currentOOBPeer + 1) % len(config.OOBPeers)
		return
	}
	defer session.CloseWithError(0, "Done")

	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		log.Println("❌ ERROR: Failed to open OOB stream to", peer, ":", err)
		currentOOBPeer = (currentOOBPeer + 1) % len(config.OOBPeers)
		return
	}
	defer stream.Close()

	_, err = stream.Write([]byte(realSNI))
	if err != nil {
		log.Println("❌ ERROR: Writing to OOB stream to", peer, "failed:", err)
		currentOOBPeer = (currentOOBPeer + 1) % len(config.OOBPeers)
		return
	}

	fmt.Println("🔹 Successfully sent real SNI via OOB to", peer, ":", realSNI)
	time.Sleep(200 * time.Millisecond)
}

// generateTLSConfig returns a TLS configuration using a self-signed certificate.
func generateTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{generateSelfSignedCert()},
		NextProtos:   []string{"quic"},
	}
}

// For simplicity, we embed dummy certs here. In production, use proper certificates.
func generateSelfSignedCert() tls.Certificate {
	cert, err := tls.X509KeyPair([]byte(testCert), []byte(testKey))
	if err != nil {
		log.Fatal(err)
	}
	return cert
}

func generateSelfSignedCert() tls.Certificate {
	cert, err := tls.LoadX509KeyPair("cert.pem", "cert.key")
	if err != nil {
		log.Fatal(err)
	}
	return cert
}
