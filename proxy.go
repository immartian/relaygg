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

// Config holds parameters loaded from config.json.
type Config struct {
	LocalProxyAddr string   `json:"local_proxy_addr"` // e.g., "127.0.0.1:8443"
	OOBPort        string   `json:"oob_port"`         // e.g., "[::]:8008"
	OOBPeers       []string `json:"oob_peers"`        // list of OOB peer addresses (Yggdrasil addresses)
	FakeSNI        string   `json:"fake_sni"`         // camouflage domain, e.g., "harvard.edu"
}

var config Config
var currentOOBPeer int = 0

// realSNI is captured from the client's handshake.
var realSNI string

func main() {
	// Load configuration from file
	configPath := flag.String("config", "config.json", "Path to configuration file")
	flag.Parse()
	if err := loadConfig(*configPath); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Start the TLS proxy with SNI interception.
	startTLSProxy()
	startOOBListener()
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

// startTLSProxy starts a TLS listener that intercepts the ClientHello.
func startTLSProxy() {
	listener, err := tls.Listen("tcp", config.LocalProxyAddr, &tls.Config{
		// The GetConfigForClient callback is used to capture the SNI.
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			fmt.Println("DEBUG: Client requested SNI:", chi.ServerName)
			realSNI = chi.ServerName // capture the real SNI from the client
			// For the outward (camouflaged) handshake, we use the fake SNI.
			return &tls.Config{
				ServerName:         config.FakeSNI,
				InsecureSkipVerify: true,
				NextProtos:         []string{"quic"},
			}, nil
		},
	})
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
	fmt.Println("DEBUG: Handling TLS connection from client")

	// Send the real SNI (captured from the ClientHello) via the OOB channel.
	go sendOOBMessage(realSNI)

	// For demonstration, we establish a TLS connection to the camouflage domain.
	targetConn, err := tls.Dial("tcp", config.FakeSNI+":443", &tls.Config{
		ServerName:         config.FakeSNI,
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Println("❌ ERROR: Failed to connect to remote server using fake SNI:", err)
		return
	}
	defer targetConn.Close()
	fmt.Println("DEBUG: Connected to remote server using fake SNI:", config.FakeSNI)
	// Relay data between client and target.
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

// sendOOBMessage sends the real SNI to a remote OOB peer.
func sendOOBMessage(realSNI string) {
	ctx := context.Background()
	if len(config.OOBPeers) == 0 {
		log.Println("❌ No OOB peers configured")
		return
	}
	peer := config.OOBPeers[currentOOBPeer]
	fmt.Println("DEBUG: Attempting to send real SNI via OOB to peer:", peer)

	// Use a TLS config with proper NextProtos for QUIC.
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic"},
	}
	session, err := quic.DialAddr(ctx, peer, tlsConfig, nil)
	if err != nil {
		log.Println("❌ ERROR: Failed to open OOB channel to", peer, ":", err)
		// Rotate to next peer if available.
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
	fmt.Println("DEBUG: Successfully sent real SNI via OOB to", peer, ":", realSNI)
	// Wait a bit to ensure transmission before closing the stream.
	time.Sleep(200 * time.Millisecond)
}

// For QUIC, we need a TLS configuration with a certificate.
// Here we generate a self-signed certificate.
func generateTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{generateSelfSignedCert()},
		NextProtos:   []string{"quic"},
	}
}

func generateSelfSignedCert() tls.Certificate {
	cert, err := tls.LoadX509KeyPair("cert.pem", "cert.key")
	if err != nil {
		log.Fatal(err)
	}
	return cert
}
