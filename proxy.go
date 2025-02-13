package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

// Config struct holds parameters from config.json.
type Config struct {
	LocalProxyAddr string   `json:"local_proxy_addr"`
	OOBPort        string   `json:"oob_port"`
	OOBPeers       []string `json:"oob_peers"`
	FakeSNI        string   `json:"fake_sni"`
}

var config Config
var requestMap sync.Map // Mapping of request ID to real SNI and waiting channel

func main() {
	configPath := flag.String("config", "config.json", "Path to configuration file")
	flag.Parse()
	if err := loadConfig(*configPath); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	fmt.Println("✅ Config loaded successfully")

	// Start TLS proxy in a goroutine
	go startTLSProxy()
	fmt.Println("✅ TLS Proxy initiated")

	// Start the OOB QUIC listener
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

// startTLSProxy starts the TLS proxy with SNI interception.
func startTLSProxy() {
	listener, err := tls.Listen("tcp", config.LocalProxyAddr, &tls.Config{
		GetConfigForClient: handleClientHello,
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

// handleClientHello captures the SNI and modifies it.
func handleClientHello(chi *tls.ClientHelloInfo) (*tls.Config, error) {
	reqID := generateRequestID()
	realSNI := chi.ServerName
	fmt.Println("DEBUG: Captured SNI:", realSNI)

	// Send realSNI via OOB QUIC and wait for response
	respChan := make(chan string, 1)
	requestMap.Store(reqID, respChan)
	go sendOOBMessage(reqID, realSNI)

	// Return modified TLS config with FakeSNI
	return &tls.Config{
		ServerName:         config.FakeSNI,
		InsecureSkipVerify: true,
	}, nil
}

// handleTLSConnection manages TLS handshakes and relays data.
func handleTLSConnection(clientConn net.Conn) {
	defer clientConn.Close()
	fmt.Println("DEBUG: Handling TLS connection from client")

	// Generate a new TLS configuration with FakeSNI
	tlsConfig := &tls.Config{
		ServerName:         config.FakeSNI, // Ensure FakeSNI is injected
		InsecureSkipVerify: true,
	}

	// Connect to FakeSNI destination
	targetConn, err := tls.Dial("tcp", config.FakeSNI+":443", tlsConfig)
	if err != nil {
		log.Println("❌ ERROR: FakeSNI connection failed:", err)
		return
	}
	defer targetConn.Close()
	fmt.Println("DEBUG: Connected to remote server using FakeSNI:", config.FakeSNI)

	// Relay data
	go io.Copy(targetConn, clientConn)
	io.Copy(clientConn, targetConn)
}

// startOOBListener starts a QUIC listener for OOB communication.
func startOOBListener() {
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
		go handleOOBSession(session)
	}
}

// handleOOBSession processes incoming SNI messages and returns responses.
func handleOOBSession(session quic.Connection) {
	stream, err := session.AcceptStream(context.Background())
	if err != nil {
		log.Println("❌ ERROR: Failed to accept OOB stream:", err)
		return
	}
	defer stream.Close()

	// Read request (format: "reqID|realSNI")
	buf := make([]byte, 256)
	n, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		log.Println("❌ ERROR: Reading OOB message failed:", err)
		return
	}
	message := string(buf[:n])
	fmt.Println("🔹 Received OOB:", message)

	// Extract request ID and real SNI
	var reqID, realSNI string
	fmt.Sscanf(message, "%s|%s", &reqID, &realSNI)

	// Find waiting channel and send response
	if ch, ok := requestMap.Load(reqID); ok {
		respChan := ch.(chan string)
		respChan <- realSNI
		requestMap.Delete(reqID)
	}
}

// sendOOBMessage sends the real SNI with a request ID via OOB QUIC.
func sendOOBMessage(reqID, realSNI string) {
	ctx := context.Background()
	if len(config.OOBPeers) == 0 {
		log.Println("❌ No OOB peers configured")
		return
	}
	peer := config.OOBPeers[rand.Intn(len(config.OOBPeers))]

	session, err := quic.DialAddr(ctx, peer, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic"},
	}, nil)
	if err != nil {
		log.Println("❌ ERROR: Failed to open OOB session:", err)
		return
	}
	defer session.CloseWithError(0, "Done")

	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		log.Println("❌ ERROR: Failed to open OOB stream:", err)
		return
	}
	defer stream.Close()

	// Send request as "reqID|realSNI"
	msg := fmt.Sprintf("%s|%s\n", reqID, realSNI)
	_, err = stream.Write([]byte(msg))
	if err != nil {
		log.Println("❌ ERROR: Writing to OOB stream failed:", err)
		return
	}
	fmt.Println("DEBUG: Sent real SNI via OOB to", peer, ":", msg)

	// **NEW: Wait for acknowledgment before closing**
	buf := make([]byte, 256)
	n, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		log.Println("❌ ERROR: Reading OOB response failed:", err)
		return
	}
	ack := string(buf[:n])
	fmt.Println("🔹 Received acknowledgment from OOB peer:", ack)
}

// generateRequestID creates a unique identifier for request mapping.
func generateRequestID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// generateTLSConfig creates a self-signed TLS config for QUIC.
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
