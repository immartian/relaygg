package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"oob"
	"time"
)

// TLSProxy handles the actual proxy functionality.
type TLSProxy struct {
	OOB *oob.OOBModule
}

// Start runs the TLS proxy.
func (p *TLSProxy) Start(localAddr string) {
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Fatalf("❌ Failed to start TLS Proxy: %v", err)
	}
	defer listener.Close()
	fmt.Println("🔹 TLS Proxy listening on", localAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("❌ Connection error:", err)
			continue
		}
		go p.handleTLSConnection(conn)
	}
}

// handleTLSConnection manages TLS handshakes and data relay.
func (p *TLSProxy) handleTLSConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Read initial TLS handshake (ClientHello)
	clientHello := make([]byte, 4096)
	n, err := clientConn.Read(clientHello)
	if err != nil {
		log.Println("❌ ERROR: Failed to read ClientHello:", err)
		return
	}

	// Extract SNI from ClientHello
	realSNI, err := extractSNI(clientHello[:n])
	if err != nil {
		log.Println("❌ ERROR: Failed to extract SNI:", err)
		return
	}

	fmt.Println("🔹 Client requested SNI:", realSNI)

	// Send real SNI over OOB and wait for real ServerHello
	reqID := fmt.Sprintf("%d", time.Now().UnixNano())
	realServerHello, err := p.OOB.SendOOBRequest(p.OOB.Peers[0], reqID, realSNI)
	if err != nil {
		log.Println("❌ OOB request failed:", err)
		return
	}

	// Inject the real ServerHello response back to the client
	_, err = clientConn.Write(realServerHello)
	if err != nil {
		log.Println("❌ ERROR: Failed to send real ServerHello to client:", err)
		return
	}

	// After handshake, establish a real TLS tunnel
	targetConn, err := tls.Dial("tcp", realSNI+":443", &tls.Config{
		ServerName:         realSNI,
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Println("❌ ERROR: Failed to connect to real server:", err)
		return
	}
	defer targetConn.Close()

	// Start bidirectional data relay
	go io.Copy(targetConn, clientConn)
	io.Copy(clientConn, targetConn)
}

// extractSNI parses ClientHello to extract the SNI field.
func extractSNI(clientHello []byte) (string, error) {
	// TODO: Implement a proper ClientHello parser to extract SNI
	return "example.com", nil
}

func main() {
	oobModule, _ := oob.NewOOBModule("config.json")
	proxy := TLSProxy{OOB: oobModule}
	proxy.Start("127.0.0.1:8443")
}
