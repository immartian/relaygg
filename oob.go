package main

import (
	"crypto/tls"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggquic"
)

// OOBMessage represents a basic OOB request.
type OOBMessage struct {
	RequestID string `json:"request_id"`
	Data      string `json:"data"`
}

// OOBModule handles OOB communication via QUIC.
type OOBModule struct {
	Node       *core.Core
	Transport  *yggquic.YggdrasilTransport
	Peers      []string
	mu         sync.Mutex
	requestMap sync.Map // Maps request IDs to response channels
}

// isValidYggdrasilAddress validates if a given peer address is a valid Yggdrasil address.
func isValidYggdrasilAddress(address string) bool {
	yggPattern := `^[a-fA-F0-9:]+$` // Simplified regex for Yggdrasil addresses
	matched, _ := regexp.MatchString(yggPattern, address)
	return matched
}

// generateSelfSignedCert generates a self-signed TLS certificate.
func generateSelfSignedCert() tls.Certificate {
	priv, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{}, &x509.Certificate{}, &priv.PublicKey, priv)
	if err != nil {
		log.Fatal(err)
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv.Seed()})
	cert, err := tls.X509KeyPair(pemCert, pemKey); if err != nil { log.Fatal(err) }
	return cert
}

// NewOOBModule initializes the QUIC transport over Yggdrasil.
func NewOOBModule(peers []string) (*OOBModule, error) {
	cert := generateSelfSignedCert()
	logger := log.New(os.Stdout, "core: ", log.LstdFlags)
	yggNode, err := core.New(&cert, logger, core.WithPrivateKey(priv))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Yggdrasil core: %v", err)
	}

	quicTransport, err := yggquic.New(yggNode, cert, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to start QUIC transport: %v", err)
	}

	return &OOBModule{
		Node:      yggNode,
		Transport: quicTransport,
		Peers:     peers,
	}, nil
}

// SendOOBRequest sends a request to an OOB peer and waits for a response.
func (o *OOBModule) SendOOBRequest(peer, data string) (string, error) {
	if !isValidYggdrasilAddress(peer) {
		return "", fmt.Errorf("invalid Yggdrasil address: %s", peer)
	}

	requestID := fmt.Sprintf("%d", time.Now().UnixNano())
	message := OOBMessage{RequestID: requestID, Data: data}
	encoded, _ := json.Marshal(message)

	conn, err := o.Transport.Dial("yggdrasil", peer)
	if err != nil {
		return "", fmt.Errorf("failed to connect to peer %s: %v", peer, err)
	}
	if conn != nil {
		defer conn.Close()
	}

	_, err = conn.Write(encoded)
	if err != nil {
		return "", fmt.Errorf("failed to send data: %v", err)
	}

	// Wait for response
	respChan := make(chan string, 1) // Buffered to avoid blocking if no response is sent
	o.requestMap.Store(requestID, respChan)
	defer o.requestMap.Delete(requestID)

	select {
	case response := <-respChan:
		return response, nil
	case <-time.After(5 * time.Second):
		return "", fmt.Errorf("timeout waiting for response")
	}
}

// HandleOOBSession handles incoming OOB requests.
func (o *OOBModule) HandleOOBSession(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		log.Println("❌ Failed to read from connection:", err)
		return
	}

	var message OOBMessage
	if err := json.Unmarshal(buf[:n], &message); err != nil {
		log.Println("❌ Failed to parse JSON:", err)
		return
	}

	log.Printf("{"event": "oob_request_received", "request_id": "%s", "data": "%s"}"
		, message.RequestID, message.Data)
	response := fmt.Sprintf("ACK: %s", message.Data)
	conn.Write([]byte(response))

	// Store response for requestor if it's an awaited request
	if ch, ok := o.requestMap.Load(message.RequestID); ok {
		select {
		case ch.(chan string) <- response:
		default:
			log.Println("⚠️ Response channel was not ready, avoiding deadlock")
		}
	}
}

func main() {
	peers := []string{"ygg_peer1", "ygg_peer2"}
	oobModule, err := NewOOBModule(peers)
	if err != nil {
		log.Fatalf("Failed to initialize OOB module: %v", err)
	}

	log.Println("✅ OOB Module initialized")

	// Simulate sending a request
	response, err := oobModule.SendOOBRequest("ygg_peer1", "test_data")
	if err != nil {
		log.Println("❌ OOB request failed:", err)
	} else {
		log.Println("✅ OOB response received:", response)
	}
}
