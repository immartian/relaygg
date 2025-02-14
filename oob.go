package oob

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"sync"

	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggquic"
)

type Config struct {
	OOBPeers []string `json:"oob_peers"`
}

var config Config

// OOBModule handles QUIC-based out-of-band communication over Yggdrasil.
type OOBModule struct {
	Node       *core.Core
	Transport  *yggquic.YggdrasilTransport
	Peers      []string
	mu         sync.Mutex
	requestMap sync.Map // Stores request ID to response channel
}

// NewOOBModule initializes the QUIC transport over Yggdrasil.
func NewOOBModule(configPath string) (*OOBModule, error) {
	if err := loadConfig(configPath); err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	privateKey := ed25519.NewKeyFromSeed(make([]byte, 32))
	yggNode, err := core.New(nil, core.WithPrivateKey(privateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Yggdrasil core: %v", err)
	}

	tlsCert := generateSelfSignedCert()
	quicTransport, err := yggquic.New(yggNode, tlsCert, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to start Yggdrasil QUIC transport: %v", err)
	}

	return &OOBModule{
		Node:      yggNode,
		Transport: quicTransport,
		Peers:     config.OOBPeers,
	}, nil
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

// PerformTLSHandshake connects to the actual destination and extracts the ServerHello.
func (o *OOBModule) PerformTLSHandshake(realSNI string) ([]byte, error) {
	conn, err := tls.Dial("tcp", realSNI+":443", &tls.Config{
		ServerName: realSNI,
	})
	if err != nil {
		return nil, fmt.Errorf("TLS handshake failed for %s: %v", realSNI, err)
	}
	defer conn.Close()

	// Extract ServerHello raw bytes (this may require low-level access)
	serverHello := conn.ConnectionState().PeerCertificates[0].Raw
	return serverHello, nil
}

// HandleOOBSession processes incoming QUIC requests and performs a TLS handshake.
func (o *OOBModule) HandleOOBSession(conn net.Conn) {
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		log.Println("❌ ERROR: Failed to read OOB message:", err)
		return
	}
	message := string(buf[:n])

	var reqID, realSNI string
	fmt.Sscanf(message, "%s|%s", &reqID, &realSNI)
	fmt.Printf("🔹 OOB received request: %s -> %s\n", reqID, realSNI)

	// Perform real TLS handshake with destination
	serverHello, err := o.PerformTLSHandshake(realSNI)
	if err != nil {
		log.Println("❌ ERROR: Failed to complete TLS handshake:", err)
		return
	}

	// Send ServerHello response back via OOB
	conn.Write(serverHello)
}

// generateSelfSignedCert generates a self-signed TLS certificate.
func generateSelfSignedCert() tls.Certificate {
	priv, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv.Seed()})
	if pemKey == nil {
		log.Fatal("Failed to encode private key")
	}
	cert, err := tls.X509KeyPair(pemKey, pemKey)
	if err != nil {
		log.Fatal(err)
	}
	return cert
}
