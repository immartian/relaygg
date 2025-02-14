package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggquic"
)

type Config struct {
	LocalProxyAddr string   `json:"local_proxy_addr"`
	OOBPeers       []string `json:"oob_peers"`
	FakeSNI        string   `json:"fake_sni"`
}

var config Config
var yggNode *core.Core
var quicTransport *yggquic.YggdrasilTransport

func main() {
	configPath := flag.String("config", "config.json", "Path to configuration file")
	flag.Parse()
	if err := loadConfig(*configPath); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	initYggdrasil()
	go startTLSProxy()
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

func initYggdrasil() {
	var err error
	cert := generateSelfSignedCert()
	yggNode, err = core.New(&cert, nil)
	if err != nil {
		log.Fatalf("❌ ERROR: Failed to initialize Yggdrasil core: %v", err)
	}
	fmt.Println("✅ Yggdrasil Core Initialized")
}

func startTLSProxy() {
	listener, err := tls.Listen("tcp", config.LocalProxyAddr, &tls.Config{
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			fmt.Println("DEBUG: Client requested SNI:", chi.ServerName)
			return &tls.Config{
				ServerName:         config.FakeSNI,
				InsecureSkipVerify: true,
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

func handleTLSConnection(clientConn net.Conn) {
	defer clientConn.Close()
	fmt.Println("DEBUG: Handling TLS connection from client")
	// Capture and relay the real SNI
	buf := make([]byte, 256)
	n, err := clientConn.Read(buf)
	if err != nil {
		log.Println("❌ ERROR: Reading SNI from client failed:", err)
		return
	}
	realSNI := string(buf[:n])
	go sendOOBMessage(realSNI)
}

func startOOBListener() {
	var err error
	tlsCert := generateSelfSignedCert()
	quicTransport, err = yggquic.New(yggNode, tlsCert, nil)
	if err != nil {
		log.Fatalf("❌ ERROR: Failed to start Yggdrasil QUIC transport: %v", err)
	}
	fmt.Println("🔹 OOB QUIC Listener started over Yggdrasil")

	for {
		conn, err := quicTransport.Accept()
		if err != nil {
			log.Println("❌ ERROR: Failed to accept OOB connection:", err)
			continue
		}
		fmt.Println("🔹 OOB session established with", conn.RemoteAddr())
		go handleOOBSession(conn)
	}
}

func handleOOBSession(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		log.Println("❌ ERROR: Reading OOB message failed:", err)
		return
	}
	fmt.Println("🔹 Received real SNI via OOB:", string(buf[:n]))
}

func sendOOBMessage(realSNI string) {
	if len(config.OOBPeers) == 0 {
		log.Println("❌ No OOB peers configured")
		return
	}

	peerIP := config.OOBPeers[0]
	fmt.Println("DEBUG: Sending real SNI via OOB to peer IP:", peerIP)

	conn, err := quicTransport.Dial("yggdrasil", peerIP)
	if err != nil {
		log.Println("❌ ERROR: Failed to connect to Yggdrasil peer", peerIP, "via QUIC:", err)
		return
	}
	defer conn.Close()

	_, err = conn.Write([]byte(realSNI + "\n"))
	if err != nil {
		log.Println("❌ ERROR: Writing to OOB stream to", peerIP, "failed:", err)
		return
	}

	fmt.Println("✅ Successfully sent real SNI via OOB to", peerIP, ":", realSNI)
}

func generateSelfSignedCert() tls.Certificate {
	cert, err := tls.LoadX509KeyPair("cert.pem", "cert.key")
	if err != nil {
		log.Fatal(err)
	}
	return cert
}
