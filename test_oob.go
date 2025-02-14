package main

import (
	"fmt"
	"log"
	"oob"
	"time"
)

func main() {
	// Load OOB module
	oobModule, err := oob.NewOOBModule("config.json")
	if err != nil {
		log.Fatalf("❌ Failed to initialize OOB module: %v", err)
	}
	fmt.Println("✅ OOB Module initialized successfully")

	// Step 1: Validate peer configuration
	if len(oobModule.Peers) == 0 {
		log.Fatalf("❌ No OOB peers found in config.json")
	}
	fmt.Println("✅ Loaded OOB peers:", oobModule.Peers)

	// Step 2: Test connectivity with peers
	var workingPeer string
	for _, peer := range oobModule.Peers {
		fmt.Printf("🔹 Testing connection to peer: %s...\n", peer)
		if oobModule.CanConnect(peer) {
			workingPeer = peer
			fmt.Printf("✅ Peer %s is reachable\n", peer)
			break
		} else {
			fmt.Printf("❌ Peer %s is unreachable, trying next...\n", peer)
		}
	}

	if workingPeer == "" {
		log.Fatalf("❌ No OOB peers are reachable!")
	}

	// Step 3: Validate the SNI relay protocol support
	reqID := fmt.Sprintf("%d", time.Now().UnixNano())
	testSNI := "test.example.com"
	fmt.Printf("🔹 Testing if peer %s supports SNI relay for %s...\n", workingPeer, testSNI)

	response, err := oobModule.SendOOBRequest(workingPeer, reqID, testSNI)
	if err != nil {
		log.Fatalf("❌ ERROR: Peer %s does not support SNI relay: %v", workingPeer, err)
	}
	fmt.Printf("✅ Peer %s successfully processed SNI relay!\nReceived ServerHello: %x\n", workingPeer, response)
}
