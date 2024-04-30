package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"

	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

// LoggerAdapter adapts *log.Logger to core.Logger interface
type LoggerAdapter struct {
	*log.Logger
}

// Implement additional methods required by core.Logger
func (la *LoggerAdapter) Debugf(format string, v ...interface{}) {
	la.Printf("DEBUG: "+format, v...)
}

func (la *LoggerAdapter) Debugln(v ...interface{}) {
	la.Println(append([]interface{}{"DEBUG:"}, v...)...)
}

func (la *LoggerAdapter) Infof(format string, v ...interface{}) {
	la.Printf("INFO: "+format, v...)
}

func (la *LoggerAdapter) Infoln(v ...interface{}) {
	la.Println(append([]interface{}{"INFO:"}, v...)...)
}

func (la *LoggerAdapter) Warnf(format string, v ...interface{}) {
	la.Printf("WARN: "+format, v...)
}

func (la *LoggerAdapter) Warnln(v ...interface{}) {
	la.Println(append([]interface{}{"WARN:"}, v...)...)
}

func (la *LoggerAdapter) Errorf(format string, v ...interface{}) {
	la.Printf("ERROR: "+format, v...)
}

func (la *LoggerAdapter) Errorln(v ...interface{}) {
	la.Println(append([]interface{}{"ERROR:"}, v...)...)
}

func (la *LoggerAdapter) Traceln(v ...interface{}) {
	la.Println(append([]interface{}{"TRACE:"}, v...)...)
}

func main() {
	// Generate a new configuration
	cfg := config.GenerateConfig()

	// Use the generated certificate from the configuration
	cert := cfg.Certificate

	// Create a new Yggdrasil node with the adapted logger
	node, err := core.New(cert, &LoggerAdapter{log.Default()})
	u, _ := url.Parse("tls://192.9.143.104:443")
	node.AddPeer(u, "")

	if err != nil {
		log.Fatalf("Failed to create Yggdrasil node: %v", err)
	}

	defer node.Stop()

	// Get the IPv6 address from Yggdrasil
	ipv6Address := node.Address().String()

	// Create a new TUN interface
	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = "tun1" // You may want the OS to pick a name automatically
	iface, err := water.New(config)
	if err != nil {
		log.Fatalf("Unable to create TUN device: %v", err)
	}
	defer iface.Close()

	log.Printf("Interface %s created\n", iface.Name())

	// Find the network interface represented by the TUN device
	link, err := netlink.LinkByName(iface.Name())
	if err != nil {
		log.Fatalf("Failed to find interface '%s': %v", iface.Name(), err)
	}

	// Set the interface up
	if err := netlink.LinkSetUp(link); err != nil {
		log.Fatalf("Failed to set interface %s up: %v", iface.Name(), err)
	}

	// Assign IPv6 address to the interface
	addr, err := netlink.ParseAddr(ipv6Address + "/7") // Ensure correct prefix length
	if err != nil {
		log.Fatalf("Invalid IPv6 address: %v", err)
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		log.Fatalf("Failed to add IPv6 address to interface %s: %v", iface.Name(), err)
	}

	// Your main application logic here, for example starting a web server
	log.Println("Yggdrasil node is running with IP:", ipv6Address)

	// Set up HTTP server
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Example response using the node's address, assuming a method to fetch it
		fmt.Fprintf(w, "Hello from Yggdrasil: %s", node.Address())
	})

	// Start the HTTP server on localhost:8383
	fmt.Println("Server starting on http://localhost:8383/")
	if err := http.ListenAndServe(":8383", nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
