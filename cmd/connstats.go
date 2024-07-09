package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/gabspt/ConnectionStats/internal/probe"
	"github.com/vishvananda/netlink"
)

var (
	ifaceFlag         = flag.String("i", "enp0s8", "interface to attach the probe to") //enp0s8
	pktAgrupationFlag = flag.Int("p", 100, "Number of packets to be aggregated before sending the stats")
	//ft                = probe.NewFlowTable()
)

// signalHandler catches SIGINT and SIGTERM then exits the program
func signalHandler(cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("\nCaught SIGINT... Exiting")
		cancel()
	}()
}

// displayInterfaces displays all available network interfaces
func displayInterfaces() {
	interfaces, err := net.Interfaces()

	if err != nil {
		log.Fatal("Failed fetching network interfaces")
		return
	}

	for i, iface := range interfaces {
		fmt.Printf("%d %s\n", i, iface.Name)
	}
	os.Exit(1)
}

func main() {
	flag.Parse()

	//Configure probe's network interface
	iface, errint := netlink.LinkByName(*ifaceFlag)
	if errint != nil {
		log.Printf("Could not find interface %v: %v", *ifaceFlag, errint)
		displayInterfaces()
	}

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	signalHandler(cancel)

	//Run the probe. Pass the context and the network interface and the packet agrupation flag
	if err := probe.Run(ctx, iface, *pktAgrupationFlag); err != nil {
		log.Fatalf("Failed running the probe: %v", err)
	}

}
