package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

const (
	bpfProgFile = "drop_packets.o"
	defaultPort = 4040
)

func main() {
	// Load BPF program
	spec, err := ebpf.LoadCollectionSpec(bpfProgFile)
	if err != nil {
		log.Fatalf("Failed to load BPF program: %v", err)
	}

	// Retrieve the network interface
	iface := "eth0" // Default interface
	if len(os.Args) > 1 {
		iface = os.Args[1]
	}
	linkHandle, err := netlink.NewHandle(syscall.NETLINK_ROUTE)
	if err != nil {
		log.Fatalf("Failed to create netlink handle: %v", err)
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v", iface, err)
	}

	// Attach XDP program to the interface
	xdpLink, err := link.Handle.AttachXDP(link.LinkHandleAttachXDPOptions{
		Program:   spec.Programs["drop_tcp_packets"],
		Mode:      ebpf.LinkModeXDP,
		Interface: link.Attrs().Index,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer xdpLink.Close()

	// Create BPF map
	portMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  2,
		MaxEntries: 1,
	})
	if err != nil {
		log.Fatalf("Failed to create BPF map: %v", err)
	}
	defer portMap.Close()

	// Update the port map
	port := defaultPort // Default port
	if len(os.Args) > 2 {
		fmt.Sscanf(os.Args[2], "%d", &port)
	}
	key := uint32(0)
	value := uint16(port)
	if err := portMap.Update(&key, &value, ebpf.UpdateAny); err != nil {
		log.Fatalf("Failed to update BPF map: %v", err)
	}

	log.Printf("Dropping TCP packets on port %d", port)

	// Listen for termination signals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("Shutting down...")
}
