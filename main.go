package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ./bpf/tracer.c -- -I./bpf -D__TARGET_ARCH_x86

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

// Event types
const (
	EvtNFHook = 1
	EvtXmit   = 2
	EvtDrop   = 3
	EvtRoute  = 4
)

// Protocol mappings
var protocolMap = map[uint8]string{
	1:  "ICMP",
	6:  "TCP",
	17: "UDP",
}

// Protocol name to number mapping
var protocolNameMap = map[string]uint8{
	"icmp": 1,
	"tcp":  6,
	"udp":  17,
	"all":  0,
}

// Hook point mappings
var hookMap = map[uint32]string{
	0: "PREROUTING",
	1: "LOCAL_IN",
	2: "FORWARD",
	3: "LOCAL_OUT",
	4: "POSTROUTING",
}

// FilterConfig holds all the filter parameters
type FilterConfig struct {
	SrcIP      *net.IPNet
	DstIP      *net.IPNet
	SrcPorts   []uint16
	DstPorts   []uint16
	Protocols  []uint8
	Interfaces []string
}

// ParsePortRange parses port range string (e.g., "80" or "1000-2000")
func ParsePortRange(s string) ([]uint16, error) {
	if s == "" {
		return nil, nil
	}

	parts := strings.Split(s, "-")
	if len(parts) > 2 {
		return nil, fmt.Errorf("invalid port range format: %s", s)
	}

	start, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port number: %s", parts[0])
	}

	if len(parts) == 1 {
		return []uint16{uint16(start)}, nil
	}

	end, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port number: %s", parts[1])
	}

	if start > end {
		return nil, fmt.Errorf("invalid port range: %d > %d", start, end)
	}

	var ports []uint16
	for i := start; i <= end; i++ {
		ports = append(ports, uint16(i))
	}
	return ports, nil
}

// ParseProtocols parses protocol string (e.g., "tcp,udp" or "6,17")
func ParseProtocols(s string) ([]uint8, error) {
	if s == "" {
		return nil, nil
	}

	if strings.ToLower(s) == "all" {
		return []uint8{0}, nil
	}

	var protocols []uint8
	for _, p := range strings.Split(s, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if proto, ok := protocolNameMap[p]; ok {
			protocols = append(protocols, proto)
			continue
		}
		
		num, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid protocol: %s", p)
		}
		protocols = append(protocols, uint8(num))
	}
	return protocols, nil
}

// ParseInterfaces parses interface string (e.g., "eth0,eth1")
func ParseInterfaces(s string) []string {
	if s == "" {
		return nil
	}
	var ifaces []string
	for _, iface := range strings.Split(s, ",") {
		iface = strings.TrimSpace(iface)
		if iface != "" {
			ifaces = append(ifaces, iface)
		}
	}
	return ifaces
}

// PktInfo represents a network packet information
type PktInfo struct {
	EventType  uint32
	SrcIP      uint32
	DstIP      uint32
	SrcPort    uint16
	DstPort    uint16
	Protocol   uint8
	IFName     [16]byte
	Hook       uint32
	Verdict    uint32
	Mark       uint32
	Table      uint32
	Chain      uint32
	RuleID     uint32
	ICMPType   uint8
	ICMPCode   uint8
	Action     [32]byte
	Seq        uint32
	DropReason uint32
}

func setupLogging(logDir string) (*os.File, error) {
	// Create logs directory if it doesn't exist
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %v", err)
	}

	// Create log file with timestamp in name
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	logFile := filepath.Join(logDir, fmt.Sprintf("network-debug_%s.log", timestamp))

	// Open log file with append mode
	f, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %v", err)
	}

	// Set log output to file
	log.SetOutput(f)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Write initial log entry
	log.Printf("Starting network debug tool...")
	log.Printf("Log file: %s", logFile)

	return f, nil
}

func main() {
	// Parse command line arguments
	debug := flag.Bool("debug", false, "enable debug logging")
	logDir := flag.String("log-dir", "logs", "directory for log files")
	
	// Filter parameters
	srcIP := flag.String("src-ip", "", "source IP address or CIDR")
	dstIP := flag.String("dst-ip", "", "destination IP address or CIDR")
	srcPort := flag.String("src-port", "", "source port or port range (e.g., 80 or 1000-2000)")
	dstPort := flag.String("dst-port", "", "destination port or port range")
	protocol := flag.String("protocol", "", "protocol (name or number, comma-separated)")
	iface := flag.String("interface", "", "network interface name")

	flag.Parse()

	// Parse filter parameters
	filter := &FilterConfig{}
	var err error

	// Parse IP filters
	if *srcIP != "" {
		_, filter.SrcIP, err = net.ParseCIDR(*srcIP)
		if err != nil {
			ip := net.ParseIP(*srcIP)
			if ip == nil {
				fmt.Printf("Invalid source IP or CIDR: %s\n", *srcIP)
				os.Exit(1)
			}
			filter.SrcIP = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		}
	}

	if *dstIP != "" {
		_, filter.DstIP, err = net.ParseCIDR(*dstIP)
		if err != nil {
			ip := net.ParseIP(*dstIP)
			if ip == nil {
				fmt.Printf("Invalid destination IP or CIDR: %s\n", *dstIP)
				os.Exit(1)
			}
			filter.DstIP = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		}
	}

	// Parse port filters
	filter.SrcPorts, err = ParsePortRange(*srcPort)
	if err != nil {
		fmt.Printf("Invalid source port range: %v\n", err)
		os.Exit(1)
	}

	filter.DstPorts, err = ParsePortRange(*dstPort)
	if err != nil {
		fmt.Printf("Invalid destination port range: %v\n", err)
		os.Exit(1)
	}

	// Parse protocol filter
	filter.Protocols, err = ParseProtocols(*protocol)
	if err != nil {
		fmt.Printf("Invalid protocol: %v\n", err)
		os.Exit(1)
	}

	// Parse interface filter
	filter.Interfaces = ParseInterfaces(*iface)

	// Set up logging to file
	logFile, err := setupLogging(*logDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up logging: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()

	// Set up logging
	if *debug {
		log.Printf("Debug logging enabled")
	}

	// Print startup message and filter configuration
	log.Println("Network Debug Tool")
	log.Println("Press Ctrl+C to exit")

	if filter.SrcIP != nil {
		log.Printf("Source IP filter: %s", filter.SrcIP)
	}
	if filter.DstIP != nil {
		log.Printf("Destination IP filter: %s", filter.DstIP)
	}
	if len(filter.SrcPorts) > 0 {
		log.Printf("Source port filter: %v", filter.SrcPorts)
	}
	if len(filter.DstPorts) > 0 {
		log.Printf("Destination port filter: %v", filter.DstPorts)
	}
	if len(filter.Protocols) > 0 {
		var protoNames []string
		for _, p := range filter.Protocols {
			protoNames = append(protoNames, parseProtocol(p))
		}
		log.Printf("Protocol filter: %v", protoNames)
	}
	if len(filter.Interfaces) > 0 {
		log.Printf("Interface filter: %v", filter.Interfaces)
	}

	// Check if we're running on Linux
	if runtime.GOOS != "linux" {
		log.Printf("Warning: eBPF programs can only be loaded on Linux. Current OS: %s", runtime.GOOS)
		log.Printf("The program will compile but not load the eBPF program.")
		return
	}

	// Allow the current process to lock memory for eBPF resources
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Printf("Warning: Failed to adjust RLIMIT_MEMLOCK: %v", err)
	}

	// Set up signal handling for graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Load pre-compiled BPF program
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Printf("Error loading BPF objects: %v", err)
		return
	}
	defer objs.Close()

	// Set up perf buffer reader
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Printf("Error creating perf event reader: %v", err)
		return
	}
	defer rd.Close()

	// Process events
	go func() {
		var event PktInfo
		for {
			record, err := rd.Read()
			if err != nil {
				if err == perf.ErrClosed {
					return
				}
				log.Printf("Error reading perf event: %v", err)
				continue
			}

			// Parse event data
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Error parsing event data: %v", err)
				continue
			}

			// Convert IPs and ports for logging
			srcIP := net.IPv4(byte(event.SrcIP), byte(event.SrcIP>>8), byte(event.SrcIP>>16), byte(event.SrcIP>>24))
			dstIP := net.IPv4(byte(event.DstIP), byte(event.DstIP>>8), byte(event.DstIP>>16), byte(event.DstIP>>24))
			
			log.Printf("Received packet: src=%s:%d dst=%s:%d proto=%s", 
				srcIP.String(), event.SrcPort,
				dstIP.String(), event.DstPort,
				parseProtocol(event.Protocol))

			// Apply filters
			if filter.SrcIP != nil {
				if !filter.SrcIP.Contains(srcIP) {
					log.Printf("Source IP %s does not match filter %s", srcIP.String(), filter.SrcIP.String())
					continue
				}
				log.Printf("Source IP %s matches filter %s", srcIP.String(), filter.SrcIP.String())
			}

			if filter.DstIP != nil {
				if !filter.DstIP.Contains(dstIP) {
					log.Printf("Destination IP %s does not match filter %s", dstIP.String(), filter.DstIP.String())
					continue
				}
				log.Printf("Destination IP %s matches filter %s", dstIP.String(), filter.DstIP.String())
			}

			if len(filter.SrcPorts) > 0 {
				match := false
				for _, port := range filter.SrcPorts {
					if event.SrcPort == port {
						match = true
						log.Printf("Source port %d matches filter", event.SrcPort)
						break
					}
				}
				if !match {
					log.Printf("Source port %d does not match any filter ports %v", event.SrcPort, filter.SrcPorts)
					continue
				}
			}

			if len(filter.DstPorts) > 0 {
				match := false
				for _, port := range filter.DstPorts {
					if event.DstPort == port {
						match = true
						log.Printf("Destination port %d matches filter", event.DstPort)
						break
					}
				}
				if !match {
					log.Printf("Destination port %d does not match any filter ports %v", event.DstPort, filter.DstPorts)
					continue
				}
			}

			if len(filter.Protocols) > 0 && filter.Protocols[0] != 0 {
				match := false
				for _, proto := range filter.Protocols {
					if event.Protocol == proto {
						match = true
						log.Printf("Protocol %s matches filter", parseProtocol(event.Protocol))
						break
					}
				}
				if !match {
					log.Printf("Protocol %s does not match any filter protocols %v", 
						parseProtocol(event.Protocol), 
						filter.Protocols)
					continue
				}
			}

			// If all filters passed, print the full event details
			log.Printf("MATCH - Packet details: src=%s:%d dst=%s:%d proto=%s hook=%s verdict=%d mark=%d table=%d chain=%d rule=%d", 
				srcIP.String(), event.SrcPort,
				dstIP.String(), event.DstPort,
				parseProtocol(event.Protocol),
				parseHook(event.Hook),
				event.Verdict,
				event.Mark,
				event.Table,
				event.Chain,
				event.RuleID)

			// Format and log the event
			switch event.EventType {
			case EvtNFHook:
				log.Printf("[NFHook] %s:%d -> %s:%d Proto=%s Hook=%s Verdict=%d",
					srcIP, event.SrcPort, dstIP, event.DstPort,
					parseProtocol(event.Protocol), parseHook(event.Hook), event.Verdict)
			case EvtXmit:
				log.Printf("[Xmit] %s:%d -> %s:%d Proto=%s IFace=%s",
					srcIP, event.SrcPort, dstIP, event.DstPort,
					parseProtocol(event.Protocol), string(event.IFName[:bytes.IndexByte(event.IFName[:], 0)]))
			case EvtDrop:
				log.Printf("[Drop] %s:%d -> %s:%d Proto=%s Reason=%d",
					srcIP, event.SrcPort, dstIP, event.DstPort,
					parseProtocol(event.Protocol), event.DropReason)
			case EvtRoute:
				log.Printf("[Route] %s:%d -> %s:%d Proto=%s IFace=%s",
					srcIP, event.SrcPort, dstIP, event.DstPort,
					parseProtocol(event.Protocol), string(event.IFName[:bytes.IndexByte(event.IFName[:], 0)]))
			}
		}
	}()

	// Write PID file
	pidFile := filepath.Join(*logDir, "network-debug.pid")
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644); err != nil {
		log.Printf("Warning: Failed to write PID file: %v", err)
	} else {
		log.Printf("PID file written to: %s", pidFile)
	}

	// Wait for signal
	receivedSig := <-sig
	log.Printf("Received signal %v, exiting...", receivedSig)

	// Clean up PID file
	if err := os.Remove(pidFile); err != nil {
		log.Printf("Warning: Failed to remove PID file: %v", err)
	}
}

// parseProtocol converts protocol number to string
func parseProtocol(proto uint8) string {
	if name, ok := protocolMap[proto]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", proto)
}

// parseHook converts netfilter hook point to string
func parseHook(hook uint32) string {
	if name, ok := hookMap[hook]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", hook)
}
