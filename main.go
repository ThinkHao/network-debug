package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ./bpf/tracer.c -- -I./bpf -D__TARGET_ARCH_x86

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

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

// Hook point mappings
var hookMap = map[uint32]string{
	0: "PREROUTING",
	1: "LOCAL_IN",
	2: "FORWARD",
	3: "LOCAL_OUT",
	4: "POSTROUTING",
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
	// Parse command line flags
	debug := flag.Bool("debug", false, "enable debug logging")
	logDir := flag.String("log-dir", "logs", "directory for log files")
	flag.Parse()

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

	// Print startup message
	log.Println("Network Debug Tool")
	log.Println("Press Ctrl+C to exit")

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
