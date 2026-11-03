/*
 * File: 04_honeypot_orchestrator.go
 * Topic: Defensive Security Monitoring - Telemetry Log Collector
 * Language: Go (1.20+)
 * Description: Multi-threaded server designed to log connection telemetry,
 *              inspect structural anomalies, and rate-limit client interactions safely.
 */

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type ConnectionMetaData struct {
	SessionID   string    `json:"session_id"`
	RemoteAddr  string    `json:"remote_addr"`
	ConnectTime time.Time `json:"connect_time"`
	BytesRead   int64     `json:"bytes_read"`
	Status      string    `json:"status"`
}

type SecurityEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	EventType   string    `json:"event_type"`
	Severity    string    `json:"severity"`
	Source      string    `json:"source"`
	Details     string    `json:"details"`
}

type TelemetryCollector struct {
	mu             sync.Mutex
	activeSessions map[string]*ConnectionMetaData
	events         []SecurityEvent
	totalConns     uint64
	bytesProcessed uint64
}

func NewTelemetryCollector() *TelemetryCollector {
	return &TelemetryCollector{
		activeSessions: make(map[string]*ConnectionMetaData),
		events:         make([]SecurityEvent, 0),
	}
}

func (tc *TelemetryCollector) LogEvent(eventType, severity, source, details string) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	evt := SecurityEvent{
		Timestamp: time.Now().UTC(),
		EventType: eventType,
		Severity:  severity,
		Source:    source,
		Details:   details,
	}

	tc.events = append(tc.events, evt)
	log.Printf("[%s] [%s] Source: %s - %s", severity, eventType, source, details)
}

func (tc *TelemetryCollector) RegisterSession(id, addr string) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	atomic.AddUint64(&tc.totalConns, 1)
	tc.activeSessions[id] = &ConnectionMetaData{
		SessionID:   id,
		RemoteAddr:  addr,
		ConnectTime: time.Now().UTC(),
		BytesRead:   0,
		Status:      "CONNECTED",
	}
}

func (tc *TelemetryCollector) UnregisterSession(id string, totalBytes int64) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if session, exists := tc.activeSessions[id]; exists {
		session.BytesRead = totalBytes
		session.Status = "CLOSED"
		atomic.AddUint64(&tc.bytesProcessed, uint64(totalBytes))
		delete(tc.activeSessions, id)
	}
}

type ServerEngine struct {
	listenAddr string
	collector  *TelemetryCollector
	listener   net.Listener
	shutdownCh chan struct{}
	wg         sync.WaitGroup
}

func NewServerEngine(addr string) *ServerEngine {
	return &ServerEngine{
		listenAddr: addr,
		collector:  NewTelemetryCollector(),
		shutdownCh: make(chan struct{}),
	}
}

func (se *ServerEngine) Start(ctx context.Context) error {
	var err error
	se.listener, err = net.Listen("tcp", se.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to bind address %s: %w", se.listenAddr, err)
	}
	defer se.listener.Close()

	se.collector.LogEvent("SERVER_START", "INFO", se.listenAddr, "Security logging service operational")

	go func() {
		<-ctx.Done()
		se.collector.LogEvent("SERVER_SHUTDOWN", "WARN", se.listenAddr, "Shutdown signal received")
		close(se.shutdownCh)
		se.listener.Close()
	}()

	for {
		conn, err := se.listener.Accept()
		if err != nil {
			select {
			case <-se.shutdownCh:
				return nil
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}

		se.wg.Add(1)
		go se.handleConnection(conn)
	}
}

func (se *ServerEngine) handleConnection(conn net.Conn) {
	defer se.wg.Done()
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	sessionID := fmt.Sprintf("sess-%d", time.Now().UnixNano())

	se.collector.RegisterSession(sessionID, remoteAddr)
	se.collector.LogEvent("CONN_OPEN", "INFO", remoteAddr, fmt.Sprintf("Session %s initialized", sessionID))

	// Set connection deadline for resource control
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	buffer := make([]byte, 1024)
	var totalBytes int64

	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				se.collector.LogEvent("CONN_READ_ERR", "DEBUG", remoteAddr, err.Error())
			}
			break
		}

		totalBytes += int64(n)

		// Basic anomaly inspection: check for disproportionately large inputs
		if totalBytes > 4096 {
			se.collector.LogEvent("ANOMALY_PAYLOAD_SIZE", "WARN", remoteAddr, "Read threshold exceeded; throttling")
			break
		}

		// Acknowledge payload safely
		response := fmt.Sprintf("ACK: %d bytes received\n", n)
		conn.Write([]byte(response))
	}

	se.collector.UnregisterSession(sessionID, totalBytes)
	se.collector.LogEvent("CONN_CLOSE", "INFO", remoteAddr, fmt.Sprintf("Session closed. Total bytes: %d", totalBytes))
}

func (se *ServerEngine) PrintSummary() {
	se.collector.mu.Lock()
	defer se.collector.mu.Unlock()

	fmt.Println("\n=======================================================")
	fmt.Println("         TELEMETRY LOGGING SERVICE SUMMARY             ")
	fmt.Println("=======================================================")
	fmt.Printf("Total Connections Handled : %d\n", atomic.LoadUint64(&se.collector.totalConns))
	fmt.Printf("Total Bytes Processed     : %d\n", atomic.LoadUint64(&se.collector.bytesProcessed))
	fmt.Printf("Total Events Logged       : %d\n", len(se.collector.events))
	fmt.println("=======================================================")
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	server := NewServerEngine("127.0.0.1:8888")

	go func() {
		<-sigChan
		fmt.Println("\n[!] Interrupt received. Initiating shutdown...")
		cancel()
	}()

	fmt.Println("Starting Telemetry Collector on 127.0.0.1:8888 (Press Ctrl+C to stop)...")
	if err := server.Start(ctx); err != nil {
		log.Fatalf("Server exit error: %v", err)
	}

	server.wg.Wait()
	server.PrintSummary()
}