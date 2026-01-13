package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

// Request/Response structures
type DelayRequest struct {
	Link    string                 `json:"link"`
	Node    map[string]interface{} `json:"node"`    // Direct node config
	Chain   []map[string]interface{} `json:"chain"` // Chain of nodes for proxy chain testing
	URL     string                 `json:"url"`
	Timeout int                    `json:"timeout"` // milliseconds
}

type DelayResponse struct {
	Success bool   `json:"success"`
	Latency int    `json:"latency"` // milliseconds, -1 if failed
	Error   string `json:"error,omitempty"`
}

type IPRequest struct {
	Link    string                 `json:"link"`
	Node    map[string]interface{} `json:"node"`
	Chain   []map[string]interface{} `json:"chain"` // Chain of nodes
	Timeout int                    `json:"timeout"`
}

type IPResponse struct {
	Success bool   `json:"success"`
	IP      string `json:"ip,omitempty"`
	Error   string `json:"error,omitempty"`
}

type SpeedRequest struct {
	Link               string                 `json:"link"`
	Node               map[string]interface{} `json:"node"`
	Chain              []map[string]interface{} `json:"chain"` // Chain of nodes
	URL                string                 `json:"url"`
	Timeout            int                    `json:"timeout"`            // seconds
	Mode               string                 `json:"mode"`               // "average" or "peak", default "average"
	PeakSampleInterval int                    `json:"peakSampleInterval"` // milliseconds, 50-200, default 100
}

type SpeedResponse struct {
	Success   bool    `json:"success"`
	Speed     float64 `json:"speed"`     // MB/s
	PeakSpeed float64 `json:"peakSpeed"` // MB/s, only in peak mode
	Latency   int     `json:"latency"`   // milliseconds
	Bytes     int64   `json:"bytes"`     // bytes downloaded
	Error     string  `json:"error,omitempty"`
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9876"
	}

	http.HandleFunc("/api/delay", handleDelay)
	http.HandleFunc("/api/ip", handleIP)
	http.HandleFunc("/api/speed", handleSpeed)
	http.HandleFunc("/health", handleHealth)

	log.Printf("Speedtest service starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func handleDelay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req DelayRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, DelayResponse{Success: false, Latency: -1, Error: "Invalid request"})
		return
	}

	if req.Link == "" && req.Node == nil && len(req.Chain) == 0 {
		sendJSON(w, DelayResponse{Success: false, Latency: -1, Error: "Link, node, or chain is required"})
		return
	}

	if req.URL == "" {
		req.URL = "http://www.gstatic.com/generate_204"
	}
	if req.Timeout <= 0 {
		req.Timeout = 5000
	}

	var latency int
	var err error

	if len(req.Chain) > 0 {
		// Chain proxy test
		latency, err = testDelayWithChain(req.Chain, req.URL, time.Duration(req.Timeout)*time.Millisecond)
	} else if req.Node != nil {
		latency, err = testDelayWithNode(req.Node, req.URL, time.Duration(req.Timeout)*time.Millisecond)
	} else {
		latency, err = testDelay(req.Link, req.URL, time.Duration(req.Timeout)*time.Millisecond)
	}

	if err != nil {
		sendJSON(w, DelayResponse{Success: false, Latency: -1, Error: err.Error()})
		return
	}

	sendJSON(w, DelayResponse{Success: true, Latency: latency})
}

func handleIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req IPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, IPResponse{Success: false, Error: "Invalid request"})
		return
	}

	if req.Link == "" && req.Node == nil && len(req.Chain) == 0 {
		sendJSON(w, IPResponse{Success: false, Error: "Link, node, or chain is required"})
		return
	}

	if req.Timeout <= 0 {
		req.Timeout = 5000
	}

	var ip string
	var err error

	if len(req.Chain) > 0 {
		// Chain proxy test
		ip, err = getExitIPWithChain(req.Chain, time.Duration(req.Timeout)*time.Millisecond)
	} else if req.Node != nil {
		ip, err = getExitIPWithNode(req.Node, time.Duration(req.Timeout)*time.Millisecond)
	} else {
		ip, err = getExitIP(req.Link, time.Duration(req.Timeout)*time.Millisecond)
	}

	if err != nil {
		sendJSON(w, IPResponse{Success: false, Error: err.Error()})
		return
	}

	sendJSON(w, IPResponse{Success: true, IP: ip})
}

func handleSpeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SpeedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, SpeedResponse{Success: false, Error: "Invalid request"})
		return
	}

	if req.Link == "" && req.Node == nil && len(req.Chain) == 0 {
		sendJSON(w, SpeedResponse{Success: false, Error: "Link, node, or chain is required"})
		return
	}

	if req.URL == "" {
		req.URL = "https://speed.cloudflare.com/__down?bytes=10000000"
	}
	if req.Timeout <= 0 {
		req.Timeout = 10
	}
	if req.Mode == "" {
		req.Mode = "average"
	}
	if req.PeakSampleInterval <= 0 {
		req.PeakSampleInterval = 100
	}

	var speed, peakSpeed float64
	var latency int
	var bytes int64
	var err error

	if len(req.Chain) > 0 {
		// Chain proxy test
		speed, peakSpeed, latency, bytes, err = testSpeedWithChain(req.Chain, req.URL, time.Duration(req.Timeout)*time.Second, req.Mode, req.PeakSampleInterval)
	} else if req.Node != nil {
		speed, peakSpeed, latency, bytes, err = testSpeedWithNode(req.Node, req.URL, time.Duration(req.Timeout)*time.Second, req.Mode, req.PeakSampleInterval)
	} else {
		speed, peakSpeed, latency, bytes, err = testSpeed(req.Link, req.URL, time.Duration(req.Timeout)*time.Second, req.Mode, req.PeakSampleInterval)
	}

	if err != nil {
		sendJSON(w, SpeedResponse{Success: false, Error: err.Error()})
		return
	}

	sendJSON(w, SpeedResponse{Success: true, Speed: speed, PeakSpeed: peakSpeed, Latency: latency, Bytes: bytes})
}

func sendJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
