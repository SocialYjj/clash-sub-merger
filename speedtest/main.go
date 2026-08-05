package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const defaultLatencyURL = "https://cp.cloudflare.com/generate_204"

var fallbackLatencyURLs = []string{
	"https://www.gstatic.com/generate_204",
	"http://cp.cloudflare.com/generate_204",
}

// Request/Response structures
type DelayRequest struct {
	Link        string                   `json:"link"`
	Node        map[string]interface{}   `json:"node"`
	Chain       []map[string]interface{} `json:"chain"`
	URL         string                   `json:"url"`
	Timeout     int                      `json:"timeout"` // milliseconds
	DialerProxy string                   `json:"dialer_proxy"`
}

type DelayResponse struct {
	Success bool   `json:"success"`
	Latency int    `json:"latency"` // milliseconds, -1 if failed
	Error   string `json:"error,omitempty"`
}

type IPRequest struct {
	Link        string                   `json:"link"`
	Node        map[string]interface{}   `json:"node"`
	Chain       []map[string]interface{} `json:"chain"`
	Timeout     int                      `json:"timeout"`
	DialerProxy string                   `json:"dialer_proxy"`
}

type IPResponse struct {
	Success bool   `json:"success"`
	IP      string `json:"ip,omitempty"`
	Error   string `json:"error,omitempty"`
}

type SpeedRequest struct {
	Link               string                   `json:"link"`
	Node               map[string]interface{}   `json:"node"`
	Chain              []map[string]interface{} `json:"chain"`
	URL                string                   `json:"url"`
	Timeout            int                      `json:"timeout"`            // seconds
	Mode               string                   `json:"mode"`               // "average" or "peak", default "average"
	PeakSampleInterval int                      `json:"peakSampleInterval"` // milliseconds, 50-200, default 100
	DialerProxy        string                   `json:"dialer_proxy"`
}

type SpeedResponse struct {
	Success   bool    `json:"success"`
	Speed     float64 `json:"speed"`     // MB/s
	PeakSpeed float64 `json:"peakSpeed"` // MB/s, only in peak mode
	Latency   int     `json:"latency"`   // milliseconds
	Bytes     int64   `json:"bytes"`     // bytes downloaded
	Error     string  `json:"error,omitempty"`
}

type FetchURLRequest struct {
	Link    string                   `json:"link"`
	Node    map[string]interface{}   `json:"node"`
	Chain   []map[string]interface{} `json:"chain"`
	URL     string                   `json:"url"`     // Target URL to fetch
	Timeout int                      `json:"timeout"` // seconds
}

type FetchURLResponse struct {
	Success    bool              `json:"success"`
	Content    string            `json:"content,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	StatusCode int               `json:"statusCode,omitempty"`
	Error      string            `json:"error,omitempty"`
}

var runNodeDelayRequest = testDelayWithNodeAndDialer

func main() {
	initDNS()

	port := os.Getenv("GO_SPEEDTEST_PORT")
	if port == "" {
		port = "9876"
	}

	http.HandleFunc("/api/delay", handleDelay)
	http.HandleFunc("/api/ip", handleIP)
	http.HandleFunc("/api/speed", handleSpeed)
	http.HandleFunc("/api/fetch-url", handleFetchURL)
	http.HandleFunc("/health", handleHealth)

	server := &http.Server{
		Addr:    "127.0.0.1:" + port,
		Handler: nil,
	}

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
		<-sigChan
		log.Println("Shutting down speedtest service...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()

	log.Printf("Speedtest service starting on localhost:%s", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
	log.Println("Speedtest service stopped")
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
		req.URL = defaultLatencyURL
	}
	if req.Timeout <= 0 {
		req.Timeout = 5000
	}

	var latency int
	var err error

	timeout := time.Duration(req.Timeout) * time.Millisecond
	for _, candidateURL := range latencyTestURLs(req.URL) {
		if len(req.Chain) > 0 {
			latency, err = testDelayWithChainAndDialer(req.Chain, candidateURL, timeout, req.DialerProxy)
		} else if req.Node != nil {
			latency, err = runNodeDelayRequest(req.Node, candidateURL, timeout, req.DialerProxy)
		} else {
			latency, err = testDelayWithDialer(req.Link, candidateURL, timeout, req.DialerProxy)
		}
		if err == nil {
			break
		}
	}

	if err != nil {
		sendJSON(w, DelayResponse{Success: false, Latency: -1, Error: err.Error()})
		return
	}

	sendJSON(w, DelayResponse{Success: true, Latency: latency})
}

func latencyTestURLs(requestedURL string) []string {
	// Some proxy providers can reach the internet but cannot complete a TLS
	// handshake with Cloudflare's 204 endpoint. Keep that endpoint as the
	// primary target, then retry with independent 204 endpoints before failing.
	if requestedURL != defaultLatencyURL {
		return []string{requestedURL}
	}

	urls := make([]string, 0, 1+len(fallbackLatencyURLs))
	urls = append(urls, requestedURL)
	urls = append(urls, fallbackLatencyURLs...)
	return urls
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
		ip, err = getExitIPWithChainAndDialer(req.Chain, time.Duration(req.Timeout)*time.Millisecond, req.DialerProxy)
	} else if req.Node != nil {
		ip, err = getExitIPWithNodeAndDialer(req.Node, time.Duration(req.Timeout)*time.Millisecond, req.DialerProxy)
	} else {
		ip, err = getExitIPWithDialer(req.Link, time.Duration(req.Timeout)*time.Millisecond, req.DialerProxy)
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
		speed, peakSpeed, latency, bytes, err = testSpeedWithChainAndDialer(req.Chain, req.URL, time.Duration(req.Timeout)*time.Second, req.Mode, req.PeakSampleInterval, req.DialerProxy)
	} else if req.Node != nil {
		speed, peakSpeed, latency, bytes, err = testSpeedWithNodeAndDialer(req.Node, req.URL, time.Duration(req.Timeout)*time.Second, req.Mode, req.PeakSampleInterval, req.DialerProxy)
	} else {
		speed, peakSpeed, latency, bytes, err = testSpeedWithDialer(req.Link, req.URL, time.Duration(req.Timeout)*time.Second, req.Mode, req.PeakSampleInterval, req.DialerProxy)
	}

	if err != nil {
		sendJSON(w, SpeedResponse{Success: false, Error: err.Error()})
		return
	}

	sendJSON(w, SpeedResponse{Success: true, Speed: speed, PeakSpeed: peakSpeed, Latency: latency, Bytes: bytes})
}

func handleFetchURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req FetchURLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, FetchURLResponse{Success: false, Error: "Invalid request"})
		return
	}

	if req.Link == "" && req.Node == nil && len(req.Chain) == 0 {
		sendJSON(w, FetchURLResponse{Success: false, Error: "Link, node, or chain is required"})
		return
	}

	if req.URL == "" {
		sendJSON(w, FetchURLResponse{Success: false, Error: "URL is required"})
		return
	}

	if req.Timeout <= 0 {
		req.Timeout = 30
	}

	var content string
	var headers map[string]string
	var statusCode int
	var err error

	if len(req.Chain) > 0 {
		content, headers, statusCode, err = fetchURLWithChain(req.Chain, req.URL, time.Duration(req.Timeout)*time.Second)
	} else if req.Node != nil {
		content, headers, statusCode, err = fetchURLWithNode(req.Node, req.URL, time.Duration(req.Timeout)*time.Second)
	} else {
		content, headers, statusCode, err = fetchURL(req.Link, req.URL, time.Duration(req.Timeout)*time.Second)
	}

	if err != nil {
		sendJSON(w, FetchURLResponse{Success: false, Error: err.Error()})
		return
	}

	sendJSON(w, FetchURLResponse{Success: true, Content: content, Headers: headers, StatusCode: statusCode})
}

func sendJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
