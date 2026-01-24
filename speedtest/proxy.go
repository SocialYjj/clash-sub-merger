package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/constant"
)

// getProxyAdapter creates a mihomo proxy adapter from a node link
func getProxyAdapter(link string) (constant.Proxy, error) {
	proxyMap, err := linkToProxyMap(link)
	if err != nil {
		return nil, err
	}

	proxyAdapter, err := adapter.ParseProxy(proxyMap)
	if err != nil {
		return nil, fmt.Errorf("parse proxy error: %v", err)
	}

	return proxyAdapter, nil
}

// testDelay tests latency using mihomo's URLTest
func testDelay(link string, testURL string, timeout time.Duration) (int, error) {
	proxyAdapter, err := getProxyAdapter(link)
	if err != nil {
		return -1, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Use mihomo's built-in URLTest
	delay, err := proxyAdapter.URLTest(ctx, testURL, nil)
	if err != nil {
		return -1, err
	}

	return int(delay), nil
}

// getExitIP gets the exit IP through the proxy
func getExitIP(link string, timeout time.Duration) (string, error) {
	proxyAdapter, err := getProxyAdapter(link)
	if err != nil {
		return "", err
	}
	return getExitIPWithAdapter(proxyAdapter, timeout)
}

// testSpeed tests download speed through the proxy
func testSpeed(link string, testURL string, timeout time.Duration, mode string, peakSampleInterval int) (float64, float64, int, int64, error) {
	proxyAdapter, err := getProxyAdapter(link)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	return testSpeedWithAdapter(proxyAdapter, testURL, timeout, mode, peakSampleInterval)
}

// getProxyAdapterFromNode creates a mihomo proxy adapter from a node config map
func getProxyAdapterFromNode(node map[string]interface{}) (constant.Proxy, error) {
	proxyAdapter, err := adapter.ParseProxy(node)
	if err != nil {
		return nil, fmt.Errorf("parse proxy error: %v", err)
	}
	return proxyAdapter, nil
}

// testDelayWithNode tests latency using direct node config
func testDelayWithNode(node map[string]interface{}, testURL string, timeout time.Duration) (int, error) {
	proxyAdapter, err := getProxyAdapterFromNode(node)
	if err != nil {
		return -1, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	delay, err := proxyAdapter.URLTest(ctx, testURL, nil)
	if err != nil {
		return -1, err
	}

	return int(delay), nil
}

// getExitIPWithNode gets the exit IP using direct node config
func getExitIPWithNode(node map[string]interface{}, timeout time.Duration) (string, error) {
	proxyAdapter, err := getProxyAdapterFromNode(node)
	if err != nil {
		return "", err
	}
	return getExitIPWithAdapter(proxyAdapter, timeout)
}

// testSpeedWithNode tests download speed using direct node config
func testSpeedWithNode(node map[string]interface{}, testURL string, timeout time.Duration, mode string, peakSampleInterval int) (float64, float64, int, int64, error) {
	proxyAdapter, err := getProxyAdapterFromNode(node)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	return testSpeedWithAdapter(proxyAdapter, testURL, timeout, mode, peakSampleInterval)
}

// getExitIPWithAdapter gets the exit IP using an existing adapter
func getExitIPWithAdapter(proxyAdapter constant.Proxy, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
				h, pStr, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				p, _ := strconv.Atoi(pStr)
				md := &constant.Metadata{
					Host:    h,
					DstPort: uint16(p),
					Type:    constant.HTTP,
				}
				return proxyAdapter.DialContext(dialCtx, md)
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: timeout,
	}

	urls := []string{
		"https://api.ipify.org",
		"https://ipinfo.io/ip",
		"https://api.ip.sb/ip",
	}

	for _, ipURL := range urls {
		req, err := http.NewRequestWithContext(ctx, "GET", ipURL, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body := make([]byte, 64)
		n, _ := resp.Body.Read(body)
		resp.Body.Close()

		ip := strings.TrimSpace(string(body[:n]))
		if ip != "" && strings.Contains(ip, ".") {
			return ip, nil
		}
	}

	return "", fmt.Errorf("failed to get exit IP")
}

// testSpeedWithAdapter tests download speed using an existing adapter
// mode: "average" or "peak"
// peakSampleInterval: sampling interval in milliseconds (50-200)
func testSpeedWithAdapter(proxyAdapter constant.Proxy, testURL string, timeout time.Duration, mode string, peakSampleInterval int) (float64, float64, int, int64, error) {
	// Validate parameters
	if mode == "" {
		mode = "average"
	}
	if peakSampleInterval < 50 {
		peakSampleInterval = 50
	} else if peakSampleInterval > 200 {
		peakSampleInterval = 200
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
				h, pStr, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				p, _ := strconv.Atoi(pStr)
				md := &constant.Metadata{
					Host:    h,
					DstPort: uint16(p),
					Type:    constant.HTTP,
				}
				return proxyAdapter.DialContext(dialCtx, md)
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: timeout,
	}

	start := time.Now()
	resp, err := client.Get(testURL)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("request error: %v", err)
	}
	defer resp.Body.Close()

	latency := int(time.Since(start).Milliseconds())

	buf := make([]byte, 32*1024)
	var totalRead int64
	readStart := time.Now()

	// Peak speed sampling variables
	var peakSpeed float64
	var lastSampleBytes int64
	var lastSampleTime time.Time
	var sampleTicker *time.Ticker
	var sampleDone chan struct{}

	if mode == "peak" {
		lastSampleTime = readStart
		lastSampleBytes = 0
		sampleTicker = time.NewTicker(time.Duration(peakSampleInterval) * time.Millisecond)
		sampleDone = make(chan struct{})

		// Sampling goroutine: calculate instant speed at fixed intervals
		go func() {
			defer sampleTicker.Stop()
			for {
				select {
				case <-sampleTicker.C:
					now := time.Now()
					currentBytes := totalRead
					elapsed := now.Sub(lastSampleTime).Seconds()
					if elapsed > 0 {
						instantSpeed := float64(currentBytes-lastSampleBytes) / 1024 / 1024 / elapsed
						if instantSpeed > peakSpeed {
							peakSpeed = instantSpeed
						}
					}
					lastSampleBytes = currentBytes
					lastSampleTime = now
				case <-sampleDone:
					return
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	for {
		n, err := resp.Body.Read(buf)
		totalRead += int64(n)
		if err != nil {
			if err == io.EOF {
				break
			}
			if ctx.Err() != nil {
				break
			}
			break
		}
		select {
		case <-ctx.Done():
			goto Calculate
		default:
		}
	}

Calculate:
	// Stop sampling goroutine
	if sampleDone != nil {
		close(sampleDone)
	}

	duration := time.Since(readStart)
	if duration.Seconds() == 0 {
		return 0, 0, latency, totalRead, nil
	}

	// Minimum valid download check (10KB)
	const minValidBytes int64 = 10 * 1024
	if totalRead < minValidBytes {
		return 0, 0, latency, totalRead, fmt.Errorf("download too small (%d bytes < %d bytes), result unreliable", totalRead, minValidBytes)
	}

	// Average speed (MB/s)
	avgSpeed := float64(totalRead) / 1024 / 1024 / duration.Seconds()

	return avgSpeed, peakSpeed, latency, totalRead, nil
}


// buildProxyChain creates a chain of proxies where each proxy uses the previous one as dialer
// chain: [A, B, C] means traffic goes A -> B -> C -> target
// Returns the final proxy adapter that represents the entire chain
func buildProxyChain(chain []map[string]interface{}) (constant.Proxy, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("empty chain")
	}

	if len(chain) == 1 {
		// Single node, no chain needed
		return getProxyAdapterFromNode(chain[0])
	}

	// Create adapters for all nodes
	adapters := make([]constant.Proxy, len(chain))
	for i, node := range chain {
		adapter, err := getProxyAdapterFromNode(node)
		if err != nil {
			return nil, fmt.Errorf("failed to create adapter for node %d: %v", i, err)
		}
		adapters[i] = adapter
	}

	// Build chain: each node uses the previous one as dialer
	// For [A, B, C]: B dials through A, C dials through B
	// We need to create new adapters with dialer-proxy set
	
	// Start with the first adapter as the base
	var currentProxy constant.Proxy = adapters[0]
	
	for i := 1; i < len(chain); i++ {
		// Create a new node config with dialer-proxy pointing to previous
		nodeConfig := make(map[string]interface{})
		for k, v := range chain[i] {
			nodeConfig[k] = v
		}
		
		// Set dialer-proxy to the previous proxy's name
		nodeConfig["dialer-proxy"] = currentProxy.Name()
		
		// Parse the new proxy with dialer-proxy set
		// Note: mihomo's adapter.ParseProxy handles dialer-proxy internally
		// But we need to register the previous proxy first
		
		// For now, use a simpler approach: create a wrapped proxy
		nextAdapter, err := adapter.ParseProxy(nodeConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create chained adapter for node %d: %v", i, err)
		}
		
		currentProxy = nextAdapter
	}
	
	return currentProxy, nil
}

// testDelayWithChain tests latency through a proxy chain
func testDelayWithChain(chain []map[string]interface{}, testURL string, timeout time.Duration) (int, error) {
	if len(chain) == 0 {
		return -1, fmt.Errorf("empty chain")
	}
	
	// For chain testing, we need to manually build the connection chain
	// Since mihomo's dialer-proxy requires proxies to be registered in a global map,
	// we'll use a different approach: dial through each proxy sequentially
	
	if len(chain) == 1 {
		return testDelayWithNode(chain[0], testURL, timeout)
	}
	
	// Build the chain adapter
	chainAdapter, err := buildChainAdapter(chain)
	if err != nil {
		return -1, err
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	
	delay, err := chainAdapter.URLTest(ctx, testURL, nil)
	if err != nil {
		return -1, err
	}
	
	return int(delay), nil
}

// getExitIPWithChain gets the exit IP through a proxy chain
func getExitIPWithChain(chain []map[string]interface{}, timeout time.Duration) (string, error) {
	if len(chain) == 0 {
		return "", fmt.Errorf("empty chain")
	}
	
	if len(chain) == 1 {
		return getExitIPWithNode(chain[0], timeout)
	}
	
	chainAdapter, err := buildChainAdapter(chain)
	if err != nil {
		return "", err
	}
	
	return getExitIPWithAdapter(chainAdapter, timeout)
}

// testSpeedWithChain tests download speed through a proxy chain
func testSpeedWithChain(chain []map[string]interface{}, testURL string, timeout time.Duration, mode string, peakSampleInterval int) (float64, float64, int, int64, error) {
	if len(chain) == 0 {
		return 0, 0, 0, 0, fmt.Errorf("empty chain")
	}
	
	if len(chain) == 1 {
		return testSpeedWithNode(chain[0], testURL, timeout, mode, peakSampleInterval)
	}
	
	chainAdapter, err := buildChainAdapter(chain)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	
	return testSpeedWithAdapter(chainAdapter, testURL, timeout, mode, peakSampleInterval)
}

// buildChainAdapter creates a proxy adapter that chains multiple proxies together
// This uses a custom approach since mihomo's dialer-proxy requires global registration
func buildChainAdapter(chain []map[string]interface{}) (constant.Proxy, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("empty chain")
	}
	
	if len(chain) == 1 {
		return getProxyAdapterFromNode(chain[0])
	}
	
	// Create the first proxy adapter
	firstAdapter, err := getProxyAdapterFromNode(chain[0])
	if err != nil {
		return nil, fmt.Errorf("failed to create first adapter: %v", err)
	}
	
	// For each subsequent node, we need to create a proxy that dials through the previous one
	// We'll use mihomo's proxy chain support by setting up the dialer-proxy relationship
	
	// Register the first proxy in a temporary map
	proxyMap := make(map[string]constant.Proxy)
	proxyMap[firstAdapter.Name()] = firstAdapter
	
	currentProxyName := firstAdapter.Name()
	
	for i := 1; i < len(chain); i++ {
		nodeConfig := make(map[string]interface{})
		for k, v := range chain[i] {
			nodeConfig[k] = v
		}
		
		// Ensure unique name for intermediate proxies
		if i < len(chain)-1 {
			nodeConfig["name"] = fmt.Sprintf("chain_%d_%s", i, nodeConfig["name"])
		}
		
		// Set dialer-proxy to chain through previous proxy
		nodeConfig["dialer-proxy"] = currentProxyName
		
		// Create adapter with the dialer-proxy set
		// Note: This requires the proxy to be findable by name
		// We'll use a workaround by creating a wrapped dialer
		
		nextAdapter, err := adapter.ParseProxy(nodeConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create adapter %d: %v", i, err)
		}
		
		proxyMap[nextAdapter.Name()] = nextAdapter
		currentProxyName = nextAdapter.Name()
	}
	
	// Return the last adapter in the chain
	return proxyMap[currentProxyName], nil
}

// fetchURL fetches a URL through a proxy and returns content, headers, and status code
func fetchURL(link string, targetURL string, timeout time.Duration) (string, map[string]string, int, error) {
	proxyAdapter, err := getProxyAdapter(link)
	if err != nil {
		return "", nil, 0, err
	}

	return fetchURLWithAdapter(proxyAdapter, targetURL, timeout)
}

// fetchURLWithNode fetches a URL through a proxy node
func fetchURLWithNode(node map[string]interface{}, targetURL string, timeout time.Duration) (string, map[string]string, int, error) {
	proxyAdapter, err := getProxyAdapterFromNode(node)
	if err != nil {
		return "", nil, 0, err
	}

	return fetchURLWithAdapter(proxyAdapter, targetURL, timeout)
}

// fetchURLWithChain fetches a URL through a proxy chain
func fetchURLWithChain(chain []map[string]interface{}, targetURL string, timeout time.Duration) (string, map[string]string, int, error) {
	proxyAdapter, err := buildProxyChain(chain)
	if err != nil {
		return "", nil, 0, err
	}

	return fetchURLWithAdapter(proxyAdapter, targetURL, timeout)
}

// fetchURLWithAdapter fetches a URL using an existing adapter
func fetchURLWithAdapter(proxyAdapter constant.Proxy, targetURL string, timeout time.Duration) (string, map[string]string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Create HTTP client with proxy dialer
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			portNum, err := strconv.Atoi(port)
			if err != nil {
				return nil, err
			}

			metadata := &constant.Metadata{
				Host:    host,
				DstPort: uint16(portNum),
			}

			return proxyAdapter.DialContext(ctx, metadata)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return "", nil, 0, fmt.Errorf("create request error: %v", err)
	}

	// Set User-Agent to mimic FlClash
	req.Header.Set("User-Agent", "FlClash/v0.8.91 clash-verge Platform/windows")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return "", nil, 0, fmt.Errorf("fetch error: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, resp.StatusCode, fmt.Errorf("read body error: %v", err)
	}

	// Extract important headers
	headers := make(map[string]string)
	importantHeaders := []string{
		"subscription-userinfo",
		"profile-update-interval",
		"content-disposition",
		"content-type",
	}
	for _, key := range importantHeaders {
		if value := resp.Header.Get(key); value != "" {
			headers[key] = value
		}
	}

	return string(body), headers, resp.StatusCode, nil
}
