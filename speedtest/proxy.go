package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/component/proxydialer"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
)

var parseProxyAdapter = adapter.ParseProxy

// initDNS initializes mihomo's DNS resolver with IPv6 support.
// Without this, IPv6 proxy server addresses cause "dns resolve failed: ip version error".
func initDNS() {
	resolver.DisableIPv6 = false

	rs := dns.NewResolver(dns.Config{
		IPv6: true,
		Main: []dns.NameServer{
			{Addr: "114.114.114.114:53"},
			{Addr: "8.8.8.8:53"},
			{Addr: "[2001:4860:4860::8888]:53"},
			{Addr: "[2606:4700:4700::1111]:53"},
		},
	})

	resolver.DefaultResolver = rs.Resolver
	if rs.ProxyResolver.Invalid() {
		resolver.ProxyServerHostResolver = rs.ProxyResolver
	} else {
		resolver.ProxyServerHostResolver = rs.Resolver
	}
}

// getProxyAdapter creates a mihomo proxy adapter from a node link
func getProxyAdapter(link string) (constant.Proxy, error) {
	return getProxyAdapterWithDialer(link, "")
}

func getProxyAdapterWithDialer(link string, dialerProxy string) (constant.Proxy, error) {
	proxyMap, err := linkToProxyMap(link)
	if err != nil {
		return nil, err
	}

	return parseTargetProxy(proxyMap, dialerProxy)
}

func dialerProxyConfig(rawProxyURL string) (map[string]interface{}, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawProxyURL))
	if err != nil || parsed.Hostname() == "" {
		return nil, fmt.Errorf("invalid dialer proxy configuration")
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" && scheme != "socks" && scheme != "socks5" {
		return nil, fmt.Errorf("unsupported dialer proxy scheme")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, fmt.Errorf("invalid dialer proxy configuration")
	}

	defaultPort := 1080
	proxyType := "socks5"
	if scheme == "http" {
		defaultPort = 80
		proxyType = "http"
	} else if scheme == "https" {
		defaultPort = 443
		proxyType = "http"
	}

	port := defaultPort
	if parsed.Port() != "" {
		parsedPort, parseErr := strconv.Atoi(parsed.Port())
		if parseErr != nil || parsedPort < 1 || parsedPort > 65535 {
			return nil, fmt.Errorf("invalid dialer proxy configuration")
		}
		port = parsedPort
	}

	proxyConfig := map[string]interface{}{
		"name":   "__speedtest_dialer_proxy__",
		"type":   proxyType,
		"server": parsed.Hostname(),
		"port":   port,
	}
	if scheme == "https" {
		proxyConfig["tls"] = true
	}
	if parsed.User != nil {
		proxyConfig["username"] = parsed.User.Username()
		if password, exists := parsed.User.Password(); exists {
			proxyConfig["password"] = password
		}
	}
	return proxyConfig, nil
}

func parseTargetProxy(proxyConfig map[string]interface{}, dialerProxy string) (constant.Proxy, error) {
	if strings.TrimSpace(dialerProxy) == "" {
		proxyAdapter, err := parseProxyAdapter(normalizeProxyConfig(proxyConfig))
		if err != nil {
			return nil, fmt.Errorf("parse proxy error")
		}
		return proxyAdapter, nil
	}

	upstreamConfig, err := dialerProxyConfig(dialerProxy)
	if err != nil {
		return nil, err
	}
	upstreamAdapter, err := parseProxyAdapter(upstreamConfig)
	if err != nil {
		return nil, fmt.Errorf("invalid dialer proxy configuration")
	}

	targetConfig := make(map[string]interface{}, len(proxyConfig))
	for key, value := range proxyConfig {
		targetConfig[key] = value
	}
	delete(targetConfig, "dialer-proxy")
	targetAdapter, err := parseProxyAdapter(
		normalizeProxyConfig(targetConfig),
		adapter.WithDialerForAPI(proxydialer.New(upstreamAdapter, true)),
	)
	if err != nil {
		return nil, fmt.Errorf("parse proxy error")
	}
	return targetAdapter, nil
}

func normalizeProxyConfig(node map[string]interface{}) map[string]interface{} {
	if node == nil {
		return nil
	}

	normalized := make(map[string]interface{}, len(node))
	for key, value := range node {
		normalized[key] = value
	}

	if strings.EqualFold(configString(normalized["type"]), "trojan") {
		if configString(normalized["sni"]) == "" {
			for _, alias := range []string{"servername", "peer"} {
				if serverName := configString(normalized[alias]); serverName != "" {
					normalized["sni"] = serverName
					break
				}
			}
		}
		delete(normalized, "servername")
		delete(normalized, "peer")
	}

	return normalizeXHTTPNode(normalized)
}

func configString(value interface{}) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

// testDelay tests latency using mihomo's URLTest
func testDelay(link string, testURL string, timeout time.Duration) (int, error) {
	return testDelayWithDialer(link, testURL, timeout, "")
}

func testDelayWithDialer(link string, testURL string, timeout time.Duration, dialerProxy string) (int, error) {
	proxyAdapter, err := getProxyAdapterWithDialer(link, dialerProxy)
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
	return getExitIPWithDialer(link, timeout, "")
}

func getExitIPWithDialer(link string, timeout time.Duration, dialerProxy string) (string, error) {
	proxyAdapter, err := getProxyAdapterWithDialer(link, dialerProxy)
	if err != nil {
		return "", err
	}
	return getExitIPWithAdapter(proxyAdapter, timeout)
}

// testSpeed tests download speed through the proxy
func testSpeed(link string, testURL string, timeout time.Duration, mode string, peakSampleInterval int) (float64, float64, int, int64, error) {
	return testSpeedWithDialer(link, testURL, timeout, mode, peakSampleInterval, "")
}

func testSpeedWithDialer(link string, testURL string, timeout time.Duration, mode string, peakSampleInterval int, dialerProxy string) (float64, float64, int, int64, error) {
	proxyAdapter, err := getProxyAdapterWithDialer(link, dialerProxy)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	return testSpeedWithAdapter(proxyAdapter, testURL, timeout, mode, peakSampleInterval)
}

// getProxyAdapterFromNode creates a mihomo proxy adapter from a node config map
func getProxyAdapterFromNode(node map[string]interface{}) (constant.Proxy, error) {
	return getProxyAdapterFromNodeWithDialer(node, "")
}

func getProxyAdapterFromNodeWithDialer(node map[string]interface{}, dialerProxy string) (constant.Proxy, error) {
	return parseTargetProxy(node, dialerProxy)
}

func normalizeXHTTPNode(node map[string]interface{}) map[string]interface{} {
	if node == nil || strings.ToLower(fmt.Sprint(node["network"])) != "xhttp" {
		return node
	}

	xhttpOpts := map[string]interface{}{}
	if existing, ok := node["xhttp-opts"].(map[string]interface{}); ok {
		for k, v := range existing {
			if v != nil && fmt.Sprint(v) != "" {
				xhttpOpts[k] = v
			}
		}
	}

	if mode, ok := node["xhttp-mode"]; ok && mode != nil && fmt.Sprint(mode) != "" {
		if _, exists := xhttpOpts["mode"]; !exists {
			xhttpOpts["mode"] = mode
		}
	}
	if path, ok := node["path"]; ok && path != nil && fmt.Sprint(path) != "" {
		if _, exists := xhttpOpts["path"]; !exists {
			xhttpOpts["path"] = path
		}
	}
	if host, ok := node["host"]; ok && host != nil && fmt.Sprint(host) != "" {
		if _, exists := xhttpOpts["host"]; !exists {
			xhttpOpts["host"] = host
		}
	}

	delete(node, "xhttp-mode")
	delete(node, "path")
	delete(node, "host")
	if len(xhttpOpts) > 0 {
		node["xhttp-opts"] = xhttpOpts
	}

	return node
}

// testDelayWithNode tests latency using direct node config
func testDelayWithNode(node map[string]interface{}, testURL string, timeout time.Duration) (int, error) {
	return testDelayWithNodeAndDialer(node, testURL, timeout, "")
}

func testDelayWithNodeAndDialer(node map[string]interface{}, testURL string, timeout time.Duration, dialerProxy string) (int, error) {
	proxyAdapter, err := getProxyAdapterFromNodeWithDialer(node, dialerProxy)
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
	return getExitIPWithNodeAndDialer(node, timeout, "")
}

func getExitIPWithNodeAndDialer(node map[string]interface{}, timeout time.Duration, dialerProxy string) (string, error) {
	proxyAdapter, err := getProxyAdapterFromNodeWithDialer(node, dialerProxy)
	if err != nil {
		return "", err
	}
	return getExitIPWithAdapter(proxyAdapter, timeout)
}

// testSpeedWithNode tests download speed using direct node config
func testSpeedWithNode(node map[string]interface{}, testURL string, timeout time.Duration, mode string, peakSampleInterval int) (float64, float64, int, int64, error) {
	return testSpeedWithNodeAndDialer(node, testURL, timeout, mode, peakSampleInterval, "")
}

func testSpeedWithNodeAndDialer(node map[string]interface{}, testURL string, timeout time.Duration, mode string, peakSampleInterval int, dialerProxy string) (float64, float64, int, int64, error) {
	proxyAdapter, err := getProxyAdapterFromNodeWithDialer(node, dialerProxy)
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

	// Peak speed sampling variables. Sampling is done inside the read loop to
	// avoid data races between the download goroutine and a separate sampler.
	var peakSpeed float64
	var lastSampleBytes int64
	var lastSampleTime time.Time
	sampleInterval := time.Duration(peakSampleInterval) * time.Millisecond

	if mode == "peak" {
		lastSampleTime = readStart
		lastSampleBytes = 0
	}

	for {
		n, err := resp.Body.Read(buf)
		totalRead += int64(n)
		if mode == "peak" {
			now := time.Now()
			if now.Sub(lastSampleTime) >= sampleInterval {
				elapsed := now.Sub(lastSampleTime).Seconds()
				if elapsed > 0 {
					instantSpeed := float64(totalRead-lastSampleBytes) / 1024 / 1024 / elapsed
					if instantSpeed > peakSpeed {
						peakSpeed = instantSpeed
					}
				}
				lastSampleBytes = totalRead
				lastSampleTime = now
			}
		}
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
	if mode == "peak" {
		now := time.Now()
		elapsed := now.Sub(lastSampleTime).Seconds()
		if elapsed > 0 && totalRead > lastSampleBytes {
			instantSpeed := float64(totalRead-lastSampleBytes) / 1024 / 1024 / elapsed
			if instantSpeed > peakSpeed {
				peakSpeed = instantSpeed
			}
		}
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
	return buildChainAdapterWithDialer(chain, "")
}

// testDelayWithChain tests latency through a proxy chain
func testDelayWithChain(chain []map[string]interface{}, testURL string, timeout time.Duration) (int, error) {
	return testDelayWithChainAndDialer(chain, testURL, timeout, "")
}

func testDelayWithChainAndDialer(chain []map[string]interface{}, testURL string, timeout time.Duration, dialerProxy string) (int, error) {
	if len(chain) == 0 {
		return -1, fmt.Errorf("empty chain")
	}

	// For chain testing, we need to manually build the connection chain
	// Since mihomo's dialer-proxy requires proxies to be registered in a global map,
	// we'll use a different approach: dial through each proxy sequentially

	if len(chain) == 1 {
		return testDelayWithNodeAndDialer(chain[0], testURL, timeout, dialerProxy)
	}

	// Build the chain adapter
	chainAdapter, err := buildChainAdapterWithDialer(chain, dialerProxy)
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
	return getExitIPWithChainAndDialer(chain, timeout, "")
}

func getExitIPWithChainAndDialer(chain []map[string]interface{}, timeout time.Duration, dialerProxy string) (string, error) {
	if len(chain) == 0 {
		return "", fmt.Errorf("empty chain")
	}

	if len(chain) == 1 {
		return getExitIPWithNodeAndDialer(chain[0], timeout, dialerProxy)
	}

	chainAdapter, err := buildChainAdapterWithDialer(chain, dialerProxy)
	if err != nil {
		return "", err
	}

	return getExitIPWithAdapter(chainAdapter, timeout)
}

// testSpeedWithChain tests download speed through a proxy chain
func testSpeedWithChain(chain []map[string]interface{}, testURL string, timeout time.Duration, mode string, peakSampleInterval int) (float64, float64, int, int64, error) {
	return testSpeedWithChainAndDialer(chain, testURL, timeout, mode, peakSampleInterval, "")
}

func testSpeedWithChainAndDialer(chain []map[string]interface{}, testURL string, timeout time.Duration, mode string, peakSampleInterval int, dialerProxy string) (float64, float64, int, int64, error) {
	if len(chain) == 0 {
		return 0, 0, 0, 0, fmt.Errorf("empty chain")
	}

	if len(chain) == 1 {
		return testSpeedWithNodeAndDialer(chain[0], testURL, timeout, mode, peakSampleInterval, dialerProxy)
	}

	chainAdapter, err := buildChainAdapterWithDialer(chain, dialerProxy)
	if err != nil {
		return 0, 0, 0, 0, err
	}

	return testSpeedWithAdapter(chainAdapter, testURL, timeout, mode, peakSampleInterval)
}

// buildChainAdapter creates a proxy adapter that chains multiple proxies together
// This uses a custom approach since mihomo's dialer-proxy requires global registration
func buildChainAdapter(chain []map[string]interface{}) (constant.Proxy, error) {
	return buildChainAdapterWithDialer(chain, "")
}

func buildChainAdapterWithDialer(chain []map[string]interface{}, dialerProxy string) (constant.Proxy, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("empty chain")
	}

	if len(chain) == 1 {
		return getProxyAdapterFromNodeWithDialer(chain[0], dialerProxy)
	}

	// Create the first proxy adapter
	currentAdapter, err := getProxyAdapterFromNodeWithDialer(chain[0], dialerProxy)
	if err != nil {
		return nil, fmt.Errorf("failed to create first adapter: %v", err)
	}

	for i := 1; i < len(chain); i++ {
		nodeConfig := make(map[string]interface{})
		for k, v := range chain[i] {
			nodeConfig[k] = v
		}

		// Ensure unique name for intermediate proxies
		if i < len(chain)-1 {
			nodeConfig["name"] = fmt.Sprintf("chain_%d_%s", i, nodeConfig["name"])
		}

		// Do not rely on dialer-proxy name lookup in tunnel.Proxies(); this
		// speedtest service builds temporary adapters that are never registered
		// globally. Inject the previous adapter as the API dialer instead.
		delete(nodeConfig, "dialer-proxy")

		nextAdapter, err := parseProxyAdapter(
			normalizeProxyConfig(nodeConfig),
			adapter.WithDialerForAPI(proxydialer.New(currentAdapter, true)),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create adapter %d: %v", i, err)
		}

		currentAdapter = nextAdapter
	}

	return currentAdapter, nil
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
				Type:    constant.HTTP,
			}

			return proxyAdapter.DialContext(ctx, metadata)
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

	// Set User-Agent
	userAgent := os.Getenv("SUBSCRIPTION_USER_AGENT")
	if userAgent == "" {
		userAgent = "FlClash/v0.8.91 clash-verge Platform/windows"
	}
	req.Header.Set("User-Agent", userAgent)
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
