package main

import (
	"os"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/constant"
)

func TestNormalizeXHTTPNodeMigratesLegacyFields(t *testing.T) {
	node := map[string]interface{}{
		"name":       "legacy-xhttp",
		"type":       "vless",
		"network":    "xhttp",
		"xhttp-mode": "auto",
		"path":       "/bar",
		"host":       "www.apple.com",
	}

	normalized := normalizeXHTTPNode(node)
	opts, ok := normalized["xhttp-opts"].(map[string]interface{})
	if !ok {
		t.Fatalf("xhttp-opts missing or invalid: %#v", normalized["xhttp-opts"])
	}

	if opts["mode"] != "auto" {
		t.Fatalf("mode = %v, want auto", opts["mode"])
	}
	if opts["path"] != "/bar" {
		t.Fatalf("path = %v, want /bar", opts["path"])
	}
	if opts["host"] != "www.apple.com" {
		t.Fatalf("host = %v, want www.apple.com", opts["host"])
	}

	if _, ok := normalized["xhttp-mode"]; ok {
		t.Fatal("legacy xhttp-mode was not removed")
	}
	if _, ok := normalized["path"]; ok {
		t.Fatal("legacy top-level path was not removed")
	}
	if _, ok := normalized["host"]; ok {
		t.Fatal("legacy top-level host was not removed")
	}
}

func TestNormalizeXHTTPNodePreservesExistingXHTTPOpts(t *testing.T) {
	node := map[string]interface{}{
		"network":    "xhttp",
		"xhttp-mode": "auto",
		"path":       "/legacy",
		"xhttp-opts": map[string]interface{}{
			"mode": "stream-up",
			"path": "/current",
		},
	}

	normalized := normalizeXHTTPNode(node)
	opts := normalized["xhttp-opts"].(map[string]interface{})

	if opts["mode"] != "stream-up" {
		t.Fatalf("mode = %v, want existing stream-up", opts["mode"])
	}
	if opts["path"] != "/current" {
		t.Fatalf("path = %v, want existing /current", opts["path"])
	}
}

func TestNormalizeProxyConfigMigratesTrojanServername(t *testing.T) {
	node := map[string]interface{}{
		"name":       "legacy-trojan",
		"type":       "trojan",
		"server":     "example.com",
		"port":       443,
		"password":   "secret",
		"servername": "cdn.example.com",
	}

	normalized := normalizeProxyConfig(node)
	if normalized["sni"] != "cdn.example.com" {
		t.Fatalf("sni = %v, want cdn.example.com", normalized["sni"])
	}
	if _, ok := normalized["servername"]; ok {
		t.Fatal("legacy servername was not removed")
	}
}

func TestGetProxyAdapterNormalizesTrojanServernameBeforeParsing(t *testing.T) {
	original := parseProxyAdapter
	t.Cleanup(func() { parseProxyAdapter = original })

	var captured map[string]interface{}
	parseProxyAdapter = func(mapping map[string]interface{}, options ...adapter.ProxyOption) (constant.Proxy, error) {
		captured = mapping
		return nil, nil
	}

	_, err := getProxyAdapterFromNode(map[string]interface{}{
		"name":       "legacy-trojan",
		"type":       "trojan",
		"server":     "example.com",
		"port":       443,
		"password":   "secret",
		"servername": "cdn.example.com",
	})
	if err != nil {
		t.Fatalf("getProxyAdapterFromNode returned error: %v", err)
	}
	if captured["sni"] != "cdn.example.com" {
		t.Fatalf("captured sni = %v, want cdn.example.com", captured["sni"])
	}
	if _, ok := captured["servername"]; ok {
		t.Fatal("captured mapping retained legacy servername")
	}
}

func TestProxySourceDoesNotDisableTLSVerification(t *testing.T) {
	source, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatalf("read proxy.go: %v", err)
	}

	if strings.Contains(string(source), "InsecureSkipVerify: true") {
		t.Fatal("proxy.go must not disable HTTPS certificate verification")
	}
}

func TestFetchURLWithAdapterMetadataSetsHTTPType(t *testing.T) {
	source, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatalf("read proxy.go: %v", err)
	}

	content := string(source)
	start := strings.Index(content, "func fetchURLWithAdapter")
	if start == -1 {
		t.Fatal("fetchURLWithAdapter function missing")
	}
	end := strings.Index(content[start:], "\n}\n")
	if end == -1 {
		t.Fatal("fetchURLWithAdapter function body not found")
	}
	body := content[start : start+end]
	if !strings.Contains(body, "Type:    constant.HTTP") {
		t.Fatal("fetchURLWithAdapter metadata should set Type: constant.HTTP")
	}
}

func TestProxyChainUsesInjectedDialerInsteadOfGlobalNameLookup(t *testing.T) {
	source, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatalf("read proxy.go: %v", err)
	}
	content := string(source)

	if !strings.Contains(content, "adapter.WithDialerForAPI(proxydialer.New(currentAdapter, true))") {
		t.Fatal("proxy chain should inject previous adapter as dialer instead of relying on global proxy name lookup")
	}
	if strings.Contains(content, "nodeConfig[\"dialer-proxy\"] =") {
		t.Fatal("proxy chain must not create temporary dialer-proxy name references")
	}
}
