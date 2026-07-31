package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/constant"
)

func TestDelayHandlerPassesDialerProxy(t *testing.T) {
	original := runNodeDelayRequest
	t.Cleanup(func() { runNodeDelayRequest = original })

	const proxyURL = "socks5://user:password@[2001:db8::1]:1080"
	called := false
	runNodeDelayRequest = func(node map[string]interface{}, testURL string, timeout time.Duration, dialerProxy string) (int, error) {
		called = true
		if dialerProxy != proxyURL {
			t.Fatalf("dialer proxy = %q, want request value", dialerProxy)
		}
		return 7, nil
	}

	body := bytes.NewBufferString(`{"node":{"name":"target","type":"http","server":"127.0.0.1","port":8080},"dialer_proxy":"socks5://user:password@[2001:db8::1]:1080"}`)
	request := httptest.NewRequest(http.MethodPost, "/api/delay", body)
	response := httptest.NewRecorder()
	handleDelay(response, request)

	if !called {
		t.Fatal("delay handler did not invoke the node test path")
	}
	var payload DelayResponse
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !payload.Success || payload.Latency != 7 {
		t.Fatalf("unexpected response: %#v", payload)
	}
}

func TestTargetAdapterReceivesDialerOption(t *testing.T) {
	original := parseProxyAdapter
	t.Cleanup(func() { parseProxyAdapter = original })

	callCount := 0
	parseProxyAdapter = func(mapping map[string]interface{}, options ...adapter.ProxyOption) (constant.Proxy, error) {
		callCount++
		if callCount == 1 {
			if mapping["type"] != "http" || mapping["tls"] != true {
				t.Fatalf("unexpected upstream mapping: %#v", mapping)
			}
			if len(options) != 0 {
				t.Fatalf("upstream adapter received %d target options", len(options))
			}
		}
		if callCount == 2 && len(options) != 1 {
			t.Fatalf("target adapter received %d dialer options, want 1", len(options))
		}
		return original(mapping, options...)
	}

	target := map[string]interface{}{
		"name":   "target",
		"type":   "http",
		"server": "127.0.0.1",
		"port":   8080,
	}
	if _, err := getProxyAdapterFromNodeWithDialer(target, "https://user:password@127.0.0.1:8443"); err != nil {
		t.Fatalf("create target adapter: %v", err)
	}
	if callCount != 2 {
		t.Fatalf("parse call count = %d, want 2", callCount)
	}
}

func TestDialerProxyErrorsDoNotExposeCredentials(t *testing.T) {
	secret := "credential-that-must-not-leak"
	_, err := getProxyAdapterFromNodeWithDialer(
		map[string]interface{}{"name": "target", "type": "http", "server": "127.0.0.1", "port": 8080},
		"ftp://user:"+secret+"@127.0.0.1:21",
	)
	if err == nil {
		t.Fatal("unsupported dialer proxy scheme was accepted")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error exposed credentials: %q", err.Error())
	}
}
