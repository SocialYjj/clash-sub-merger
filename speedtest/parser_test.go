package main

import "testing"

func TestParseVlessXHTTPUsesXHTTPOpts(t *testing.T) {
	proxy, err := parseVless("vless://11111111-1111-1111-1111-111111111111@example.com:443?type=xhttp&mode=stream-up&path=%2Ffoo&host=www.apple.com#xhttp")
	if err != nil {
		t.Fatalf("parseVless returned error: %v", err)
	}

	if proxy["network"] != "xhttp" {
		t.Fatalf("network = %v, want xhttp", proxy["network"])
	}

	opts, ok := proxy["xhttp-opts"].(map[string]interface{})
	if !ok {
		t.Fatalf("xhttp-opts missing or invalid: %#v", proxy["xhttp-opts"])
	}

	if opts["mode"] != "stream-up" {
		t.Fatalf("mode = %v, want stream-up", opts["mode"])
	}
	if opts["path"] != "/foo" {
		t.Fatalf("path = %v, want /foo", opts["path"])
	}
	if opts["host"] != "www.apple.com" {
		t.Fatalf("host = %v, want www.apple.com", opts["host"])
	}
}
