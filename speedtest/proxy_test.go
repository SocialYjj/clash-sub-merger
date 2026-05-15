package main

import "testing"

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
