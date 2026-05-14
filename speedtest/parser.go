package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// linkToProxyMap converts a proxy link to a map for mihomo adapter
func linkToProxyMap(link string) (map[string]interface{}, error) {
	link = strings.TrimSpace(link)

	if strings.HasPrefix(link, "vmess://") {
		return parseVmess(link)
	} else if strings.HasPrefix(link, "vless://") {
		return parseVless(link)
	} else if strings.HasPrefix(link, "trojan://") {
		return parseTrojan(link)
	} else if strings.HasPrefix(link, "ss://") {
		return parseShadowsocks(link)
	} else if strings.HasPrefix(link, "ssr://") {
		return parseShadowsocksR(link)
	} else if strings.HasPrefix(link, "hysteria2://") || strings.HasPrefix(link, "hy2://") {
		return parseHysteria2(link)
	}

	return nil, fmt.Errorf("unsupported protocol: %s", link[:min(20, len(link))])
}

func setXHTTPOpts(proxy map[string]interface{}, mode, path, host string) {
	xhttpOpts := map[string]interface{}{}
	if mode != "" {
		xhttpOpts["mode"] = mode
	}
	if path != "" {
		xhttpOpts["path"] = path
	}
	if host != "" {
		xhttpOpts["host"] = host
	}
	if len(xhttpOpts) > 0 {
		proxy["xhttp-opts"] = xhttpOpts
	}
}

func parseVmess(link string) (map[string]interface{}, error) {
	// vmess://base64encoded
	encoded := strings.TrimPrefix(link, "vmess://")

	// Handle URL fragment (name)
	if idx := strings.Index(encoded, "#"); idx != -1 {
		encoded = encoded[:idx]
	}

	decoded, err := base64Decode(encoded)
	if err != nil {
		return nil, fmt.Errorf("vmess base64 decode error: %v", err)
	}

	// Parse JSON
	var vmessConfig map[string]interface{}
	if err := json.Unmarshal([]byte(decoded), &vmessConfig); err != nil {
		return nil, fmt.Errorf("vmess json parse error: %v", err)
	}

	port, _ := toInt(vmessConfig["port"])
	aid, _ := toInt(vmessConfig["aid"])

	proxy := map[string]interface{}{
		"name":    vmessConfig["ps"],
		"type":    "vmess",
		"server":  vmessConfig["add"],
		"port":    port,
		"uuid":    vmessConfig["id"],
		"alterId": aid,
		"cipher":  "auto",
		"udp":     true,
	}

	// TLS
	if vmessConfig["tls"] == "tls" {
		proxy["tls"] = true
		if sni, ok := vmessConfig["sni"].(string); ok && sni != "" {
			proxy["servername"] = sni
		}
		proxy["skip-cert-verify"] = true
	}

	// Network type
	net := toString(vmessConfig["net"])
	if net == "" {
		net = "tcp"
	}
	proxy["network"] = net

	// WebSocket options
	if net == "ws" {
		wsOpts := map[string]interface{}{}
		if path := toString(vmessConfig["path"]); path != "" {
			wsOpts["path"] = path
		}
		if host := toString(vmessConfig["host"]); host != "" {
			wsOpts["headers"] = map[string]interface{}{"Host": host}
		}
		proxy["ws-opts"] = wsOpts
	}

	// gRPC options
	if net == "grpc" {
		grpcOpts := map[string]interface{}{}
		if path := toString(vmessConfig["path"]); path != "" {
			grpcOpts["grpc-service-name"] = path
		}
		proxy["grpc-opts"] = grpcOpts
	}

	if net == "xhttp" {
		setXHTTPOpts(
			proxy,
			toString(vmessConfig["mode"]),
			toString(vmessConfig["path"]),
			toString(vmessConfig["host"]),
		)
	}

	return proxy, nil
}

func parseVless(link string) (map[string]interface{}, error) {
	// vless://uuid@server:port?params#name
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}

	port, _ := strconv.Atoi(u.Port())
	params := u.Query()

	proxy := map[string]interface{}{
		"name":   u.Fragment,
		"type":   "vless",
		"server": u.Hostname(),
		"port":   port,
		"uuid":   u.User.Username(),
		"udp":    true,
	}

	// Flow
	if flow := params.Get("flow"); flow != "" {
		proxy["flow"] = flow
	}

	// TLS / Reality
	security := params.Get("security")
	if security == "tls" {
		proxy["tls"] = true
		if sni := params.Get("sni"); sni != "" {
			proxy["servername"] = sni
		}
		if fp := params.Get("fp"); fp != "" {
			proxy["client-fingerprint"] = fp
		}
		if alpn := params.Get("alpn"); alpn != "" {
			proxy["alpn"] = strings.Split(alpn, ",")
		}
		proxy["skip-cert-verify"] = true
	} else if security == "reality" {
		proxy["tls"] = true
		realityOpts := map[string]interface{}{}
		if pbk := params.Get("pbk"); pbk != "" {
			realityOpts["public-key"] = pbk
		}
		if sid := params.Get("sid"); sid != "" {
			realityOpts["short-id"] = sid
		}
		proxy["reality-opts"] = realityOpts
		if sni := params.Get("sni"); sni != "" {
			proxy["servername"] = sni
		}
		if fp := params.Get("fp"); fp != "" {
			proxy["client-fingerprint"] = fp
		}
	}

	// Network type
	netType := params.Get("type")
	if netType == "" {
		netType = "tcp"
	}
	proxy["network"] = netType

	// WebSocket
	if netType == "ws" {
		wsOpts := map[string]interface{}{}
		if path := params.Get("path"); path != "" {
			wsOpts["path"] = path
		}
		if host := params.Get("host"); host != "" {
			wsOpts["headers"] = map[string]interface{}{"Host": host}
		}
		proxy["ws-opts"] = wsOpts
	}

	// gRPC
	if netType == "grpc" {
		grpcOpts := map[string]interface{}{}
		if sn := params.Get("serviceName"); sn != "" {
			grpcOpts["grpc-service-name"] = sn
		}
		proxy["grpc-opts"] = grpcOpts
	}

	if netType == "xhttp" {
		setXHTTPOpts(proxy, params.Get("mode"), params.Get("path"), params.Get("host"))
	}

	return proxy, nil
}

func parseTrojan(link string) (map[string]interface{}, error) {
	// trojan://password@server:port?params#name
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}

	port, _ := strconv.Atoi(u.Port())
	params := u.Query()

	proxy := map[string]interface{}{
		"name":     u.Fragment,
		"type":     "trojan",
		"server":   u.Hostname(),
		"port":     port,
		"password": u.User.Username(),
		"udp":      true,
	}

	// SNI
	if sni := params.Get("sni"); sni != "" {
		proxy["sni"] = sni
	}

	// Skip cert verify
	proxy["skip-cert-verify"] = true

	// Network type
	netType := params.Get("type")
	if netType == "ws" {
		proxy["network"] = "ws"
		wsOpts := map[string]interface{}{}
		if path := params.Get("path"); path != "" {
			wsOpts["path"] = path
		}
		if host := params.Get("host"); host != "" {
			wsOpts["headers"] = map[string]interface{}{"Host": host}
		}
		proxy["ws-opts"] = wsOpts
	} else if netType == "grpc" {
		proxy["network"] = "grpc"
		grpcOpts := map[string]interface{}{}
		if sn := params.Get("serviceName"); sn != "" {
			grpcOpts["grpc-service-name"] = sn
		}
		proxy["grpc-opts"] = grpcOpts
	} else if netType == "xhttp" {
		proxy["network"] = "xhttp"
		setXHTTPOpts(proxy, params.Get("mode"), params.Get("path"), params.Get("host"))
	}

	return proxy, nil
}

func parseShadowsocks(link string) (map[string]interface{}, error) {
	// ss://base64(method:password)@server:port#name
	// or ss://base64(method:password@server:port)#name
	link = strings.TrimPrefix(link, "ss://")

	var name string
	if idx := strings.LastIndex(link, "#"); idx != -1 {
		name, _ = url.QueryUnescape(link[idx+1:])
		link = link[:idx]
	}

	// Try new format: base64(method:password)@server:port
	if idx := strings.Index(link, "@"); idx != -1 {
		encoded := link[:idx]
		serverPart := link[idx+1:]

		decoded, err := base64Decode(encoded)
		if err == nil {
			parts := strings.SplitN(decoded, ":", 2)
			if len(parts) == 2 {
				method := parts[0]
				password := parts[1]

				host, portStr, _ := net.SplitHostPort(serverPart)
				port, _ := strconv.Atoi(portStr)

				return map[string]interface{}{
					"name":     name,
					"type":     "ss",
					"server":   host,
					"port":     port,
					"cipher":   method,
					"password": password,
					"udp":      true,
				}, nil
			}
		}
	}

	// Try old format: base64(method:password@server:port)
	decoded, err := base64Decode(link)
	if err != nil {
		return nil, fmt.Errorf("ss decode error: %v", err)
	}

	// method:password@server:port
	atIdx := strings.LastIndex(decoded, "@")
	if atIdx == -1 {
		return nil, fmt.Errorf("invalid ss format")
	}

	methodPwd := decoded[:atIdx]
	serverPort := decoded[atIdx+1:]

	colonIdx := strings.Index(methodPwd, ":")
	if colonIdx == -1 {
		return nil, fmt.Errorf("invalid ss format")
	}

	method := methodPwd[:colonIdx]
	password := methodPwd[colonIdx+1:]

	host, portStr, _ := net.SplitHostPort(serverPort)
	port, _ := strconv.Atoi(portStr)

	return map[string]interface{}{
		"name":     name,
		"type":     "ss",
		"server":   host,
		"port":     port,
		"cipher":   method,
		"password": password,
		"udp":      true,
	}, nil
}

func parseShadowsocksR(link string) (map[string]interface{}, error) {
	// ssr://base64encoded
	encoded := strings.TrimPrefix(link, "ssr://")
	decoded, err := base64Decode(encoded)
	if err != nil {
		return nil, err
	}

	// server:port:protocol:method:obfs:base64pass/?params
	mainPart := decoded
	var params string
	if idx := strings.Index(decoded, "/?"); idx != -1 {
		mainPart = decoded[:idx]
		params = decoded[idx+2:]
	}

	parts := strings.Split(mainPart, ":")
	if len(parts) < 6 {
		return nil, fmt.Errorf("invalid ssr format")
	}

	port, _ := strconv.Atoi(parts[1])
	password, _ := base64Decode(parts[5])

	proxy := map[string]interface{}{
		"name":     "",
		"type":     "ssr",
		"server":   parts[0],
		"port":     port,
		"protocol": parts[2],
		"cipher":   parts[3],
		"obfs":     parts[4],
		"password": password,
		"udp":      true,
	}

	// Parse params
	if params != "" {
		paramMap, _ := url.ParseQuery(params)
		if remarks := paramMap.Get("remarks"); remarks != "" {
			name, _ := base64Decode(remarks)
			proxy["name"] = name
		}
		if obfsParam := paramMap.Get("obfsparam"); obfsParam != "" {
			decoded, _ := base64Decode(obfsParam)
			proxy["obfs-param"] = decoded
		}
		if protoParam := paramMap.Get("protoparam"); protoParam != "" {
			decoded, _ := base64Decode(protoParam)
			proxy["protocol-param"] = decoded
		}
	}

	return proxy, nil
}

func parseHysteria2(link string) (map[string]interface{}, error) {
	// hysteria2://password@server:port?params#name
	link = strings.TrimPrefix(link, "hysteria2://")
	link = strings.TrimPrefix(link, "hy2://")

	u, err := url.Parse("hy2://" + link)
	if err != nil {
		return nil, err
	}

	port, _ := strconv.Atoi(u.Port())
	params := u.Query()

	proxy := map[string]interface{}{
		"name":     u.Fragment,
		"type":     "hysteria2",
		"server":   u.Hostname(),
		"port":     port,
		"password": u.User.Username(),
	}

	if sni := params.Get("sni"); sni != "" {
		proxy["sni"] = sni
	}

	if insecure := params.Get("insecure"); insecure == "1" {
		proxy["skip-cert-verify"] = true
	}

	return proxy, nil
}

// Helper functions
func base64Decode(s string) (string, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")

	// Add padding
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}

	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func toInt(v interface{}) (int, error) {
	if v == nil {
		return 0, nil
	}
	switch val := v.(type) {
	case int:
		return val, nil
	case float64:
		return int(val), nil
	case string:
		return strconv.Atoi(val)
	}
	return 0, fmt.Errorf("cannot convert to int")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
