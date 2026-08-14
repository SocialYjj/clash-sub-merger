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

func setXHTTPOpts(proxy map[string]interface{}, mode, path, host, extra string) error {
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
	if extra != "" {
		extraOpts, err := parseXHTTPExtra(extra)
		if err != nil {
			return err
		}
		for key, value := range extraOpts {
			xhttpOpts[key] = value
		}
	}
	if len(xhttpOpts) > 0 {
		if err := validateXHTTPOpts(xhttpOpts); err != nil {
			return err
		}
		proxy["xhttp-opts"] = xhttpOpts
	}
	return nil
}

func firstQueryValue(params url.Values, keys ...string) string {
	for _, key := range keys {
		if value := params.Get(key); value != "" {
			return value
		}
	}
	return ""
}

func isTruthy(value interface{}) bool {
	switch strings.ToLower(strings.TrimSpace(toString(value))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func splitALPN(value string) []string {
	var protocols []string
	for _, protocol := range strings.Split(value, ",") {
		if protocol = strings.TrimSpace(protocol); protocol != "" {
			protocols = append(protocols, protocol)
		}
	}
	return protocols
}

func setRealityOpts(proxy map[string]interface{}, params url.Values) error {
	publicKey := firstQueryValue(params, "pbk", "publicKey", "public-key")
	shortID := firstQueryValue(params, "sid", "shortId", "short-id")
	spiderX := firstQueryValue(params, "spx", "spiderX", "spider-x")
	if spiderX != "" {
		return fmt.Errorf("unsupported REALITY spider-x option")
	}
	if publicKey == "" && shortID == "" {
		return nil
	}

	realityOpts := map[string]interface{}{}
	if publicKey != "" {
		realityOpts["public-key"] = publicKey
	}
	if shortID != "" {
		realityOpts["short-id"] = shortID
	}
	if supportMLKEM := firstQueryValue(params, "support-x25519mlkem768", "supportX25519MLKEM768"); supportMLKEM != "" {
		realityOpts["support-x25519mlkem768"] = isTruthy(supportMLKEM)
	}
	proxy["reality-opts"] = realityOpts
	return nil
}

func setAdvancedTLSOpts(proxy map[string]interface{}, params url.Values) error {
	for _, unsupportedKey := range []string{"ech", "pqv", "vcn", "fm"} {
		if params.Get(unsupportedKey) != "" {
			return fmt.Errorf("unsupported TLS option: %s", unsupportedKey)
		}
	}
	if certSHA := firstQueryValue(params, "pcs", "pinSHA256"); certSHA != "" {
		setCertificatePin(proxy, certSHA)
	}
	return nil
}

func setCertificatePin(proxy map[string]interface{}, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if isMihomoFingerprint(value) {
		proxy["fingerprint"] = strings.ToLower(strings.ReplaceAll(value, ":", ""))
		return
	}
	if decoded, err := decodeCertificatePin(value); err == nil {
		proxy["fingerprint"] = fmt.Sprintf("%x", decoded)
		proxy["_v2rayn-certificate-pin"] = value
		return
	}
	proxy["_v2rayn-certificate-pin"] = value
}

func decodeCertificatePin(value string) ([]byte, error) {
	value = strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(value), "-", "+"), "_", "/")
	padding := (4 - len(value)%4) % 4
	decoded, err := base64.StdEncoding.DecodeString(value + strings.Repeat("=", padding))
	if err != nil || len(decoded) != 32 {
		return nil, fmt.Errorf("certificate pin is not a SHA-256 digest")
	}
	return decoded, nil
}

func isMihomoFingerprint(value string) bool {
	compact := strings.ReplaceAll(strings.TrimSpace(value), ":", "")
	if len(compact) != 64 {
		return false
	}
	for _, char := range compact {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			return false
		}
	}
	return true
}

func setURITransport(proxy map[string]interface{}, params url.Values, protocol string) error {
	requestedNetwork := strings.ToLower(firstQueryValue(params, "type", "transport", "network"))
	network := requestedNetwork
	if network == "" || network == "raw" {
		network = "tcp"
	}

	if network == "httpupgrade" {
		network = "ws"
	}

	allowedNetworks := map[string]map[string]bool{
		"vmess":  {"tcp": true, "http": true, "h2": true, "ws": true, "grpc": true},
		"vless":  {"tcp": true, "http": true, "h2": true, "ws": true, "grpc": true, "xhttp": true},
		"trojan": {"tcp": true, "ws": true, "grpc": true},
	}
	if !allowedNetworks[protocol][network] {
		return fmt.Errorf("unsupported %s transport: %s", protocol, network)
	}

	headerType := strings.ToLower(firstQueryValue(params, "headerType", "headertype"))
	if network == "tcp" && headerType != "" && headerType != "none" {
		if headerType != "http" || protocol == "trojan" {
			return fmt.Errorf("unsupported %s TCP disguise", protocol)
		}
		network = "http"
	}
	proxy["network"] = network

	switch network {
	case "ws":
		wsOpts := map[string]interface{}{}
		if path := params.Get("path"); path != "" {
			wsOpts["path"] = path
		}
		if host := params.Get("host"); host != "" {
			wsOpts["headers"] = map[string]interface{}{"Host": host}
		}
		if requestedNetwork == "httpupgrade" {
			wsOpts["v2ray-http-upgrade"] = true
			if params.Get("ed") != "" {
				wsOpts["v2ray-http-upgrade-fast-open"] = true
			}
		} else if earlyData := params.Get("ed"); earlyData != "" {
			maxEarlyData, err := strconv.Atoi(earlyData)
			if err != nil || maxEarlyData < 0 {
				return fmt.Errorf("invalid WebSocket early data size")
			}
			wsOpts["max-early-data"] = maxEarlyData
		}
		if headerName := params.Get("eh"); headerName != "" {
			wsOpts["early-data-header-name"] = headerName
		}
		proxy["ws-opts"] = wsOpts
	case "grpc":
		mode := strings.ToLower(params.Get("mode"))
		if mode != "" && mode != "gun" {
			return fmt.Errorf("unsupported gRPC mode")
		}
		if params.Get("authority") != "" {
			return fmt.Errorf("unsupported gRPC authority")
		}
		grpcOpts := map[string]interface{}{}
		if serviceName := firstQueryValue(params, "serviceName", "servicename"); serviceName != "" {
			grpcOpts["grpc-service-name"] = serviceName
		}
		if len(grpcOpts) > 0 {
			proxy["grpc-opts"] = grpcOpts
		}
	case "http", "h2":
		if network == "http" && headerType == "http" {
			httpOpts := map[string]interface{}{}
			if method := params.Get("method"); method != "" {
				httpOpts["method"] = method
			}
			path := params.Get("path")
			if path == "" {
				path = "/"
			}
			httpOpts["path"] = []string{path}
			if host := params.Get("host"); host != "" {
				httpOpts["headers"] = map[string]interface{}{"Host": []string{host}}
			}
			proxy["http-opts"] = httpOpts
		} else {
			proxy["network"] = "h2"
			h2Opts := map[string]interface{}{}
			if path := params.Get("path"); path != "" {
				h2Opts["path"] = path
			}
			if host := params.Get("host"); host != "" {
				h2Opts["host"] = []string{host}
			}
			if len(h2Opts) > 0 {
				proxy["h2-opts"] = h2Opts
			}
		}
	case "xhttp":
		if err := setXHTTPOpts(
			proxy,
			params.Get("mode"),
			params.Get("path"),
			params.Get("host"),
			params.Get("extra"),
		); err != nil {
			return err
		}
	}
	return nil
}

func parseVmess(link string) (map[string]interface{}, error) {
	// vmess://base64encoded
	encoded := strings.TrimPrefix(link, "vmess://")
	if strings.Contains(strings.SplitN(encoded, "#", 2)[0], "@") {
		return parseStandardVmess(link)
	}

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
	tlsMode := strings.ToLower(toString(vmessConfig["tls"]))
	if tlsMode == "tls" || tlsMode == "reality" || isTruthy(vmessConfig["tls"]) {
		proxy["tls"] = true
		if sni, ok := vmessConfig["sni"].(string); ok && sni != "" {
			proxy["servername"] = sni
		}
		if fp := toString(vmessConfig["fp"]); fp != "" {
			proxy["client-fingerprint"] = fp
		}
		if alpn := splitALPN(toString(vmessConfig["alpn"])); len(alpn) > 0 {
			proxy["alpn"] = alpn
		}
		if certSHA := firstNonEmptyString(vmessConfig, "pcs", "pinSHA256"); certSHA != "" {
			setCertificatePin(proxy, certSHA)
		}
		if isTruthy(vmessConfig["insecure"]) || isTruthy(vmessConfig["allowInsecure"]) || isTruthy(vmessConfig["allow_insecure"]) {
			proxy["skip-cert-verify"] = true
		}
		if tlsMode == "reality" {
			if firstNonEmptyString(vmessConfig, "spx", "spiderX", "spider-x") != "" {
				return nil, fmt.Errorf("unsupported REALITY spider-x option")
			}
			realityOpts := map[string]interface{}{}
			if publicKey := firstNonEmptyString(vmessConfig, "pbk", "publicKey", "public-key"); publicKey != "" {
				realityOpts["public-key"] = publicKey
			}
			if shortID := firstNonEmptyString(vmessConfig, "sid", "shortId", "short-id"); shortID != "" {
				realityOpts["short-id"] = shortID
			}
			if supportMLKEM := firstNonEmptyString(vmessConfig, "support-x25519mlkem768", "supportX25519MLKEM768"); supportMLKEM != "" {
				realityOpts["support-x25519mlkem768"] = isTruthy(supportMLKEM)
			}
			if len(realityOpts) > 0 {
				proxy["reality-opts"] = realityOpts
			}
		}
	}
	for _, unsupportedKey := range []string{"ech", "pqv", "vcn", "fm"} {
		if toString(vmessConfig[unsupportedKey]) != "" {
			return nil, fmt.Errorf("unsupported TLS option: %s", unsupportedKey)
		}
	}
	if err := setVmessJSONTransport(proxy, vmessConfig); err != nil {
		return nil, err
	}

	return proxy, nil
}

func setVmessJSONTransport(proxy map[string]interface{}, vmessConfig map[string]interface{}) error {
	network := strings.ToLower(toString(vmessConfig["net"]))
	if network == "" || network == "raw" {
		network = "tcp"
	}
	headerType := strings.ToLower(toString(vmessConfig["type"]))
	if network == "tcp" && headerType != "" && headerType != "none" {
		if headerType != "http" {
			return fmt.Errorf("unsupported vmess TCP disguise")
		}
		network = "http"
	} else if network == "http" {
		network = "h2"
	} else if network == "httpupgrade" {
		network = "ws"
	}
	if network != "tcp" && network != "http" && network != "h2" && network != "ws" && network != "grpc" {
		return fmt.Errorf("unsupported vmess transport: %s", network)
	}
	proxy["network"] = network

	switch network {
	case "http":
		path := toString(vmessConfig["path"])
		if path == "" {
			path = "/"
		}
		httpOpts := map[string]interface{}{"path": []string{path}}
		if host := toString(vmessConfig["host"]); host != "" {
			httpOpts["headers"] = map[string]interface{}{"Host": []string{host}}
		}
		proxy["http-opts"] = httpOpts
	case "h2":
		h2Opts := map[string]interface{}{}
		if path := toString(vmessConfig["path"]); path != "" {
			h2Opts["path"] = path
		}
		if host := toString(vmessConfig["host"]); host != "" {
			h2Opts["host"] = []string{host}
		}
		if len(h2Opts) > 0 {
			proxy["h2-opts"] = h2Opts
		}
	case "ws":
		wsOpts := map[string]interface{}{}
		path := toString(vmessConfig["path"])
		if parsedPath, err := url.Parse(path); err == nil && parsedPath != nil {
			query := parsedPath.Query()
			if earlyData := query.Get("ed"); earlyData != "" {
				maxEarlyData, parseErr := strconv.Atoi(earlyData)
				if parseErr != nil || maxEarlyData < 0 {
					return fmt.Errorf("invalid WebSocket early data size")
				}
				wsOpts["max-early-data"] = maxEarlyData
				query.Del("ed")
				parsedPath.RawQuery = query.Encode()
				path = parsedPath.String()
			}
			if headerName := query.Get("eh"); headerName != "" {
				wsOpts["early-data-header-name"] = headerName
			}
		}
		if path != "" {
			wsOpts["path"] = path
		}
		if host := toString(vmessConfig["host"]); host != "" {
			wsOpts["headers"] = map[string]interface{}{"Host": host}
		}
		if strings.EqualFold(toString(vmessConfig["net"]), "httpupgrade") {
			wsOpts["v2ray-http-upgrade"] = true
		}
		proxy["ws-opts"] = wsOpts
	case "grpc":
		mode := strings.ToLower(toString(vmessConfig["type"]))
		if mode != "" && mode != "none" && mode != "gun" {
			return fmt.Errorf("unsupported gRPC mode")
		}
		if toString(vmessConfig["host"]) != "" {
			return fmt.Errorf("unsupported gRPC authority")
		}
		if serviceName := toString(vmessConfig["path"]); serviceName != "" {
			proxy["grpc-opts"] = map[string]interface{}{"grpc-service-name": serviceName}
		}
	}
	return nil
}

func firstNonEmptyString(values map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value := toString(values[key]); value != "" {
			return value
		}
	}
	return ""
}

func parseStandardVmess(link string) (map[string]interface{}, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(u.Port())
	params := u.Query()
	proxy := map[string]interface{}{
		"name":    u.Fragment,
		"type":    "vmess",
		"server":  u.Hostname(),
		"port":    port,
		"uuid":    u.User.Username(),
		"alterId": 0,
		"cipher":  "auto",
		"udp":     true,
	}
	if alterID, err := strconv.Atoi(firstQueryValue(params, "alterId", "alterid", "aid")); err == nil {
		proxy["alterId"] = alterID
	}
	if cipher := firstQueryValue(params, "encryption", "cipher", "scy"); cipher != "" {
		proxy["cipher"] = cipher
	}

	security := strings.ToLower(params.Get("security"))
	if security == "tls" || security == "reality" || isTruthy(params.Get("tls")) {
		proxy["tls"] = true
		if sni := firstQueryValue(params, "sni", "peer"); sni != "" {
			proxy["servername"] = sni
		}
		if fp := params.Get("fp"); fp != "" {
			proxy["client-fingerprint"] = fp
		}
		if alpn := splitALPN(params.Get("alpn")); len(alpn) > 0 {
			proxy["alpn"] = alpn
		}
		if fingerprint := firstQueryValue(params, "pcs", "pinSHA256"); fingerprint != "" {
			setCertificatePin(proxy, fingerprint)
		}
		if isTruthy(firstQueryValue(params, "insecure", "allowInsecure", "allow_insecure")) {
			proxy["skip-cert-verify"] = true
		}
		if security == "reality" {
			if err := setRealityOpts(proxy, params); err != nil {
				return nil, err
			}
		}
	}
	if err := setAdvancedTLSOpts(proxy, params); err != nil {
		return nil, err
	}
	if err := setURITransport(proxy, params, "vmess"); err != nil {
		return nil, err
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
	if encryption := params.Get("encryption"); encryption != "" {
		proxy["encryption"] = encryption
	}

	// TLS / Reality
	security := strings.ToLower(params.Get("security"))
	if security == "tls" || security == "reality" {
		proxy["tls"] = true
		if sni := firstQueryValue(params, "sni", "peer"); sni != "" {
			proxy["servername"] = sni
		}
		if fp := params.Get("fp"); fp != "" {
			proxy["client-fingerprint"] = fp
		}
		if alpn := params.Get("alpn"); alpn != "" {
			proxy["alpn"] = splitALPN(alpn)
		}
		if fingerprint := firstQueryValue(params, "pcs", "pinSHA256"); fingerprint != "" {
			setCertificatePin(proxy, fingerprint)
		}
		if isTruthy(firstQueryValue(params, "insecure", "allowInsecure", "allow_insecure")) {
			proxy["skip-cert-verify"] = true
		}
		if security == "reality" {
			if err := setRealityOpts(proxy, params); err != nil {
				return nil, err
			}
		}
	} else {
		if err := setRealityOpts(proxy, params); err != nil {
			return nil, err
		}
		if _, ok := proxy["reality-opts"]; ok {
			proxy["tls"] = true
		}
	}

	if err := setAdvancedTLSOpts(proxy, params); err != nil {
		return nil, err
	}
	if err := setURITransport(proxy, params, "vless"); err != nil {
		return nil, err
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

	// TLS / Reality
	sni := firstQueryValue(params, "sni", "peer")
	if sni != "" {
		proxy["sni"] = sni
	}
	if fp := params.Get("fp"); fp != "" {
		proxy["client-fingerprint"] = fp
	}
	if alpn := splitALPN(params.Get("alpn")); len(alpn) > 0 {
		proxy["alpn"] = alpn
	}
	if fingerprint := firstQueryValue(params, "pcs", "pinSHA256"); fingerprint != "" {
		setCertificatePin(proxy, fingerprint)
	}
	if isTruthy(firstQueryValue(params, "insecure", "allowInsecure", "allow_insecure")) {
		proxy["skip-cert-verify"] = true
	}
	if strings.EqualFold(params.Get("security"), "reality") {
		if err := setRealityOpts(proxy, params); err != nil {
			return nil, err
		}
	}
	if flow := params.Get("flow"); flow != "" {
		return nil, fmt.Errorf("unsupported trojan flow")
	}
	if err := setAdvancedTLSOpts(proxy, params); err != nil {
		return nil, err
	}

	if err := setURITransport(proxy, params, "trojan"); err != nil {
		return nil, err
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

	var params url.Values
	if idx := strings.Index(link, "?"); idx != -1 {
		params, _ = url.ParseQuery(link[idx+1:])
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

				proxy := map[string]interface{}{
					"name":     name,
					"type":     "ss",
					"server":   host,
					"port":     port,
					"cipher":   method,
					"password": password,
					"udp":      true,
				}
				if err := setShadowsocksPlugin(proxy, params.Get("plugin")); err != nil {
					return nil, err
				}
				return proxy, nil
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

	proxy := map[string]interface{}{
		"name":     name,
		"type":     "ss",
		"server":   host,
		"port":     port,
		"cipher":   method,
		"password": password,
		"udp":      true,
	}
	if err := setShadowsocksPlugin(proxy, params.Get("plugin")); err != nil {
		return nil, err
	}
	return proxy, nil
}

func setShadowsocksPlugin(proxy map[string]interface{}, pluginValue string) error {
	if pluginValue == "" {
		return nil
	}

	parts := strings.Split(pluginValue, ";")
	if len(parts) == 0 {
		return nil
	}
	pluginName := strings.ToLower(strings.TrimSpace(parts[0]))
	if pluginName == "simple-obfs" || pluginName == "obfs-local" {
		pluginName = "obfs"
	}
	if pluginName != "obfs" && pluginName != "v2ray-plugin" {
		return fmt.Errorf("unsupported Shadowsocks plugin")
	}

	pluginOpts := map[string]interface{}{}
	for _, part := range parts[1:] {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, value, hasValue := strings.Cut(part, "=")
		key = strings.TrimSpace(key)
		if !hasValue && key != "tls" {
			return fmt.Errorf("unsupported Shadowsocks plugin option")
		}
		if !hasValue {
			value = "true"
		}
		value = strings.ReplaceAll(value, `\\`, `\`)
		value = strings.ReplaceAll(value, `\=`, `=`)
		value = strings.ReplaceAll(value, `\,`, `,`)
		switch pluginName + ":" + key {
		case "obfs:obfs":
			pluginOpts["mode"] = value
		case "obfs:obfs-host":
			pluginOpts["host"] = value
		case "v2ray-plugin:mode":
			if strings.ToLower(value) != "websocket" {
				return fmt.Errorf("unsupported Shadowsocks plugin mode")
			}
			pluginOpts["mode"] = "websocket"
		case "v2ray-plugin:host":
			pluginOpts["host"] = value
		case "v2ray-plugin:path":
			pluginOpts["path"] = value
		case "v2ray-plugin:mux":
			pluginOpts["mux"] = isTruthy(value)
		case "v2ray-plugin:tls":
			pluginOpts["tls"] = isTruthy(value)
		default:
			return fmt.Errorf("unsupported Shadowsocks plugin option")
		}
	}

	if pluginName == "v2ray-plugin" {
		if _, ok := pluginOpts["mode"]; !ok {
			pluginOpts["mode"] = "websocket"
		}
	}
	proxy["plugin"] = pluginName
	if len(pluginOpts) > 0 {
		proxy["plugin-opts"] = pluginOpts
	}
	return nil
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
	security := strings.ToLower(strings.TrimSpace(params.Get("security")))
	if security != "" && security != "tls" {
		return nil, fmt.Errorf("unsupported hysteria2 security: %s", security)
	}

	proxy := map[string]interface{}{
		"name":     u.Fragment,
		"type":     "hysteria2",
		"server":   u.Hostname(),
		"port":     port,
		"password": u.User.Username(),
		"tls":      true,
	}

	if sni := params.Get("sni"); sni != "" {
		proxy["sni"] = sni
	}

	if alpn := splitALPN(params.Get("alpn")); len(alpn) > 0 {
		proxy["alpn"] = alpn
	}

	if isTruthy(firstQueryValue(params, "insecure", "allowInsecure", "allow_insecure")) {
		proxy["skip-cert-verify"] = true
	}

	fingerprint := params.Get("pinSHA256")
	if fingerprint == "" {
		fingerprint = params.Get("pcs")
	}
	if fingerprint != "" {
		setCertificatePin(proxy, fingerprint)
	}

	ports := params.Get("mport")
	if ports == "" {
		ports = params.Get("ports")
	}
	if ports != "" {
		proxy["ports"] = ports
	}

	if obfs := strings.ToLower(params.Get("obfs")); obfs != "" {
		if obfs != "salamander" && obfs != "gecko" {
			return nil, fmt.Errorf("unsupported hysteria2 obfuscation")
		}
		proxy["obfs"] = obfs
		if password := params.Get("obfs-password"); password != "" {
			proxy["obfs-password"] = password
		}
		if obfs == "gecko" {
			minPacket := params.Get("minPacketSize")
			maxPacket := params.Get("maxPacketSize")
			if minPacket == "" {
				minPacket = "512"
			}
			if maxPacket == "" {
				maxPacket = "1200"
			}
			minValue, minErr := strconv.Atoi(minPacket)
			maxValue, maxErr := strconv.Atoi(maxPacket)
			if minErr != nil || maxErr != nil || minValue <= 0 || minValue > maxValue || maxValue > 2048 {
				return nil, fmt.Errorf("invalid hysteria2 gecko packet size")
			}
			proxy["obfs-min-packet-size"] = minValue
			proxy["obfs-max-packet-size"] = maxValue
		}
	}

	for queryKey, proxyKey := range map[string]string{
		"up":           "up",
		"down":         "down",
		"hop-interval": "hop-interval",
		"bbr-profile":  "bbr-profile",
	} {
		if value := params.Get(queryKey); value != "" {
			proxy[proxyKey] = value
		}
	}
	for queryKey, proxyKey := range map[string]string{
		"cwnd":                              "cwnd",
		"udp-mtu":                           "udp-mtu",
		"initial-stream-receive-window":     "initial-stream-receive-window",
		"max-stream-receive-window":         "max-stream-receive-window",
		"initial-connection-receive-window": "initial-connection-receive-window",
		"max-connection-receive-window":     "max-connection-receive-window",
	} {
		if value := params.Get(queryKey); value != "" {
			parsed, parseErr := strconv.ParseUint(value, 10, 64)
			if parseErr != nil || parsed == 0 {
				return nil, fmt.Errorf("invalid hysteria2 option: %s", queryKey)
			}
			if queryKey == "cwnd" || queryKey == "udp-mtu" {
				if parsed > uint64(^uint(0)>>1) {
					return nil, fmt.Errorf("invalid hysteria2 option: %s", queryKey)
				}
				proxy[proxyKey] = int(parsed)
			} else {
				proxy[proxyKey] = parsed
			}
		}
	}
	for _, unsupportedKey := range []string{"ech", "pqv", "vcn", "fm"} {
		if params.Get(unsupportedKey) != "" {
			return nil, fmt.Errorf("unsupported TLS option: %s", unsupportedKey)
		}
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
