package main

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

var xhttpModes = map[string]bool{
	"auto": true, "packet-up": true, "stream-up": true, "stream-one": true,
}

var xhttpPaddingPlacements = map[string]bool{
	"cookie": true, "header": true, "query": true, "queryInHeader": true,
}

var xhttpPaddingMethods = map[string]bool{
	"repeat-x": true, "tokenish": true,
}

var xhttpSessionPlacements = map[string]bool{
	"path": true, "cookie": true, "header": true, "query": true,
}

var xhttpUplinkDataPlacements = map[string]bool{
	"auto": true, "body": true, "cookie": true, "header": true,
}

var xhttpStringFields = map[string]string{
	"xPaddingKey":         "x-padding-key",
	"xPaddingHeader":      "x-padding-header",
	"xPaddingPlacement":   "x-padding-placement",
	"xPaddingMethod":      "x-padding-method",
	"uplinkHTTPMethod":    "uplink-http-method",
	"uplinkHttpMethod":    "uplink-http-method",
	"sessionIDPlacement":  "session-placement",
	"sessionPlacement":    "session-placement",
	"sessionIDKey":        "session-key",
	"sessionKey":          "session-key",
	"seqPlacement":        "seq-placement",
	"seqKey":              "seq-key",
	"uplinkDataPlacement": "uplink-data-placement",
	"uplinkDataKey":       "uplink-data-key",
}

var xhttpRangeFields = map[string]string{
	"xPaddingBytes":        "x-padding-bytes",
	"uplinkChunkSize":      "uplink-chunk-size",
	"scMaxEachPostBytes":   "sc-max-each-post-bytes",
	"scMinPostsIntervalMs": "sc-min-posts-interval-ms",
}

var xhttpBooleanFields = map[string]string{
	"noGRPCHeader":     "no-grpc-header",
	"xPaddingObfsMode": "x-padding-obfs-mode",
}

var xhttpReuseFields = map[string]string{
	"maxConcurrency":   "max-concurrency",
	"maxConnections":   "max-connections",
	"cMaxReuseTimes":   "c-max-reuse-times",
	"hMaxRequestTimes": "h-max-request-times",
	"hMaxReusableSecs": "h-max-reusable-secs",
}

func parseXHTTPExtra(raw string) (map[string]interface{}, error) {
	var extra map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &extra); err != nil {
		return nil, fmt.Errorf("invalid XHTTP extra JSON: %w", err)
	}
	allowed := map[string]bool{"headers": true, "xmux": true, "downloadSettings": true}
	for key := range xhttpStringFields {
		allowed[key] = true
	}
	for key := range xhttpRangeFields {
		allowed[key] = true
	}
	for key := range xhttpBooleanFields {
		allowed[key] = true
	}
	if unknown := unknownXHTTPKeys(extra, allowed); len(unknown) > 0 {
		return nil, fmt.Errorf("unsupported XHTTP extra field: %s", strings.Join(unknown, ", "))
	}

	opts := map[string]interface{}{}
	root := make(map[string]interface{}, len(extra))
	for key, value := range extra {
		if key != "downloadSettings" {
			root[key] = value
		}
	}
	if err := parseXHTTPFields(root, opts, "extra"); err != nil {
		return nil, err
	}
	if download, exists := extra["downloadSettings"]; exists {
		settings, err := parseXHTTPDownloadSettings(download)
		if err != nil {
			return nil, err
		}
		opts["download-settings"] = settings
	}
	return opts, nil
}

func validateXHTTPOpts(opts map[string]interface{}) error {
	mode := "auto"
	if value, exists := opts["mode"]; exists {
		text, ok := value.(string)
		if !ok || !xhttpModes[text] {
			return fmt.Errorf("unsupported XHTTP mode")
		}
		mode = text
	}
	for _, key := range []string{"path", "host"} {
		if value, exists := opts[key]; exists {
			if _, ok := value.(string); !ok {
				return fmt.Errorf("xhttp-opts.%s must be a string", key)
			}
		}
	}
	if err := validateXHTTPScalarCombinations(opts, "xhttp-opts", mode); err != nil {
		return err
	}
	if mode == "stream-one" {
		if _, exists := opts["download-settings"]; exists {
			return fmt.Errorf("XHTTP stream-one cannot use download settings")
		}
	}
	return nil
}

func validateXHTTPScalarCombinations(values map[string]interface{}, field, mode string) error {
	choices := map[string]map[string]bool{
		"x-padding-placement":   xhttpPaddingPlacements,
		"x-padding-method":      xhttpPaddingMethods,
		"session-placement":     xhttpSessionPlacements,
		"seq-placement":         xhttpSessionPlacements,
		"uplink-data-placement": xhttpUplinkDataPlacements,
	}
	for key, allowed := range choices {
		value, exists := values[key]
		if !exists {
			continue
		}
		text, ok := value.(string)
		if !ok || !allowed[text] {
			return fmt.Errorf("unsupported %s.%s value", field, key)
		}
	}
	if value, exists := values["uplink-http-method"]; exists {
		method, ok := value.(string)
		if !ok || strings.TrimSpace(method) == "" {
			return fmt.Errorf("%s.uplink-http-method must be a non-empty string", field)
		}
		if strings.EqualFold(method, "GET") && mode != "packet-up" {
			return fmt.Errorf("%s.uplink-http-method GET requires packet-up mode", field)
		}
	}
	if value, exists := values["uplink-data-placement"]; exists {
		placement, _ := value.(string)
		if (placement == "cookie" || placement == "header") && mode != "packet-up" {
			return fmt.Errorf("%s.uplink-data-placement requires packet-up mode", field)
		}
	}
	return nil
}

func parseXHTTPFields(source, target map[string]interface{}, field string) error {
	allowed := map[string]bool{"headers": true, "xmux": true}
	for key := range xhttpStringFields {
		allowed[key] = true
	}
	for key := range xhttpRangeFields {
		allowed[key] = true
	}
	for key := range xhttpBooleanFields {
		allowed[key] = true
	}
	if unknown := unknownXHTTPKeys(source, allowed); len(unknown) > 0 {
		return fmt.Errorf("unsupported %s field: %s", field, strings.Join(unknown, ", "))
	}

	for sourceKey, targetKey := range xhttpStringFields {
		value, exists := source[sourceKey]
		if !exists {
			continue
		}
		text, ok := value.(string)
		if !ok {
			return fmt.Errorf("%s.%s must be a string", field, sourceKey)
		}
		target[targetKey] = text
	}
	for sourceKey, targetKey := range xhttpRangeFields {
		value, exists := source[sourceKey]
		if !exists {
			continue
		}
		rangeText, err := xhttpRangeString(value)
		if err != nil {
			return fmt.Errorf("%s.%s: %w", field, sourceKey, err)
		}
		target[targetKey] = rangeText
	}
	for sourceKey, targetKey := range xhttpBooleanFields {
		value, exists := source[sourceKey]
		if !exists {
			continue
		}
		boolean, ok := value.(bool)
		if !ok {
			return fmt.Errorf("%s.%s must be a boolean", field, sourceKey)
		}
		target[targetKey] = boolean
	}
	if headersValue, exists := source["headers"]; exists {
		headers, err := xhttpHeaders(headersValue, field+".headers")
		if err != nil {
			return err
		}
		target["headers"] = headers
	}
	if xmuxValue, exists := source["xmux"]; exists {
		reuse, err := parseXHTTPReuseSettings(xmuxValue, field+".xmux")
		if err != nil {
			return err
		}
		target["reuse-settings"] = reuse
	}
	return nil
}

func parseXHTTPReuseSettings(value interface{}, field string) (map[string]interface{}, error) {
	xmux, ok := value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must be an object", field)
	}
	allowed := map[string]bool{"hKeepAlivePeriod": true}
	for key := range xhttpReuseFields {
		allowed[key] = true
	}
	if unknown := unknownXHTTPKeys(xmux, allowed); len(unknown) > 0 {
		return nil, fmt.Errorf("unsupported %s field: %s", field, strings.Join(unknown, ", "))
	}
	reuse := map[string]interface{}{}
	for sourceKey, targetKey := range xhttpReuseFields {
		if value, exists := xmux[sourceKey]; exists {
			rangeText, err := xhttpRangeString(value)
			if err != nil {
				return nil, fmt.Errorf("%s.%s: %w", field, sourceKey, err)
			}
			reuse[targetKey] = rangeText
		}
	}
	if keepAliveValue, exists := xmux["hKeepAlivePeriod"]; exists {
		keepAlive, err := xhttpInteger(keepAliveValue)
		if err != nil || keepAlive < 0 {
			return nil, fmt.Errorf("%s.hKeepAlivePeriod must be a non-negative integer", field)
		}
		reuse["h-keep-alive-period"] = keepAlive
	}
	if _, concurrency := reuse["max-concurrency"]; concurrency {
		if _, connections := reuse["max-connections"]; connections {
			return nil, fmt.Errorf("%s maxConcurrency and maxConnections cannot both be specified", field)
		}
	}
	return reuse, nil
}

func parseXHTTPDownloadSettings(value interface{}) (map[string]interface{}, error) {
	settings, ok := value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("extra.downloadSettings must be an object")
	}
	allowed := map[string]bool{
		"address": true, "port": true, "network": true, "security": true,
		"tlsSettings": true, "realitySettings": true, "xhttpSettings": true,
	}
	if unknown := unknownXHTTPKeys(settings, allowed); len(unknown) > 0 {
		return nil, fmt.Errorf("unsupported extra.downloadSettings field: %s", strings.Join(unknown, ", "))
	}

	network := strings.ToLower(strings.TrimSpace(toString(settings["network"])))
	if network != "" && network != "xhttp" && network != "splithttp" {
		return nil, fmt.Errorf("extra.downloadSettings.network must be xhttp")
	}
	result := map[string]interface{}{}
	if address, exists := settings["address"]; exists {
		addressText, ok := address.(string)
		if !ok {
			return nil, fmt.Errorf("extra.downloadSettings.address must be a string")
		}
		result["server"] = addressText
	}
	if portValue, exists := settings["port"]; exists {
		port, err := xhttpInteger(portValue)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("extra.downloadSettings.port must be from 1 to 65535")
		}
		result["port"] = port
	}

	security := strings.ToLower(strings.TrimSpace(toString(settings["security"])))
	if security != "" && security != "none" && security != "tls" && security != "reality" {
		return nil, fmt.Errorf("unsupported extra.downloadSettings.security")
	}
	if security == "tls" || security == "reality" {
		result["tls"] = true
	}

	if tlsValue, exists := settings["tlsSettings"]; exists {
		tlsSettings, ok := tlsValue.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("extra.downloadSettings.tlsSettings must be an object")
		}
		allowedTLS := map[string]bool{
			"serverName": true, "fingerprint": true, "alpn": true,
			"allowInsecure": true, "pinnedPeerCertSha256": true,
		}
		if unknown := unknownXHTTPKeys(tlsSettings, allowedTLS); len(unknown) > 0 {
			return nil, fmt.Errorf("unsupported extra.downloadSettings.tlsSettings field: %s", strings.Join(unknown, ", "))
		}
		for sourceKey, targetKey := range map[string]string{
			"serverName": "servername", "fingerprint": "client-fingerprint",
			"pinnedPeerCertSha256": "fingerprint",
		} {
			if value, exists := tlsSettings[sourceKey]; exists {
				text, ok := value.(string)
				if !ok {
					return nil, fmt.Errorf("extra.downloadSettings.tlsSettings.%s must be a string", sourceKey)
				}
				result[targetKey] = text
			}
		}
		if value, exists := tlsSettings["allowInsecure"]; exists {
			boolean, ok := value.(bool)
			if !ok {
				return nil, fmt.Errorf("extra.downloadSettings.tlsSettings.allowInsecure must be a boolean")
			}
			result["skip-cert-verify"] = boolean
		}
		if value, exists := tlsSettings["alpn"]; exists {
			alpn, err := xhttpALPN(value)
			if err != nil {
				return nil, err
			}
			result["alpn"] = alpn
		}
	}

	if realityValue, exists := settings["realitySettings"]; exists {
		reality, ok := realityValue.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("extra.downloadSettings.realitySettings must be an object")
		}
		allowedReality := map[string]bool{"publicKey": true, "shortId": true}
		if unknown := unknownXHTTPKeys(reality, allowedReality); len(unknown) > 0 {
			return nil, fmt.Errorf("unsupported extra.downloadSettings.realitySettings field: %s", strings.Join(unknown, ", "))
		}
		realityOpts := map[string]interface{}{}
		for sourceKey, targetKey := range map[string]string{"publicKey": "public-key", "shortId": "short-id"} {
			if value, exists := reality[sourceKey]; exists {
				text, ok := value.(string)
				if !ok {
					return nil, fmt.Errorf("extra.downloadSettings.realitySettings.%s must be a string", sourceKey)
				}
				realityOpts[targetKey] = text
			}
		}
		result["reality-opts"] = realityOpts
		result["tls"] = true
	}

	if xhttpValue, exists := settings["xhttpSettings"]; exists {
		xhttpSettings, ok := xhttpValue.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("extra.downloadSettings.xhttpSettings must be an object")
		}
		allowedXHTTP := map[string]bool{"path": true, "host": true, "extra": true, "headers": true, "xmux": true}
		for key := range xhttpStringFields {
			allowedXHTTP[key] = true
		}
		for key := range xhttpRangeFields {
			allowedXHTTP[key] = true
		}
		for key := range xhttpBooleanFields {
			allowedXHTTP[key] = true
		}
		if unknown := unknownXHTTPKeys(xhttpSettings, allowedXHTTP); len(unknown) > 0 {
			return nil, fmt.Errorf("unsupported extra.downloadSettings.xhttpSettings field: %s", strings.Join(unknown, ", "))
		}
		for _, key := range []string{"path", "host"} {
			if value, exists := xhttpSettings[key]; exists {
				text, ok := value.(string)
				if !ok {
					return nil, fmt.Errorf("extra.downloadSettings.xhttpSettings.%s must be a string", key)
				}
				result[key] = text
			}
		}
		direct := map[string]interface{}{}
		for key, value := range xhttpSettings {
			if key != "path" && key != "host" && key != "extra" {
				direct[key] = value
			}
		}
		if err := parseXHTTPFields(direct, result, "extra.downloadSettings.xhttpSettings"); err != nil {
			return nil, err
		}
		if nestedValue, exists := xhttpSettings["extra"]; exists {
			nested, ok := nestedValue.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("extra.downloadSettings.xhttpSettings.extra must be an object")
			}
			if unknown := unknownXHTTPKeys(nested, map[string]bool{"xmux": true}); len(unknown) > 0 {
				return nil, fmt.Errorf("unsupported extra.downloadSettings.xhttpSettings.extra field: %s", strings.Join(unknown, ", "))
			}
			if xmuxValue, exists := nested["xmux"]; exists {
				if _, duplicate := result["reuse-settings"]; duplicate {
					return nil, fmt.Errorf("duplicate XHTTP download xmux settings")
				}
				reuse, err := parseXHTTPReuseSettings(xmuxValue, "extra.downloadSettings.xhttpSettings.extra.xmux")
				if err != nil {
					return nil, err
				}
				result["reuse-settings"] = reuse
			}
		}
	}
	if err := validateXHTTPScalarCombinations(result, "extra.downloadSettings.xhttpSettings", ""); err != nil {
		return nil, err
	}
	return result, nil
}

func xhttpHeaders(value interface{}, field string) (map[string]interface{}, error) {
	headers, ok := value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must be an object", field)
	}
	result := map[string]interface{}{}
	for key, value := range headers {
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("%s must contain string values", field)
		}
		if strings.EqualFold(key, "host") {
			return nil, fmt.Errorf("%s cannot contain Host", field)
		}
		result[key] = text
	}
	return result, nil
}

func xhttpALPN(value interface{}) ([]string, error) {
	if text, ok := value.(string); ok {
		return splitALPN(text), nil
	}
	values, ok := value.([]interface{})
	if !ok {
		return nil, fmt.Errorf("extra.downloadSettings.tlsSettings.alpn must be a string list")
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok || text == "" {
			return nil, fmt.Errorf("extra.downloadSettings.tlsSettings.alpn must be a string list")
		}
		result = append(result, text)
	}
	return result, nil
}

func xhttpRangeString(value interface{}) (string, error) {
	if integer, err := xhttpInteger(value); err == nil {
		if integer < 0 {
			return "", fmt.Errorf("must be a non-negative integer range")
		}
		return strconv.Itoa(integer), nil
	}
	if text, ok := value.(string); ok {
		parts := strings.Split(text, "-")
		if len(parts) == 1 {
			if parsed, err := strconv.Atoi(strings.TrimSpace(parts[0])); err == nil && parsed >= 0 {
				return strings.TrimSpace(text), nil
			}
		} else if len(parts) == 2 {
			if start, err := strconv.Atoi(strings.TrimSpace(parts[0])); err == nil && start >= 0 {
				if end, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil && end >= start {
					return strings.TrimSpace(text), nil
				}
			}
		}
	}
	if valueMap, ok := value.(map[string]interface{}); ok {
		if unknown := unknownXHTTPKeys(valueMap, map[string]bool{"from": true, "to": true}); len(unknown) > 0 {
			return "", fmt.Errorf("integer range has unsupported fields")
		}
		from, err := xhttpInteger(valueMap["from"])
		if err != nil {
			return "", fmt.Errorf("integer range needs from")
		}
		to := from
		if toValue, exists := valueMap["to"]; exists {
			to, err = xhttpInteger(toValue)
			if err != nil {
				return "", fmt.Errorf("integer range needs integer to")
			}
		}
		if from == to {
			return strconv.Itoa(from), nil
		}
		if from < 0 || to < from {
			return "", fmt.Errorf("integer range must be non-descending and non-negative")
		}
		return fmt.Sprintf("%d-%d", from, to), nil
	}
	return "", fmt.Errorf("must be an integer range")
}

func xhttpInteger(value interface{}) (int, error) {
	switch typed := value.(type) {
	case int:
		return typed, nil
	case float64:
		if math.Trunc(typed) != typed || typed > float64(math.MaxInt) || typed < float64(math.MinInt) {
			return 0, fmt.Errorf("not an integer")
		}
		return int(typed), nil
	default:
		return 0, fmt.Errorf("not an integer")
	}
}

func unknownXHTTPKeys(values map[string]interface{}, allowed map[string]bool) []string {
	unknown := make([]string, 0)
	for key := range values {
		if !allowed[key] {
			unknown = append(unknown, key)
		}
	}
	sort.Strings(unknown)
	return unknown
}
