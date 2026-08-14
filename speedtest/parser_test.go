package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/adapter"
)

const (
	testUUID        = "11111111-1111-1111-1111-111111111111"
	testFingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func requireAdapter(t *testing.T, link string) {
	t.Helper()
	if _, err := getProxyAdapter(link); err != nil {
		t.Fatalf("getProxyAdapter returned error: %v", err)
	}
}

func adapterParseError(link string) error {
	proxy, err := linkToProxyMap(link)
	if err != nil {
		return err
	}
	_, err = adapter.ParseProxy(normalizeProxyConfig(proxy))
	return err
}

func requireParseError(t *testing.T, parse func(string) (map[string]interface{}, error), link, contains string) {
	t.Helper()
	if _, err := parse(link); err == nil || !strings.Contains(err.Error(), contains) {
		t.Fatalf("error = %v, want error containing %q", err, contains)
	}
}

func vmessLink(t *testing.T, config map[string]interface{}) string {
	t.Helper()
	payload, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(payload)
}

func TestParseVlessXHTTPCreatesMihomoAdapter(t *testing.T) {
	link := "vless://" + testUUID + "@example.com:443?type=xhttp&mode=stream-up&path=%2Ffoo&host=www.apple.com#xhttp"
	proxy, err := parseVless(link)
	if err != nil {
		t.Fatal(err)
	}
	if proxy["network"] != "xhttp" || !reflect.DeepEqual(proxy["xhttp-opts"], map[string]interface{}{
		"mode": "stream-up", "path": "/foo", "host": "www.apple.com",
	}) {
		t.Fatalf("unexpected xhttp config: %#v", proxy)
	}
	requireAdapter(t, link)
}

func TestParseTrojanUsesPeerAsSNI(t *testing.T) {
	link := "trojan://secret@example.com:443?peer=cdn.example.com#trojan"
	proxy, err := parseTrojan(link)
	if err != nil {
		t.Fatal(err)
	}
	if proxy["sni"] != "cdn.example.com" {
		t.Fatalf("sni = %v", proxy["sni"])
	}
	requireAdapter(t, link)
}

func TestTLSVerificationDefaultsAndExplicitDisable(t *testing.T) {
	defaultVmess := vmessLink(t, map[string]interface{}{
		"v": "2", "ps": "vmess", "add": "example.com", "port": "443",
		"id": testUUID, "aid": "0", "tls": "tls",
	})
	disabledVmess := vmessLink(t, map[string]interface{}{
		"v": "2", "ps": "vmess", "add": "example.com", "port": "443",
		"id": testUUID, "aid": "0", "tls": "tls", "allowInsecure": "true",
	})
	tests := []struct {
		name     string
		parse    func(string) (map[string]interface{}, error)
		link     string
		disabled bool
	}{
		{"vmess-default", parseVmess, defaultVmess, false},
		{"vless-default", parseVless, "vless://" + testUUID + "@example.com:443?security=tls", false},
		{"trojan-default", parseTrojan, "trojan://secret@example.com:443?security=tls", false},
		{"vmess-disabled", parseVmess, disabledVmess, true},
		{"vless-disabled", parseVless, "vless://" + testUUID + "@example.com:443?security=tls&allow_insecure=yes", true},
		{"trojan-disabled", parseTrojan, "trojan://secret@example.com:443?allowInsecure=1", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proxy, err := test.parse(test.link)
			if err != nil {
				t.Fatal(err)
			}
			if got, exists := proxy["skip-cert-verify"]; exists != test.disabled || (exists && got != true) {
				t.Fatalf("skip-cert-verify = %#v, exists=%v", got, exists)
			}
			requireAdapter(t, test.link)
		})
	}
}

func TestRealityAndCertificatePinUseSupportedMihomoFields(t *testing.T) {
	publicKey := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	link := "vless://" + testUUID + "@example.com:443?security=reality&sni=cdn.example.com&fp=chrome&pbk=" + publicKey + "&sid=abcd&support-x25519mlkem768=1&pcs=" + testFingerprint + "&type=grpc&serviceName=GunService#vless"
	proxy, err := parseVless(link)
	if err != nil {
		t.Fatal(err)
	}
	if proxy["fingerprint"] != testFingerprint {
		t.Fatalf("fingerprint = %#v", proxy["fingerprint"])
	}
	if _, exists := proxy["cert-sha"]; exists {
		t.Fatalf("unsupported cert-sha key remains: %#v", proxy)
	}
	wantReality := map[string]interface{}{
		"public-key": publicKey, "short-id": "abcd", "support-x25519mlkem768": true,
	}
	if !reflect.DeepEqual(proxy["reality-opts"], wantReality) {
		t.Fatalf("reality-opts = %#v", proxy["reality-opts"])
	}
	requireAdapter(t, link)
}

func TestUnsupportedTLSRealityAndTransportFieldsAreRejected(t *testing.T) {
	tests := []struct {
		name     string
		parse    func(string) (map[string]interface{}, error)
		link     string
		contains string
	}{
		{"reality-spider", parseVless, "vless://" + testUUID + "@example.com:443?security=reality&pbk=key&spx=%2Fspider", "spider-x"},
		{"ech", parseVless, "vless://" + testUUID + "@example.com:443?security=tls&ech=config", "TLS option"},
		{"pqv", parseVless, "vless://" + testUUID + "@example.com:443?security=reality&pqv=value", "TLS option"},
		{"verify-name", parseTrojan, "trojan://secret@example.com:443?vcn=verify.example", "TLS option"},
		{"finalmask", parseTrojan, "trojan://secret@example.com:443?fm=mask", "TLS option"},
		{"vmess-xhttp", parseVmess, "vmess://" + testUUID + "@example.com:443?type=xhttp", "vmess transport"},
		{"vmess-kcp", parseVmess, "vmess://" + testUUID + "@example.com:443?type=kcp", "vmess transport"},
		{"vless-kcp", parseVless, "vless://" + testUUID + "@example.com:443?type=kcp", "vless transport"},
		{"vless-quic", parseVless, "vless://" + testUUID + "@example.com:443?type=quic", "vless transport"},
		{"trojan-h2", parseTrojan, "trojan://secret@example.com:443?type=h2", "trojan transport"},
		{"grpc-multi", parseVless, "vless://" + testUUID + "@example.com:443?type=grpc&mode=multi", "gRPC mode"},
		{"grpc-authority", parseTrojan, "trojan://secret@example.com:443?type=grpc&authority=grpc.example.com", "gRPC authority"},
		{"trojan-flow", parseTrojan, "trojan://secret@example.com:443?flow=xtls-rprx-vision", "trojan flow"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requireParseError(t, test.parse, test.link, test.contains)
		})
	}
}

func TestHTTPUpgradeAndTCPHTTPDisguiseCreateMihomoAdapters(t *testing.T) {
	upgradeLink := "vless://" + testUUID + "@example.com:443?type=httpupgrade&path=%2Fupgrade&host=cdn.example.com"
	upgrade, err := parseVless(upgradeLink)
	if err != nil {
		t.Fatal(err)
	}
	wantWS := map[string]interface{}{
		"path": "/upgrade", "headers": map[string]interface{}{"Host": "cdn.example.com"}, "v2ray-http-upgrade": true,
	}
	if upgrade["network"] != "ws" || !reflect.DeepEqual(upgrade["ws-opts"], wantWS) {
		t.Fatalf("unexpected HTTP Upgrade config: %#v", upgrade)
	}
	requireAdapter(t, upgradeLink)

	httpLink := "vless://" + testUUID + "@example.com:443?type=tcp&headerType=http&host=cdn.example.com&path=%2Fhidden"
	httpProxy, err := parseVless(httpLink)
	if err != nil {
		t.Fatal(err)
	}
	wantHTTP := map[string]interface{}{
		"path": []string{"/hidden"}, "headers": map[string]interface{}{"Host": []string{"cdn.example.com"}},
	}
	if httpProxy["network"] != "http" || !reflect.DeepEqual(httpProxy["http-opts"], wantHTTP) {
		t.Fatalf("unexpected TCP HTTP config: %#v", httpProxy)
	}
	requireAdapter(t, httpLink)
}

func TestShadowsocksSupportedPluginsCreateMihomoAdapters(t *testing.T) {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:secret"))
	tests := []struct {
		name string
		link string
	}{
		{"obfs", "ss://" + userinfo + "@example.com:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example.com#ss"},
		{"v2ray", "ss://" + userinfo + "@example.com:8388?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bhost%3Dcdn.example.com%3Bpath%3D%2Fws%3Btls%3Bmux%3D0#ss"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseShadowsocks(test.link); err != nil {
				t.Fatal(err)
			}
			requireAdapter(t, test.link)
		})
	}
}

func TestShadowsocksUnsupportedPluginsAndOptionsAreRejected(t *testing.T) {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:secret"))
	for _, suffix := range []string{
		"plugin=unknown-plugin%3Bhost%3Dexample.com",
		"plugin=obfs-local%3Bobfs%3Dhttp%3Bpath%3D%2Fignored",
		"plugin=v2ray-plugin%3Bmode%3Dquic",
		"plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bunknown%3Dvalue",
	} {
		requireParseError(t, parseShadowsocks, "ss://"+userinfo+"@example.com:8388?"+suffix+"#ss", "Shadowsocks")
	}
}

func TestHysteria2ConnectionFieldsCreateMihomoAdapter(t *testing.T) {
	link := "hysteria2://secret@example.com:443?security=tls&sni=www.bing.com&alpn=h3&insecure=1&pinSHA256=" + testFingerprint + "&mport=20000-20002&hop-interval=15&up=100&down=200&obfs=salamander&obfs-password=obfs-secret&cwnd=32&bbr-profile=aggressive&udp-mtu=1400#hy2"
	proxy, err := parseHysteria2(link)
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]interface{}{
		"tls": true, "sni": "www.bing.com", "skip-cert-verify": true, "fingerprint": testFingerprint,
		"ports": "20000-20002", "hop-interval": "15", "up": "100", "down": "200",
		"obfs": "salamander", "obfs-password": "obfs-secret", "cwnd": 32,
		"bbr-profile": "aggressive", "udp-mtu": 1400,
	} {
		if proxy[key] != want {
			t.Fatalf("%s = %#v, want %#v", key, proxy[key], want)
		}
	}
	if !reflect.DeepEqual(proxy["alpn"], []string{"h3"}) {
		t.Fatalf("alpn = %#v", proxy["alpn"])
	}
	if err := adapterParseError(link); err != nil {
		t.Fatalf("mihomo adapter rejected hysteria2 config: %v; proxy=%#v", err, proxy)
	}
}

func TestHysteria2AlwaysKeepsTLSAndRejectsExplicitNonTLS(t *testing.T) {
	proxy, err := parseHysteria2("hysteria2://secret@example.com:443?alpn=h3#hy2")
	if err != nil {
		t.Fatal(err)
	}
	if proxy["tls"] != true {
		t.Fatalf("tls = %#v, want true", proxy["tls"])
	}
	if err := adapterParseError("hysteria2://secret@example.com:443?alpn=h3#hy2"); err != nil {
		t.Fatalf("mihomo adapter rejected implicit TLS profile: %v", err)
	}

	requireParseError(
		t,
		parseHysteria2,
		"hysteria2://secret@example.com:443?security=none#hy2",
		"hysteria2 security",
	)
}

func TestHysteria2UnsupportedObfuscationIsRejected(t *testing.T) {
	requireParseError(t, parseHysteria2, "hysteria2://secret@example.com:443?obfs=unknown", "obfuscation")
}

func TestHysteria2GeckoObfuscationUsesV2rayNDefaults(t *testing.T) {
	proxy, err := parseHysteria2(
		"hysteria2://secret@example.com:443?obfs=gecko&obfs-password=mask-secret#hy2-gecko",
	)
	if err != nil {
		t.Fatal(err)
	}
	if proxy["obfs"] != "gecko" || proxy["obfs-password"] != "mask-secret" {
		t.Fatalf("unexpected Gecko options: %#v", proxy)
	}
	if proxy["obfs-min-packet-size"] != 512 || proxy["obfs-max-packet-size"] != 1200 {
		t.Fatalf("unexpected Gecko defaults: %#v", proxy)
	}
	if err := adapterParseError(
		"hysteria2://secret@example.com:443?obfs=gecko&obfs-password=mask-secret#hy2-gecko",
	); err != nil {
		t.Fatalf("mihomo adapter rejected Gecko config: %v", err)
	}
}

func TestCertificatePinPreservesOpaqueV2rayNValue(t *testing.T) {
	proxy, err := parseHysteria2(
		"hysteria2://secret@example.com:443?pinSHA256=opaque-pin%2B%2F%3D#hy2",
	)
	if err != nil {
		t.Fatal(err)
	}
	if proxy["_v2rayn-certificate-pin"] != "opaque-pin+/=" {
		t.Fatalf("opaque pin = %#v", proxy["_v2rayn-certificate-pin"])
	}
	if _, exists := proxy["fingerprint"]; exists {
		t.Fatalf("opaque pin must not be emitted as Mihomo fingerprint: %#v", proxy)
	}
	if _, err := getProxyAdapterFromNode(proxy); err == nil {
		t.Fatal("opaque certificate pin should not be tested as an unpinned Mihomo node")
	}
}

func TestCertificatePinConvertsBase64SHA256ForMihomoAndPreservesV2rayNValue(t *testing.T) {
	digest := make([]byte, 32)
	for index := range digest {
		digest[index] = byte(index)
	}
	source := base64.StdEncoding.EncodeToString(digest)
	proxy, err := parseHysteria2(
		"hysteria2://secret@example.com:443?pinSHA256=" + url.QueryEscape(source) + "#hy2",
	)
	if err != nil {
		t.Fatal(err)
	}
	if proxy["fingerprint"] != fmt.Sprintf("%x", digest) {
		t.Fatalf("fingerprint = %#v", proxy["fingerprint"])
	}
	if proxy["_v2rayn-certificate-pin"] != source {
		t.Fatalf("preserved pin = %#v", proxy["_v2rayn-certificate-pin"])
	}
	if _, err := getProxyAdapterFromNode(proxy); err != nil {
		t.Fatalf("Mihomo rejected Base64 SHA-256 pin: %v", err)
	}
}
