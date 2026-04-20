package convert

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// https://v2.hysteria.network/zh/docs/developers/URI-Scheme/
func TestConvertsV2Ray_normal(t *testing.T) {
	hy2test := "hysteria2://letmein@example.com:8443/?insecure=1&obfs=salamander&obfs-password=gawrgura&pinSHA256=deadbeef&sni=real.example.com&up=114&down=514&alpn=h3,h4#hy2test"

	expected := []map[string]interface{}{
		{
			"name":             "hy2test",
			"type":             "hysteria2",
			"server":           "example.com",
			"port":             "8443",
			"sni":              "real.example.com",
			"obfs":             "salamander",
			"obfs-password":    "gawrgura",
			"alpn":             []string{"h3", "h4"},
			"password":         "letmein",
			"up":               "114",
			"down":             "514",
			"skip-cert-verify": true,
			"fingerprint":      "deadbeef",
		},
	}

	proxies, err := ConvertsV2Ray([]byte(hy2test))

	assert.Nil(t, err)
	assert.Equal(t, expected, proxies)
}

func TestConvertsV2RayMieru(t *testing.T) {
	mierusTest := "mierus://user:pass@1.2.3.4?handshake-mode=HANDSHAKE_NO_WAIT&mtu=1400&multiplexing=MULTIPLEXING_HIGH&port=6666&port=9998-9999&port=6489&port=4896&profile=default&protocol=TCP&protocol=TCP&protocol=UDP&protocol=UDP&traffic-pattern=CCoQAQ"

	expected := []map[string]any{
		{
			"name":            "default:6666/TCP",
			"type":            "mieru",
			"server":          "1.2.3.4",
			"port":            6666,
			"transport":       "TCP",
			"udp":             true,
			"username":        "user",
			"password":        "pass",
			"multiplexing":    "MULTIPLEXING_HIGH",
			"handshake-mode":  "HANDSHAKE_NO_WAIT",
			"traffic-pattern": "CCoQAQ",
		},
		{
			"name":            "default:9998-9999/TCP",
			"type":            "mieru",
			"server":          "1.2.3.4",
			"port-range":      "9998-9999",
			"transport":       "TCP",
			"udp":             true,
			"username":        "user",
			"password":        "pass",
			"multiplexing":    "MULTIPLEXING_HIGH",
			"handshake-mode":  "HANDSHAKE_NO_WAIT",
			"traffic-pattern": "CCoQAQ",
		},
		{
			"name":            "default:6489/UDP",
			"type":            "mieru",
			"server":          "1.2.3.4",
			"port":            6489,
			"transport":       "UDP",
			"udp":             true,
			"username":        "user",
			"password":        "pass",
			"multiplexing":    "MULTIPLEXING_HIGH",
			"handshake-mode":  "HANDSHAKE_NO_WAIT",
			"traffic-pattern": "CCoQAQ",
		},
		{
			"name":            "default:4896/UDP",
			"type":            "mieru",
			"server":          "1.2.3.4",
			"port":            4896,
			"transport":       "UDP",
			"udp":             true,
			"username":        "user",
			"password":        "pass",
			"multiplexing":    "MULTIPLEXING_HIGH",
			"handshake-mode":  "HANDSHAKE_NO_WAIT",
			"traffic-pattern": "CCoQAQ",
		},
	}

	proxies, err := ConvertsV2Ray([]byte(mierusTest))

	assert.Nil(t, err)
	assert.Equal(t, expected, proxies)
}

func TestConvertsV2RayMieruMinimal(t *testing.T) {
	mierusTest := "mierus://user:pass@example.com?port=443&protocol=TCP&profile=simple"

	expected := []map[string]any{
		{
			"name":      "simple:443/TCP",
			"type":      "mieru",
			"server":    "example.com",
			"port":      443,
			"transport": "TCP",
			"udp":       true,
			"username":  "user",
			"password":  "pass",
		},
	}

	proxies, err := ConvertsV2Ray([]byte(mierusTest))

	assert.Nil(t, err)
	assert.Equal(t, expected, proxies)
}

func TestConvertsV2RayMieruFragment(t *testing.T) {
	mierusTest := "mierus://user:pass@example.com?port=443&protocol=TCP&profile=default#myproxy"

	proxies, err := ConvertsV2Ray([]byte(mierusTest))

	assert.Nil(t, err)
	assert.Len(t, proxies, 1)
	assert.Equal(t, "myproxy:443/TCP", proxies[0]["name"])
}

func TestParseXHTTPExtraMapsXPaddingFields(t *testing.T) {
	opts := map[string]any{}
	parseXHTTPExtra(map[string]any{
		"xPaddingBytes":     "100-200",
		"xPaddingObfsMode":  true,
		"xPaddingKey":       "pad",
		"xPaddingHeader":    "X-Obfs",
		"xPaddingPlacement": "cookie",
		"xPaddingMethod":    "tokenish",
		"downloadSettings": map[string]any{
			"xhttpSettings": map[string]any{
				"xPaddingBytes":     "200-300",
				"xPaddingObfsMode":  true,
				"xPaddingKey":       "down_pad",
				"xPaddingHeader":    "X-Down-Obfs",
				"xPaddingPlacement": "header",
				"xPaddingMethod":    "repeat-x",
			},
		},
	}, opts)

	assert.Equal(t, "100-200", opts["x-padding-bytes"])
	assert.Equal(t, true, opts["x-padding-obfs-mode"])
	assert.Equal(t, "pad", opts["x-padding-key"])
	assert.Equal(t, "X-Obfs", opts["x-padding-header"])
	assert.Equal(t, "cookie", opts["x-padding-placement"])
	assert.Equal(t, "tokenish", opts["x-padding-method"])

	ds, ok := opts["download-settings"].(map[string]any)
	if !ok {
		t.Fatalf("download-settings = %T, want map[string]any", opts["download-settings"])
	}
	assert.Equal(t, "200-300", ds["x-padding-bytes"])
	assert.Equal(t, true, ds["x-padding-obfs-mode"])
	assert.Equal(t, "down_pad", ds["x-padding-key"])
	assert.Equal(t, "X-Down-Obfs", ds["x-padding-header"])
	assert.Equal(t, "header", ds["x-padding-placement"])
	assert.Equal(t, "repeat-x", ds["x-padding-method"])
}
