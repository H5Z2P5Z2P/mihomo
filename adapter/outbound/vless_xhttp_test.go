package outbound

import (
	"net"
	"testing"

	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func stringPtrTest(s string) *string {
	return &s
}

func intPtrTest(v int) *int {
	return &v
}

func boolPtrTest(v bool) *bool {
	return &v
}

func TestVlessXHTTPDownloadSettingsAreIndependent(t *testing.T) {
	v := &Vless{
		Base: &Base{addr: net.JoinHostPort("upload.example.com", "443")},
		option: &VlessOption{
			Server:            "upload.example.com",
			Port:              443,
			TLS:               true,
			ServerName:        "upload-reality.example.com",
			ClientFingerprint: "chrome",
			ALPN:              []string{"h2"},
			XHTTPOpts: XHTTPOptions{
				Host: "upload-host.example.com",
				Mode: "stream-up",
			},
		},
		realityConfig: &tlsC.RealityConfig{},
	}

	downloadServer := "cdn.example.com"
	downloadPort := 8443
	downloadServerName := "download.example.com"
	downloadSettings, err := v.newXHTTPDownloadSettings(&XHTTPDownloadSettings{
		Server:     stringPtrTest(downloadServer),
		Port:       intPtrTest(downloadPort),
		TLS:        boolPtrTest(true),
		ServerName: stringPtrTest(downloadServerName),
	})
	require.NoError(t, err)
	require.NotNil(t, downloadSettings)

	assert.Equal(t, net.JoinHostPort(downloadServer, "8443"), downloadSettings.dialAddr)
	assert.True(t, downloadSettings.tls)
	assert.Equal(t, downloadServerName, downloadSettings.config.Host)
	assert.Equal(t, downloadServerName, downloadSettings.tlsOpts.Host)
	assert.Nil(t, downloadSettings.tlsOpts.Reality)
	assert.Nil(t, downloadSettings.tlsOpts.NextProtos)
	assert.NotEqual(t, v.option.XHTTPOpts.Host, downloadSettings.config.Host)
	assert.NotEqual(t, v.option.ServerName, downloadSettings.tlsOpts.Host)
}
