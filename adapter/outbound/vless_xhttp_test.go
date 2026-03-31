package outbound

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVlessXHTTPDownloadSettingsAreIndependent(t *testing.T) {
	v := &Vless{
		Base: &Base{addr: net.JoinHostPort("upload.example.com", "443")},
		option: &VlessOption{
			Server:     "upload.example.com",
			Port:       443,
			TLS:        true,
			ServerName: "origin.example.com",
			XHTTPOpts: XHTTPOptions{
				Host: "origin.example.com",
			},
		},
	}

	downloadServer := "cdn.example.com"
	downloadPort := 8443
	downloadServerName := "download.example.com"
	downloadSettings, err := v.newXHTTPDownloadSettings(&XHTTPDownloadSettings{
		Server:     &downloadServer,
		Port:       &downloadPort,
		ServerName: &downloadServerName,
	})
	require.NoError(t, err)
	require.NotNil(t, downloadSettings)

	assert.Equal(t, net.JoinHostPort(downloadServer, "8443"), downloadSettings.dialAddr)
	assert.Equal(t, downloadServerName, downloadSettings.config.Host)
	assert.Equal(t, downloadServerName, downloadSettings.tlsOpts.Host)
	assert.NotEqual(t, v.option.XHTTPOpts.Host, downloadSettings.config.Host)
	assert.NotEqual(t, v.option.ServerName, downloadSettings.tlsOpts.Host)
}
