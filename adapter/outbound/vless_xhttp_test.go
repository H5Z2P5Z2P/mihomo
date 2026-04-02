package outbound

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func boolPtrTest(v bool) *bool {
	return &v
}

func TestParseXHTTPDownloadRealityConfigRequiresExplicitDownloadRealityOpts(t *testing.T) {
	cfg, err := parseXHTTPDownloadRealityConfig(&XHTTPDownloadSettings{
		TLS: boolPtrTest(true),
	})
	require.NoError(t, err)
	assert.Nil(t, cfg)
}
