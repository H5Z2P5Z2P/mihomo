package xhttp

import (
	"fmt"
	"strings"

	xsplithttp "github.com/xtls/xray-core/transport/internet/splithttp"
)

const (
	xPaddingPlacementQueryInHeader = "queryInHeader"
	xPaddingPlacementCookie        = "cookie"
	xPaddingPlacementHeader        = "header"
	xPaddingPlacementQuery         = "query"

	xPaddingMethodRepeatX  = "repeat-x"
	xPaddingMethodTokenish = "tokenish"
)

func (c *Config) XrayConfig() (*xsplithttp.Config, error) {
	if c == nil {
		return nil, nil
	}

	xmux, err := c.ReuseConfig.XrayConfig()
	if err != nil {
		return nil, err
	}

	xPaddingPlacement, err := normalizeXPaddingPlacement(c.XPaddingPlacement)
	if err != nil {
		return nil, err
	}
	xPaddingMethod, err := normalizeXPaddingMethod(c.XPaddingMethod)
	if err != nil {
		return nil, err
	}

	xcfg := &xsplithttp.Config{
		Host:              c.Host,
		Path:              c.Path,
		Mode:              c.Mode,
		Headers:           cloneHeaders(c.Headers),
		NoGRPCHeader:      c.NoGRPCHeader,
		XPaddingObfsMode:  c.XPaddingObfsMode,
		XPaddingKey:       normalizeXPaddingKey(c.XPaddingKey),
		XPaddingHeader:    normalizeXPaddingHeader(c.XPaddingHeader),
		XPaddingPlacement: xPaddingPlacement,
		XPaddingMethod:    xPaddingMethod,
		Xmux:              xmux,
	}

	if strings.TrimSpace(c.XPaddingBytes) != "" {
		xcfg.XPaddingBytes, err = xrayRangeConfig(c.XPaddingBytes)
		if err != nil {
			return nil, err
		}
	}

	return xcfg, nil
}

func normalizeXPaddingKey(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return "x_padding"
	}
	return raw
}

func normalizeXPaddingHeader(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return "X-Padding"
	}
	return raw
}

func normalizeXPaddingPlacement(raw string) (string, error) {
	normalized := strings.TrimSpace(raw)
	switch normalized {
	case "":
		return xPaddingPlacementQueryInHeader, nil
	case xPaddingPlacementCookie, xPaddingPlacementHeader, xPaddingPlacementQuery, xPaddingPlacementQueryInHeader:
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported padding placement: %s", raw)
	}
}

func normalizeXPaddingMethod(raw string) (string, error) {
	normalized := strings.TrimSpace(raw)
	switch normalized {
	case "":
		return xPaddingMethodRepeatX, nil
	case xPaddingMethodRepeatX, xPaddingMethodTokenish:
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported padding method: %s", raw)
	}
}

func (c *ReuseConfig) XrayConfig() (*xsplithttp.XmuxConfig, error) {
	if c == nil {
		return nil, nil
	}

	maxConcurrency, err := xrayRangeConfig(c.MaxConcurrency)
	if err != nil {
		return nil, err
	}
	maxConnections, err := xrayRangeConfig(c.MaxConnections)
	if err != nil {
		return nil, err
	}
	cMaxReuseTimes, err := xrayRangeConfig(c.CMaxReuseTimes)
	if err != nil {
		return nil, err
	}
	hMaxRequestTimes, err := xrayRangeConfig(c.HMaxRequestTimes)
	if err != nil {
		return nil, err
	}
	hMaxReusableSecs, err := xrayRangeConfig(c.HMaxReusableSecs)
	if err != nil {
		return nil, err
	}
	hKeepAlivePeriod, err := c.ResolveKeepAliveSeconds()
	if err != nil {
		return nil, err
	}

	return &xsplithttp.XmuxConfig{
		MaxConcurrency:   maxConcurrency,
		MaxConnections:   maxConnections,
		CMaxReuseTimes:   cMaxReuseTimes,
		HMaxRequestTimes: hMaxRequestTimes,
		HMaxReusableSecs: hMaxReusableSecs,
		HKeepAlivePeriod: hKeepAlivePeriod,
	}, nil
}

func xrayRangeConfig(raw string) (*xsplithttp.RangeConfig, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	minVal, maxVal, err := parseRange(raw)
	if err != nil {
		return nil, err
	}

	if minVal < 0 || maxVal < minVal {
		return nil, fmt.Errorf("invalid range: %s", raw)
	}

	return &xsplithttp.RangeConfig{From: int32(minVal), To: int32(maxVal)}, nil
}

func cloneHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}

	cloned := make(map[string]string, len(headers))
	for key, value := range headers {
		cloned[key] = value
	}

	return cloned
}
