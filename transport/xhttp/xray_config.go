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
	xPaddingPlacementPath          = "path"
	xPaddingPlacementBody          = "body"
	xPaddingPlacementAuto          = "auto"

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

	mode := c.NormalizedMode()
	uplinkHTTPMethod, err := normalizeUplinkHTTPMethod(c.UplinkHTTPMethod, mode)
	if err != nil {
		return nil, err
	}
	sessionPlacement, err := normalizeMetaPlacement(c.SessionPlacement, "session", xPaddingPlacementPath)
	if err != nil {
		return nil, err
	}
	seqPlacement, err := normalizeMetaPlacement(c.SeqPlacement, "seq", xPaddingPlacementPath)
	if err != nil {
		return nil, err
	}
	uplinkDataPlacement, err := normalizeUplinkDataPlacement(c.UplinkDataPlacement, mode)
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
		Host:                c.Host,
		Path:                c.Path,
		Mode:                mode,
		Headers:             cloneHeaders(c.Headers),
		UplinkHTTPMethod:    uplinkHTTPMethod,
		SessionPlacement:    sessionPlacement,
		SessionKey:          normalizeMetaKey(c.SessionKey, sessionPlacement, "X-Session", "x_session"),
		SeqPlacement:        seqPlacement,
		SeqKey:              normalizeMetaKey(c.SeqKey, seqPlacement, "X-Seq", "x_seq"),
		UplinkDataPlacement: uplinkDataPlacement,
		UplinkDataKey:       normalizeUplinkDataKey(c.UplinkDataKey, uplinkDataPlacement),
		NoGRPCHeader:        c.NoGRPCHeader,
		XPaddingObfsMode:    c.XPaddingObfsMode,
		XPaddingKey:         normalizeXPaddingKey(c.XPaddingKey),
		XPaddingHeader:      normalizeXPaddingHeader(c.XPaddingHeader),
		XPaddingPlacement:   xPaddingPlacement,
		XPaddingMethod:      xPaddingMethod,
		Xmux:                xmux,
	}

	if strings.TrimSpace(c.XPaddingBytes) != "" {
		xcfg.XPaddingBytes, err = xrayRangeConfig(c.XPaddingBytes)
		if err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(c.UplinkChunkSize) != "" {
		xcfg.UplinkChunkSize, err = xrayRangeConfig(c.UplinkChunkSize)
		if err != nil {
			return nil, err
		}
	}

	return xcfg, nil
}

func normalizeUplinkHTTPMethod(raw string, mode string) (string, error) {
	method := strings.ToUpper(strings.TrimSpace(raw))
	if method == "" {
		method = "POST"
	}
	if method == "GET" && mode != "packet-up" {
		return "", fmt.Errorf("uplinkHTTPMethod can be GET only in packet-up mode")
	}
	return method, nil
}

func normalizeMetaPlacement(raw string, kind string, defaultPlacement string) (string, error) {
	normalized := strings.TrimSpace(raw)
	switch normalized {
	case "":
		return defaultPlacement, nil
	case xPaddingPlacementPath, xPaddingPlacementCookie, xPaddingPlacementHeader, xPaddingPlacementQuery:
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported %s placement: %s", kind, raw)
	}
}

func normalizeMetaKey(raw string, placement string, headerDefault string, queryCookieDefault string) string {
	if strings.TrimSpace(raw) != "" {
		return raw
	}
	switch placement {
	case xPaddingPlacementHeader:
		return headerDefault
	case xPaddingPlacementCookie, xPaddingPlacementQuery:
		return queryCookieDefault
	default:
		return ""
	}
}

func normalizeUplinkDataPlacement(raw string, mode string) (string, error) {
	normalized := strings.TrimSpace(raw)
	switch normalized {
	case "":
		return xPaddingPlacementAuto, nil
	case xPaddingPlacementAuto, xPaddingPlacementBody:
		return normalized, nil
	case xPaddingPlacementCookie, xPaddingPlacementHeader:
		if mode != "packet-up" {
			return "", fmt.Errorf("UplinkDataPlacement can be %s only in packet-up mode", normalized)
		}
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported uplink data placement: %s", raw)
	}
}

func normalizeUplinkDataKey(raw string, placement string) string {
	if strings.TrimSpace(raw) != "" {
		return raw
	}
	switch placement {
	case xPaddingPlacementCookie:
		return "x_data"
	case xPaddingPlacementAuto, xPaddingPlacementHeader:
		return "X-Data"
	default:
		return ""
	}
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
