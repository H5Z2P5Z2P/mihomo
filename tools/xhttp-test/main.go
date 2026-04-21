package main

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/metacubex/http"
	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/transport/vless"
	"github.com/metacubex/mihomo/transport/vmess"
	"github.com/metacubex/mihomo/transport/xhttp"
)

var defaults = map[string]string{
	"XHTTP_MODE":            "stream-up",
	"XHTTP_UPLOAD_SERVER":   "8.209.212.176:30223",
	"XHTTP_DOWNLOAD_SERVER": "d36uzx9jjio9xb.cloudfront.net:443",
	"XHTTP_PATH":            "/35daaac8",
	"XHTTP_SNI":             "wu.uily.de",
	"XHTTP_UUID":            "81554e53-9f17-445f-9794-39cb418d2f93",
	"XHTTP_REALITY_PUB":     "uiFGNIcRsCMinsfKAQoZT9b2BuS3DhSWXTC0mUr4rVo",
	"XHTTP_REALITY_SID":     "f89f0b7c",
	"XHTTP_DOWNLOAD_SNI":    "d36uzx9jjio9xb.cloudfront.net",
	"XHTTP_FINGERPRINT":     "chrome",
}

func env(key string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaults[key]
}

type debugConn struct {
	net.Conn
	r io.Reader
}

func (d *debugConn) Read(b []byte) (int, error) {
	n, err := d.r.Read(b)
	if n > 0 {
		fmt.Printf("\n[RAW-READ] %d bytes:\n%s\n", n, hex.Dump(b[:n]))
	}
	return n, err
}

func (d *debugConn) Write(b []byte) (int, error) {
	fmt.Printf("\n[RAW-WRITE] %d bytes:\n%s\n", len(b), hex.Dump(b))
	return d.Conn.Write(b)
}

func main() {
	mode := env("XHTTP_MODE")
	uploadServer := env("XHTTP_UPLOAD_SERVER")
	downloadServer := env("XHTTP_DOWNLOAD_SERVER")
	path := env("XHTTP_PATH")
	sni := env("XHTTP_SNI")
	realityPub := env("XHTTP_REALITY_PUB")
	realitySID := env("XHTTP_REALITY_SID")
	downloadSNI := env("XHTTP_DOWNLOAD_SNI")
	fingerprint := env("XHTTP_FINGERPRINT")
	uuidStr := env("XHTTP_UUID")

	fmt.Println("========================================")
	fmt.Println("  XHTTP 端到端协议测试客户端 (anyreality 无死锁版)")
	fmt.Println("========================================")

	realityConfig, err := parseRealityConfig(realityPub, realitySID)
	if err != nil {
		fatal("Reality 配置解析失败", err)
	}

	makeUploadTransport := func() http.RoundTripper {
		return xhttp.NewTransport(
			func(ctx context.Context) (net.Conn, error) {
				fmt.Printf("  [上行] TCP 拨号 -> %s...\n", uploadServer)
				d := net.Dialer{Timeout: 15 * time.Second}
				conn, err := d.DialContext(ctx, "tcp", uploadServer)
				if err != nil {
					return nil, err
				}
				fmt.Println("  [上行] ✅ TCP 连接已建立")
				return conn, nil
			},
			func(ctx context.Context, raw net.Conn, isH2 bool) (net.Conn, error) {
				fmt.Printf("  [上行] Reality 握手 (SNI: %s)...\n", sni)
				tlsOpts := vmess.TLSConfig{
					Host:              sni,
					SkipCertVerify:    false,
					ClientFingerprint: fingerprint,
					Reality:           realityConfig,
				}
				if isH2 {
					tlsOpts.NextProtos = []string{"h2"}
				}
				conn, err := vmess.StreamTLSConn(ctx, raw, &tlsOpts)
				if err != nil {
					return nil, err
				}
				fmt.Println("  [上行] ✅ Reality 握手成功")
				return conn, nil
			},
			nil,
			[]string{"h2"},
			15*time.Second,
		)
	}

	var makeDownloadTransport func() http.RoundTripper
	if downloadServer != "" && downloadServer != uploadServer {
		makeDownloadTransport = func() http.RoundTripper {
			return xhttp.NewTransport(
				func(ctx context.Context) (net.Conn, error) {
					d := net.Dialer{Timeout: 15 * time.Second}
					return d.DialContext(ctx, "tcp", downloadServer)
				},
				func(ctx context.Context, raw net.Conn, isH2 bool) (net.Conn, error) {
					tlsOpts := vmess.TLSConfig{
						Host:              downloadSNI,
						SkipCertVerify:    false,
						ClientFingerprint: fingerprint,
					}
					if isH2 {
						tlsOpts.NextProtos = []string{"h2"}
					}
					return vmess.StreamTLSConn(ctx, raw, &tlsOpts)
				},
				nil,
				[]string{"h2"},
				15*time.Second,
			)
		}
	}

	cfg := &xhttp.Config{
		Host: sni,
		Path: path,
		Mode: mode,
	}
	if makeDownloadTransport != nil {
		cfg.DownloadConfig = &xhttp.Config{
			Host: downloadSNI,
			Path: path,
			Mode: mode,
		}
	}

	client, err := xhttp.NewClient(cfg, makeUploadTransport, makeDownloadTransport, realityConfig != nil)
	if err != nil {
		fatal("创建 Client 失败", err)
	}

	fmt.Println("\n[4/6] 建立 xhttp 连接...")
	xConn, err := client.Dial(context.Background())
	if err != nil {
		fatal("xhttp 连接建立失败", err)
	}
	defer xConn.Close()
	fmt.Println("  ✅ xhttp 连接建立成功")

	// 异步消费管道数据以避免死锁
	dr, dw := io.Pipe()
	tee := io.TeeReader(xConn, dw)
	go func() {
		buf := make([]byte, 4096)
		for {
			_, err := dr.Read(buf)
			if err != nil {
				return
			}
		}
	}()
	dConn := &debugConn{xConn, tee}

	fmt.Println("\n[5/6] 模拟真正的 VLESS 业务握手...")
	vClient, err := vless.NewClient(uuidStr, nil)
	if err != nil {
		fatal("创建 VLESS Client 失败", err)
	}

	domain := "httpbin.org"
	dst := &vless.DstAddr{
		UDP:      false,
		AddrType: vless.AtypDomainName,
		Addr:     append([]byte{byte(len(domain))}, []byte(domain)...),
		Port:     80,
	}

	conn, err := vClient.StreamConn(dConn, dst)
	if err != nil {
		fatal("VLESS 协议层协商失败", err)
	}

	fmt.Println("  [业务] 正在发送 GET /ip...")
	_, err = conn.Write([]byte("GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"))
	if err != nil {
		fatal("写入业务数据失败", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	resBuf := make([]byte, 8192)
	n, err := conn.Read(resBuf)
	if err != nil && err != io.EOF {
		fmt.Printf("  ⚠️ 业务层读取异常: %v\n", err)
	}

	fmt.Printf("\n  ✅ 端到端结果 (%d 字节):\n", n)
	if n > 0 {
		fmt.Printf("----------------------------------------\n%s\n----------------------------------------\n", string(resBuf[:n]))
	}

	fmt.Println("\n========================================")
	fmt.Println("  测试完成")
	fmt.Println("========================================")
}

func fatal(msg string, err error) {
	fmt.Printf("  ❌ %s: %v\n", msg, err)
	os.Exit(1)
}

func parseRealityConfig(pubKeyBase64, shortIDHex string) (*tlsC.RealityConfig, error) {
	if pubKeyBase64 == "" {
		return nil, nil
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		return nil, err
	}
	config := new(tlsC.RealityConfig)
	config.PublicKey, err = ecdh.X25519().NewPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	if shortIDHex != "" {
		_, _ = hex.Decode(config.ShortID[:], []byte(shortIDHex))
	}
	return config, nil
}
