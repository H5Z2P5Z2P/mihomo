package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	configPkg "github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
)

var (
	configPath  = flag.String("config", "", "Path to the mihomo config file")
	homeDir     = flag.String("home-dir", "", "Optional mihomo home directory override")
	targetURL   = flag.String("url", "http://httpbin.org/ip", "URL to fetch through the local proxy")
	timeout     = flag.Duration("timeout", 30*time.Second, "End-to-end request timeout")
	expect      = flag.String("expect", "", "Optional substring expected in the response body")
	showHeaders = flag.Bool("headers", false, "Print response headers")
)

func init() {
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "Usage: go run ./tools/real-config-check -config /path/to/config.yaml [flags]\n\n")
		flag.PrintDefaults()
	}
}

func main() {
	flag.Parse()

	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "real-config-check failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if *configPath == "" {
		flag.Usage()
		return errors.New("missing -config")
	}

	configFile, err := filepath.Abs(*configPath)
	if err != nil {
		return fmt.Errorf("resolve config path: %w", err)
	}

	runHomeDir := *homeDir
	if runHomeDir == "" {
		runHomeDir = filepath.Dir(configFile)
	}
	runHomeDir, err = filepath.Abs(runHomeDir)
	if err != nil {
		return fmt.Errorf("resolve home dir: %w", err)
	}

	C.SetHomeDir(runHomeDir)
	C.SetConfig(configFile)
	if err := configPkg.Init(C.Path.HomeDir()); err != nil {
		return fmt.Errorf("init config dir: %w", err)
	}

	cfg, err := executor.ParseWithPath(configFile)
	if err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	executor.ApplyConfig(cfg, true)
	defer executor.Shutdown()

	client, proxyKind, proxyAddr, err := newHTTPClient(cfg, *timeout)
	if err != nil {
		return err
	}

	if err := waitForProxy(proxyAddr, minDuration(*timeout, 10*time.Second)); err != nil {
		return fmt.Errorf("wait for %s listener %s: %w", proxyKind, proxyAddr, err)
	}

	fmt.Printf("config: %s\n", configFile)
	fmt.Printf("home-dir: %s\n", runHomeDir)
	fmt.Printf("proxy: %s (%s)\n", proxyAddr, proxyKind)
	fmt.Printf("target: %s\n", *targetURL)

	reqCtx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, *targetURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	fmt.Printf("status: %s\n", resp.Status)
	if *showHeaders {
		printHeaders(resp.Header)
	}
	fmt.Printf("body:\n%s\n", body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected response status: %s", resp.Status)
	}
	if *expect != "" && !strings.Contains(string(body), *expect) {
		return fmt.Errorf("response body does not contain %q", *expect)
	}

	return nil
}

func newHTTPClient(cfg *configPkg.Config, timeout time.Duration) (*http.Client, string, string, error) {
	host := localProxyHost(cfg.General.BindAddress)

	if cfg.General.MixedPort != 0 {
		addr := net.JoinHostPort(host, strconv.Itoa(cfg.General.MixedPort))
		return &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: addr}),
			},
		}, "mixed-port", addr, nil
	}

	if cfg.General.Port != 0 {
		addr := net.JoinHostPort(host, strconv.Itoa(cfg.General.Port))
		return &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: addr}),
			},
		}, "port", addr, nil
	}

	if cfg.General.SocksPort != 0 {
		addr := net.JoinHostPort(host, strconv.Itoa(cfg.General.SocksPort))
		dialer, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
		if err != nil {
			return nil, "", "", fmt.Errorf("build socks5 dialer: %w", err)
		}
		return &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
					return dialer.Dial(network, address)
				},
			},
		}, "socks-port", addr, nil
	}

	return nil, "", "", errors.New("config does not expose mixed-port, port, or socks-port")
}

func localProxyHost(bindAddress string) string {
	switch bindAddress {
	case "", "*", "0.0.0.0":
		return "127.0.0.1"
	case "::":
		return "::1"
	default:
		return bindAddress
	}
}

func waitForProxy(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func printHeaders(header http.Header) {
	keys := make([]string, 0, len(header))
	for key := range header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Printf("%s: %s\n", key, strings.Join(header.Values(key), ", "))
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
