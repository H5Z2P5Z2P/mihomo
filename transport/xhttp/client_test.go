package xhttp

import (
	"reflect"
	"testing"
)

func TestNormalizeALPN(t *testing.T) {
	got := NormalizeALPN(nil)
	want := []string{"h2", "http/1.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NormalizeALPN(nil) = %v, want %v", got, want)
	}

	input := []string{"h3"}
	got = NormalizeALPN(input)
	if !reflect.DeepEqual(got, input) {
		t.Fatalf("NormalizeALPN(%v) = %v", input, got)
	}
	got[0] = "modified"
	if input[0] != "h3" {
		t.Fatal("NormalizeALPN should clone the input slice")
	}
}

func TestDecideHTTPVersion(t *testing.T) {
	tests := []struct {
		name       string
		hasTLS     bool
		nextProtos []string
		hasReality bool
		want       string
	}{
		{name: "default h2", hasTLS: true, nextProtos: NormalizeALPN(nil), want: HTTPVersion2},
		{name: "single h1", hasTLS: true, nextProtos: []string{"http/1.1"}, want: HTTPVersion11},
		{name: "single h3", hasTLS: true, nextProtos: []string{"h3"}, want: HTTPVersion3},
		{name: "reality forces h2", hasTLS: true, nextProtos: []string{"h3"}, hasReality: true, want: HTTPVersion2},
		{name: "plain http falls back h1", hasTLS: false, nextProtos: []string{"h3"}, want: HTTPVersion11},
		{name: "multi alpn keeps h2", hasTLS: true, nextProtos: []string{"h3", "h2"}, want: HTTPVersion2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DecideHTTPVersion(tt.hasTLS, tt.nextProtos, tt.hasReality); got != tt.want {
				t.Fatalf("DecideHTTPVersion(%v, %v, %v) = %s, want %s", tt.hasTLS, tt.nextProtos, tt.hasReality, got, tt.want)
			}
		})
	}
}

func TestRequestScheme(t *testing.T) {
	if got := (&Config{}).RequestScheme(); got != "https" {
		t.Fatalf("default request scheme = %q, want https", got)
	}
	if got := (&Config{Scheme: "http"}).RequestScheme(); got != "http" {
		t.Fatalf("custom request scheme = %q, want http", got)
	}
}
