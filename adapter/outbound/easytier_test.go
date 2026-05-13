package outbound

import (
	"reflect"
	"testing"
	"time"
)

func TestEasyTierCommandArgs(t *testing.T) {
	option := EasyTierOption{
		Binary:        "/usr/local/bin/easytier-core",
		Peer:          "tcp://op.uily.de:23980",
		IPv4:          "192.88.99.3",
		NetworkName:   "boom",
		NetworkSecret: "luncheon-splendid-tinsmith-reformat-engraving-spending",
		NoListener:    true,
		ManualRoutes:  []string{"192.168.50.1/32"},
	}

	want := []string{
		"-p", "tcp://op.uily.de:23980",
		"--ipv4", "192.88.99.3",
		"--network-name", "boom",
		"--network-secret", "luncheon-splendid-tinsmith-reformat-engraving-spending",
		"--no-listener",
		"--manual-routes", "192.168.50.1/32",
	}
	if got := option.commandArgs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected easytier args:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestEasyTierOptionDefaults(t *testing.T) {
	option := EasyTierOption{}
	if got := option.binary(); got != defaultEasyTierBinary {
		t.Fatalf("unexpected default binary: %s", got)
	}
	if got := option.startWait(); got != defaultEasyTierStartWaitMS*time.Millisecond {
		t.Fatalf("unexpected default start wait: %s", got)
	}
	if !option.autoStart() {
		t.Fatal("easytier should auto-start by default")
	}

	noAutoStart := false
	option.AutoStart = &noAutoStart
	if option.autoStart() {
		t.Fatal("easytier should honor auto-start=false")
	}
}

func TestEasyTierPeerListMergesPeerAndPeers(t *testing.T) {
	option := EasyTierOption{
		Peer:  " tcp://one.example:11010 ",
		Peers: []string{"", "tcp://two.example:11010"},
	}
	want := []string{"tcp://one.example:11010", "tcp://two.example:11010"}
	if got := option.peerList(); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected peer list: got %#v want %#v", got, want)
	}
}

func TestEasyTierArgsForLogRedactsSecret(t *testing.T) {
	args := []string{"-p", "tcp://example.com:11010", "--network-secret", "secret-value", "--network-secret=second"}
	want := "-p tcp://example.com:11010 --network-secret <redacted> --network-secret=<redacted>"
	if got := easyTierArgsForLog(args); got != want {
		t.Fatalf("unexpected masked args: got %q want %q", got, want)
	}
	if args[3] != "secret-value" {
		t.Fatal("easyTierArgsForLog should not mutate input args")
	}
}
