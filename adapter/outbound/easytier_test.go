package outbound

import (
	"encoding/json"
	"reflect"
	"testing"

	et "github.com/metacubex/mihomo/transport/easytier"
)

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

func TestEasyTierNativeOptionDoesNotExposeProcessFields(t *testing.T) {
	option := EasyTierOption{
		Peer:              "tcp://peer.example.com:11010",
		IPv4:              "198.51.100.11",
		Hostname:          "et-main",
		NetworkName:       "example-net",
		NetworkSecret:     "example-network-secret",
		ManualRoutes:      []string{"203.0.113.1/32"},
		LatencyFirst:      true,
		DisableEncryption: true,
	}
	if got := option.peerList(); !reflect.DeepEqual(got, []string{"tcp://peer.example.com:11010"}) {
		t.Fatalf("unexpected peer list: %#v", got)
	}
	if !option.LatencyFirst {
		t.Fatal("expected latency-first option to be preserved")
	}
	if option.Hostname != "et-main" {
		t.Fatalf("unexpected hostname option: %s", option.Hostname)
	}
}

func TestNewEasyTierPassesHostnameToClient(t *testing.T) {
	outbound, err := NewEasyTier(EasyTierOption{
		Name:     "et",
		Peer:     "tcp://peer.example.com:11010",
		IPv4:     "198.51.100.11",
		Hostname: "configured-host",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := outbound.DebugSnapshot().Hostname; got != "configured-host" {
		t.Fatalf("unexpected client hostname: %s", got)
	}
}

func TestEasyTierDebugSnapshotDelegatesToClient(t *testing.T) {
	outbound := &EasyTier{
		Base:   NewBase(BaseOption{Name: "et", Type: 0}),
		option: EasyTierOption{Name: "et", Peer: "tcp://peer.example.com:11010"},
		client: et.NewClient(et.Options{Peers: []string{"tcp://peer.example.com:11010"}}, nil),
	}
	snapshot := outbound.DebugSnapshot()
	if snapshot.MyPeerID != 0 {
		t.Fatalf("unexpected initial peer id: %#v", snapshot)
	}
}

func TestEasyTierMarshalJSONIncludesDebugSnapshot(t *testing.T) {
	outbound := &EasyTier{
		Base:   NewBase(BaseOption{Name: "et", Type: 0}),
		option: EasyTierOption{Name: "et", Peer: "tcp://peer.example.com:11010"},
		client: et.NewClient(et.Options{Peers: []string{"tcp://peer.example.com:11010"}}, nil),
	}
	body, err := outbound.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if _, ok := payload["debugSnapshot"]; !ok {
		t.Fatalf("expected debugSnapshot in marshal output: %s", string(body))
	}
	if _, ok := payload["option"]; !ok {
		t.Fatalf("expected option in marshal output: %s", string(body))
	}
}
