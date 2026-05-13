package outbound

import (
	"reflect"
	"testing"
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
		NetworkName:       "example-net",
		NetworkSecret:     "example-network-secret",
		ManualRoutes:      []string{"203.0.113.1/32"},
		DisableEncryption: true,
	}
	if got := option.peerList(); !reflect.DeepEqual(got, []string{"tcp://peer.example.com:11010"}) {
		t.Fatalf("unexpected peer list: %#v", got)
	}
}
