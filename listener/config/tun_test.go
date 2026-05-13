package config

import "testing"

func TestParseICMPRoutingMode(t *testing.T) {
	tests := []struct {
		name    string
		input   ICMPRoutingMode
		want    ICMPRoutingMode
		wantErr bool
	}{
		{name: "default", input: "", want: ICMPRoutingModeProxy},
		{name: "proxy", input: "proxy", want: ICMPRoutingModeProxy},
		{name: "case insensitive", input: "EasyTier", want: ICMPRoutingModeEasyTier},
		{name: "direct", input: "direct", want: ICMPRoutingModeDirect},
		{name: "invalid", input: "drop", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseICMPRoutingMode(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected invalid ICMP routing mode to fail")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("unexpected ICMP routing mode: got %q want %q", got, tt.want)
			}
		})
	}
}
