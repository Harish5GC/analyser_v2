package main

import "testing"

// §11 — heartbeat detection (types 1 and 2) is used only to FLAG, never to drop.
func TestIsPFCPHeartbeat(t *testing.T) {
	cases := []struct {
		msgType string
		want    bool
	}{
		{"1", true}, // Heartbeat Request
		{"2", true}, // Heartbeat Response
		{"50", false},
		{"52", false},
		{"56", false},
	}
	for _, c := range cases {
		layer := map[string]interface{}{"pfcp.msg_type": c.msgType}
		if got := isPFCPHeartbeat(layer); got != c.want {
			t.Errorf("msg_type %s: isPFCPHeartbeat = %v, want %v", c.msgType, got, c.want)
		}
	}
}

func TestIsPFCPHeartbeatNested(t *testing.T) {
	layer := map[string]interface{}{
		"pfcp.flags": "0x21",
		"pfcp.header": map[string]interface{}{
			"pfcp.msg_type": "1",
		},
	}
	if !isPFCPHeartbeat(layer) {
		t.Fatal("expected nested heartbeat detection")
	}
}

func TestIsPFCPHeartbeatNil(t *testing.T) {
	if isPFCPHeartbeat(nil) {
		t.Fatal("nil layer must not be a heartbeat")
	}
}
