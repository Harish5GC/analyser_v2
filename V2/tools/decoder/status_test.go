package main

import "testing"

func run(name, status string) ProtocolRun {
	return ProtocolRun{Name: name, Result: ProtocolDecodeResult{Status: status}}
}

func TestOverallStatus(t *testing.T) {
	cases := []struct {
		name string
		runs []ProtocolRun
		want string
	}{
		{"all success", []ProtocolRun{run("a", "success"), run("b", "success")}, "success"},
		{"success+absent", []ProtocolRun{run("a", "success"), run("b", "absent")}, "success"},
		{"all absent", []ProtocolRun{run("a", "absent"), run("b", "absent")}, "success"},
		{"one failed one ok", []ProtocolRun{run("a", "failed"), run("b", "success")}, "partial"},
		{"all failed", []ProtocolRun{run("a", "failed"), run("b", "failed")}, "failed"},
		// M1 — a protocol-level partial must surface as overall partial.
		{"one partial", []ProtocolRun{run("a", "partial"), run("b", "success")}, "partial"},
		{"failed + partial", []ProtocolRun{run("a", "failed"), run("b", "partial")}, "partial"},
	}
	for _, c := range cases {
		if got := overallStatus(c.runs, false); got != c.want {
			t.Errorf("%s: overallStatus = %s, want %s", c.name, got, c.want)
		}
	}
}

func TestOverallStatusForcePartial(t *testing.T) {
	if got := overallStatus([]ProtocolRun{run("a", "success")}, true); got != "partial" {
		t.Fatalf("overallStatus forcePartial = %s, want partial", got)
	}
}
