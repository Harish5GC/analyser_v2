package main

import (
	"strings"
	"testing"
)

// M3 — a panicking decoder must be converted into a "failed" ProtocolRun
// rather than crashing the whole process.
func TestSafeDecodeRecoversPanic(t *testing.T) {
	run := safeDecode("http2", func() ProtocolRun {
		panic("boom: nil map")
	})
	if run.Name != "http2" {
		t.Fatalf("name = %q", run.Name)
	}
	if run.Result.Status != "failed" {
		t.Fatalf("status = %q, want failed", run.Result.Status)
	}
	if run.Err == nil {
		t.Fatal("expected non-nil Err after panic")
	}
	if len(run.Result.Warnings) == 0 || !strings.Contains(run.Result.Warnings[0].Code, "PANIC") {
		t.Fatalf("expected a PANIC warning, got %+v", run.Result.Warnings)
	}
}

// The happy path must pass results through unchanged.
func TestSafeDecodePassesThrough(t *testing.T) {
	want := ProtocolRun{Name: "pfcp", Result: ProtocolDecodeResult{Status: "success", RecordsWritten: 5}}
	got := safeDecode("pfcp", func() ProtocolRun { return want })
	if got.Result.Status != "success" || got.Result.RecordsWritten != 5 {
		t.Fatalf("pass-through altered result: %+v", got)
	}
}
