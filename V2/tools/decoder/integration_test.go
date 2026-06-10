package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// testPCAP resolves the reference capture used for integration tests.
// Override with T01_TEST_PCAP; the test is skipped if neither exists.
func testPCAP() string {
	if p := os.Getenv("T01_TEST_PCAP"); p != "" {
		return p
	}
	return "/home/newuegnb/corevonr.pcap"
}

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "5g_call_it")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

func sha256OfFile(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// checksumTree returns a map of decoder-relative path -> sha256 for every file
// under decoder/, excluding decoder_manifest.json (whose timestamps legitimately
// vary between runs).
func checksumTree(t *testing.T, decoderDir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(decoderDir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || strings.HasSuffix(p, "decoder_manifest.json") {
			return nil
		}
		rel, _ := filepath.Rel(decoderDir, p)
		out[rel] = sha256OfFile(t, p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func runDecodeBinary(t *testing.T, bin, pcap, analysisID string) (string, *DecoderManifest) {
	t.Helper()
	runDir := t.TempDir()
	decoderDir := filepath.Join(runDir, "decoder")
	cmd := exec.Command(bin, "decode", pcap,
		"--analysis-id", analysisID,
		"--output-dir", decoderDir)
	cmd.Stderr = nil
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("decode failed (%s): %v\n%s", analysisID, err, out)
	}
	raw, err := os.ReadFile(filepath.Join(decoderDir, "decoder_manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m DecoderManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return decoderDir, &m
}

// AC#14 — identical inputs (even with DIFFERENT analysis-ids) must yield
// byte-identical revisions, collection digests, and per-artifact checksums.
func TestDecodeDeterminismIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}
	pcap := testPCAP()
	if _, err := os.Stat(pcap); err != nil {
		t.Skipf("reference pcap not available (%s); set T01_TEST_PCAP", pcap)
	}
	if _, err := exec.LookPath("tshark"); err != nil {
		t.Skip("tshark not available")
	}

	bin := buildBinary(t)

	dirA, mA := runDecodeBinary(t, bin, pcap, "11111111-1111-4111-8111-111111111111")
	dirB, mB := runDecodeBinary(t, bin, pcap, "22222222-2222-4222-8222-222222222222")

	if mA.Revision != mB.Revision {
		t.Fatalf("revision not deterministic across runs:\n  A=%s\n  B=%s", mA.Revision, mB.Revision)
	}
	if mA.Revision == "" {
		t.Fatal("empty revision")
	}

	// Collection digests must match.
	if len(mA.Collections) != len(mB.Collections) {
		t.Fatalf("collection count differs: %d vs %d", len(mA.Collections), len(mB.Collections))
	}
	for i := range mA.Collections {
		if mA.Collections[i].MembersSHA256 != mB.Collections[i].MembersSHA256 {
			t.Fatalf("collection %d members_sha256 differs:\n  A=%s\n  B=%s",
				i, mA.Collections[i].MembersSHA256, mB.Collections[i].MembersSHA256)
		}
	}

	// Every published artifact file must be byte-identical.
	csA := checksumTree(t, dirA)
	csB := checksumTree(t, dirB)
	if len(csA) != len(csB) {
		t.Fatalf("artifact file count differs: %d vs %d", len(csA), len(csB))
	}
	for rel, shaA := range csA {
		shaB, ok := csB[rel]
		if !ok {
			t.Errorf("artifact %s present in run A but not B", rel)
			continue
		}
		if shaA != shaB {
			t.Errorf("artifact %s not byte-identical:\n  A=%s\n  B=%s", rel, shaA, shaB)
		}
	}
}

// Heartbeats must survive into full PFCP output (spec §11) — guards against a
// regression that silently drops them.
func TestPFCPHeartbeatsRetainedIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}
	pcap := testPCAP()
	if _, err := os.Stat(pcap); err != nil {
		t.Skipf("reference pcap not available (%s)", pcap)
	}
	if _, err := exec.LookPath("tshark"); err != nil {
		t.Skip("tshark not available")
	}
	bin := buildBinary(t)
	dir, m := runDecodeBinary(t, bin, pcap, "33333333-3333-4333-8333-333333333333")

	if pr, ok := m.Protocols["pfcp"]; !ok || pr.Status == "absent" {
		t.Skip("no pfcp in reference capture")
	}

	msgs := filepath.Join(dir, "full", "pfcp", "messages.jsonl")
	raw, err := os.ReadFile(msgs)
	if err != nil {
		t.Fatal(err)
	}
	heartbeats := 0
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]interface{}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		if hb, _ := rec["is_heartbeat"].(bool); hb {
			heartbeats++
		}
	}
	if heartbeats == 0 {
		t.Error("expected at least one retained PFCP heartbeat record, found none")
	}
	t.Logf("retained %d heartbeat records", heartbeats)
}
