package main

import "testing"

func sampleRuns() []ProtocolRun {
	rc := int64(3)
	return []ProtocolRun{
		{
			Name:   "pfcp",
			Result: ProtocolDecodeResult{Status: "success"},
			Artifacts: []ArtifactDescriptor{
				{RelativePath: "decoder/full/pfcp/messages.jsonl", SHA256: "aaa", RecordCount: &rc},
				{RelativePath: "decoder/full/pfcp/message_index.jsonl", SHA256: "bbb"},
			},
		},
		{
			Name:   "http2",
			Result: ProtocolDecodeResult{Status: "success"},
			Collections: []CollectionDescriptor{
				{RelativeDir: "decoder/full/http2/streams", MembersSHA256: "ccc"},
			},
		},
	}
}

func baseCfg() *DecodeConfig {
	return &DecodeConfig{
		AnalysisID:          "11111111-1111-4111-8111-111111111111",
		SourceSHA256:        "deadbeef",
		Protocols:           map[string]bool{"http2": true, "ngap": true, "pfcp": true},
		RetainRaw:           true,
		EnabledCapabilities: []string{"jsonl_run_store"},
		PolicyVersions:      map[string]string{"mask": "1"},
	}
}

// C1.3 + AC#14 — the revision must be reproducible for identical inputs.
func TestMintRevisionDeterministic(t *testing.T) {
	r1, err := mintRevision(baseCfg(), "TShark 4.4.9", sampleRuns())
	if err != nil {
		t.Fatal(err)
	}
	r2, err := mintRevision(baseCfg(), "TShark 4.4.9", sampleRuns())
	if err != nil {
		t.Fatal(err)
	}
	if r1 != r2 {
		t.Fatalf("revision not deterministic: %s vs %s", r1, r2)
	}
}

// C1.3 — analysis_id must NOT influence the revision (spec §7 omits it).
func TestMintRevisionIndependentOfAnalysisID(t *testing.T) {
	c1 := baseCfg()
	c2 := baseCfg()
	c2.AnalysisID = "99999999-9999-4999-8999-999999999999"
	r1, _ := mintRevision(c1, "TShark 4.4.9", sampleRuns())
	r2, _ := mintRevision(c2, "TShark 4.4.9", sampleRuns())
	if r1 != r2 {
		t.Fatalf("revision changed with analysis_id: %s vs %s", r1, r2)
	}
}

// Sanity: revision MUST change when a real input (source checksum) changes.
func TestMintRevisionChangesWithSource(t *testing.T) {
	c1 := baseCfg()
	c2 := baseCfg()
	c2.SourceSHA256 = "feedface"
	r1, _ := mintRevision(c1, "TShark 4.4.9", sampleRuns())
	r2, _ := mintRevision(c2, "TShark 4.4.9", sampleRuns())
	if r1 == r2 {
		t.Fatal("revision unchanged despite different source checksum")
	}
}

func TestMintRevisionChangesWithPacketAccessIndexOption(t *testing.T) {
	c1 := baseCfg()
	c2 := baseCfg()
	c2.PacketAccessIndex = true
	r1, _ := mintRevision(c1, "TShark 4.4.9", sampleRuns())
	r2, _ := mintRevision(c2, "TShark 4.4.9", sampleRuns())
	if r1 == r2 {
		t.Fatal("revision unchanged despite different packet-access-index option")
	}
}

// Artifact ordering must not affect the revision (checksums are sorted).
func TestMintRevisionOrderIndependent(t *testing.T) {
	runs := sampleRuns()
	reversed := []ProtocolRun{runs[1], runs[0]}
	r1, _ := mintRevision(baseCfg(), "TShark 4.4.9", runs)
	r2, _ := mintRevision(baseCfg(), "TShark 4.4.9", reversed)
	if r1 != r2 {
		t.Fatalf("revision depends on run order: %s vs %s", r1, r2)
	}
}

// The revision must carry the sha256: prefix.
func TestMintRevisionPrefix(t *testing.T) {
	r, _ := mintRevision(baseCfg(), "TShark 4.4.9", sampleRuns())
	if len(r) < 7 || r[:7] != "sha256:" {
		t.Fatalf("revision missing sha256: prefix: %s", r)
	}
}
