package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Manifest types — mirror the JSON schema in spec §13.
// ---------------------------------------------------------------------------

// DecodeWarning is the T01-scoped alias of the shared Issue model (LLD §26).
type DecodeWarning struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Stage    string `json:"stage"`
	Message  string `json:"message"`
}

func warnT01(code, msg string) DecodeWarning {
	return DecodeWarning{
		Code:     "T01_" + strings.ToUpper(code),
		Severity: "warning",
		Stage:    "T01",
		Message:  msg,
	}
}

// ProtocolDecodeResult is embedded in the manifest for each protocol.
type ProtocolDecodeResult struct {
	Status            string          `json:"status"`
	InputPackets      int64           `json:"input_packets"`
	RecordsWritten    int64           `json:"records_written"`
	IncompleteRecords int64           `json:"incomplete_records,omitempty"`
	ElapsedMS         int64           `json:"elapsed_ms"`
	Warnings          []DecodeWarning `json:"warnings"`
}

// DecoderInfo carries binary and tshark version metadata.
type DecoderInfo struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	GoVersion     string `json:"go_version"`
	TsharkVersion string `json:"tshark_version"`
}

// DecoderManifest is the authoritative Go result written last to decoder/.
type DecoderManifest struct {
	SchemaVersion       string                          `json:"schema_version"`
	AnalysisID          string                          `json:"analysis_id"`
	Status              string                          `json:"status"`
	Revision            string                          `json:"revision"`
	EnabledCapabilities []string                        `json:"enabled_capabilities"`
	PolicyVersions      map[string]string               `json:"policy_versions"`
	Decoder             DecoderInfo                     `json:"decoder"`
	Source              ArtifactDescriptor              `json:"source"`
	Protocols           map[string]ProtocolDecodeResult `json:"protocols"`
	Artifacts           []ArtifactDescriptor            `json:"artifacts"`
	Collections         []CollectionDescriptor          `json:"collections"`
	Warnings            []DecodeWarning                 `json:"warnings"`
	StartedAt           string                          `json:"started_at"`
	CompletedAt         string                          `json:"completed_at"`
	ElapsedMS           int64                           `json:"elapsed_ms"`
}

// ---------------------------------------------------------------------------
// ProtocolRun carries everything a protocol decoder returns to the orchestrator.
// ---------------------------------------------------------------------------

type ProtocolRun struct {
	Name        string
	Result      ProtocolDecodeResult
	Artifacts   []ArtifactDescriptor
	Collections []CollectionDescriptor
	Err         error // fatal decode error (non-nil → status "failed")
}

// ---------------------------------------------------------------------------
// Revision minting — spec §7, LLD §25
// ---------------------------------------------------------------------------

// revisionEnvelopeInput is the ordered, canonical input to the revision hash.
// Fields match LLD §25.1 (minus the revision field itself).
// NOTE: analysis_id is deliberately NOT part of the revision. Spec §7 lists the
// revision inputs (source, options, capabilities, versions, policy, artifact /
// collection descriptors) and analysis_id is not among them; it is unique per
// run, so including it would break AC#14 (identical inputs → identical revision).
type revisionEnvelopeInput struct {
	Tool              string            `json:"tool"`
	ToolVersion       string            `json:"tool_version"`
	SchemaVersion     string            `json:"schema_version"`
	SourceSHA256      string            `json:"source_sha256"`
	Protocols         []string          `json:"protocols"`
	RetainRaw         bool              `json:"retain_raw"`
	PacketAccessIndex bool              `json:"packet_access_index"`
	Capabilities      []string          `json:"enabled_capabilities"`
	PolicyVersions    map[string]string `json:"policy_versions"`
	TsharkVersion     string            `json:"tshark_version"`
	Artifacts         []string          `json:"artifact_checksums"`
	Collections       []string          `json:"collection_checksums"`
}

// mintRevision computes the T01 revision over the set of known inputs and
// published artifact checksums. Canonical JSON uses sorted map keys (Go's
// json.Marshal guarantees this for maps) and stable slice order (callers must
// pre-sort slices before calling).
func mintRevision(cfg *DecodeConfig, tsharkVersion string, runs []ProtocolRun) (string, error) {
	// Build ordered protocol list and artifact/collection checksum lists.
	var protos []string
	for _, p := range []string{"http2", "ngap", "pfcp"} {
		if cfg.Protocols[p] {
			protos = append(protos, p)
		}
	}

	var artifactChecksums []string
	var collectionChecksums []string
	for _, run := range runs {
		for _, a := range run.Artifacts {
			artifactChecksums = append(artifactChecksums, a.SHA256)
		}
		for _, c := range run.Collections {
			collectionChecksums = append(collectionChecksums, c.MembersSHA256)
		}
	}
	sort.Strings(artifactChecksums)
	sort.Strings(collectionChecksums)

	caps := make([]string, len(cfg.EnabledCapabilities))
	copy(caps, cfg.EnabledCapabilities)
	sort.Strings(caps)

	env := revisionEnvelopeInput{
		Tool:              DecoderName,
		ToolVersion:       DecoderVersion,
		SchemaVersion:     SchemaVersion,
		SourceSHA256:      cfg.SourceSHA256,
		Protocols:         protos,
		RetainRaw:         cfg.RetainRaw,
		PacketAccessIndex: cfg.PacketAccessIndex,
		Capabilities:      caps,
		PolicyVersions:    cfg.PolicyVersions,
		TsharkVersion:     tsharkVersion,
		Artifacts:         artifactChecksums,
		Collections:       collectionChecksums,
	}

	// canonical JSON: json.Marshal on a struct with sorted-string maps → deterministic.
	raw, err := json.Marshal(env)
	if err != nil {
		return "", fmt.Errorf("revision serialisation: %w", err)
	}
	// Re-round-trip to guarantee map key sorting (the struct already is sorted
	// by field order, but PolicyVersions is a map).
	var canonical interface{}
	if err := json.Unmarshal(raw, &canonical); err != nil {
		return "", err
	}
	canonBytes, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(canonBytes)
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// ---------------------------------------------------------------------------
// Manifest publication — always written last (spec §7, §13).
// ---------------------------------------------------------------------------

// writeManifest assembles the manifest, mints the revision, and publishes it
// atomically as the very last file in decoder/. Returns the manifest revision.
func writeManifest(
	cfg *DecodeConfig,
	sink *ArtifactSink,
	tsharkVersion string,
	sourceDesc ArtifactDescriptor,
	runs []ProtocolRun,
	manifestWarnings []DecodeWarning,
	startedAt time.Time,
	completedAt time.Time,
) (string, error) {
	revision, err := mintRevision(cfg, tsharkVersion, runs)
	if err != nil {
		return "", err
	}

	// Assemble protocol result map.
	protocols := make(map[string]ProtocolDecodeResult)
	for _, run := range runs {
		protocols[run.Name] = run.Result
	}
	// Mark not-requested protocols.
	for _, p := range []string{"http2", "ngap", "pfcp"} {
		if _, requested := cfg.Protocols[p]; !requested {
			protocols[p] = ProtocolDecodeResult{Status: "not_requested", Warnings: []DecodeWarning{}}
		}
	}

	// Flatten artifacts and collections. Sort by relative path so the manifest
	// descriptor content is byte-stable regardless of goroutine completion order
	// (spec §13 stable list order, AC#14).
	var allArtifacts []ArtifactDescriptor
	var allCollections []CollectionDescriptor
	for _, run := range runs {
		allArtifacts = append(allArtifacts, run.Artifacts...)
		allCollections = append(allCollections, run.Collections...)
	}
	sort.Slice(allArtifacts, func(i, j int) bool {
		return allArtifacts[i].RelativePath < allArtifacts[j].RelativePath
	})
	sort.Slice(allCollections, func(i, j int) bool {
		return allCollections[i].RelativeDir < allCollections[j].RelativeDir
	})

	elapsedMS := completedAt.Sub(startedAt).Milliseconds()

	manifest := DecoderManifest{
		SchemaVersion:       SchemaVersion,
		AnalysisID:          cfg.AnalysisID,
		Status:              overallStatus(runs, len(manifestWarnings) > 0),
		Revision:            revision,
		EnabledCapabilities: cfg.EnabledCapabilities,
		PolicyVersions:      cfg.PolicyVersions,
		Decoder: DecoderInfo{
			Name:          DecoderName,
			Version:       DecoderVersion,
			GoVersion:     goVersion(),
			TsharkVersion: tsharkVersion,
		},
		Source:      sourceDesc,
		Protocols:   protocols,
		Artifacts:   allArtifacts,
		Collections: allCollections,
		Warnings:    manifestWarnings,
		StartedAt:   startedAt.UTC().Format(time.RFC3339Nano),
		CompletedAt: completedAt.UTC().Format(time.RFC3339Nano),
		ElapsedMS:   elapsedMS,
	}
	if manifest.EnabledCapabilities == nil {
		manifest.EnabledCapabilities = []string{}
	}
	if manifest.Artifacts == nil {
		manifest.Artifacts = []ArtifactDescriptor{}
	}
	if manifest.Collections == nil {
		manifest.Collections = []CollectionDescriptor{}
	}
	if manifest.Warnings == nil {
		manifest.Warnings = []DecodeWarning{}
	}

	// Write to staging then publish last (spec §7 "publish manifest last").
	stgPath := filepath.Join(sink.stagingDir, "decoder_manifest.json.tmp")
	if err := os.MkdirAll(filepath.Dir(stgPath), 0750); err != nil {
		return "", err
	}
	f, err := os.OpenFile(stgPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		return "", &exitCodeError{code: 5, msg: "create manifest staging: " + err.Error()}
	}
	bw := bufio.NewWriter(f)
	enc := json.NewEncoder(bw)
	enc.SetIndent("", "  ")
	if err := enc.Encode(manifest); err != nil {
		f.Close()
		os.Remove(stgPath)
		return "", &exitCodeError{code: 5, msg: "encode manifest: " + err.Error()}
	}
	if err := bw.Flush(); err != nil {
		f.Close()
		os.Remove(stgPath)
		return "", &exitCodeError{code: 5, msg: "flush manifest: " + err.Error()}
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(stgPath)
		return "", &exitCodeError{code: 5, msg: "sync manifest: " + err.Error()}
	}
	f.Close()

	finalStg := strings.TrimSuffix(stgPath, ".tmp")
	if err := os.Rename(stgPath, finalStg); err != nil {
		return "", &exitCodeError{code: 5, msg: "rename manifest staging: " + err.Error()}
	}
	// Publish manifest last.
	dst := filepath.Join(sink.decoderDir, "decoder_manifest.json")
	if err := os.MkdirAll(filepath.Dir(dst), 0750); err != nil {
		return "", &exitCodeError{code: 5, msg: "mkdir decoder: " + err.Error()}
	}
	if err := os.Rename(finalStg, dst); err != nil {
		return "", &exitCodeError{code: 5, msg: "publish manifest: " + err.Error()}
	}
	return revision, nil
}

// overallStatus derives the manifest-level status from all protocol runs.
// Spec §14: all-fail → "failed"; any failure or any recoverable-partial → "partial";
// else "success". A protocol with status "partial" (recoverable errors during
// decode/publication) must surface as overall "partial", not be hidden as success.
func overallStatus(runs []ProtocolRun, forcePartial bool) string {
	successes := 0
	failures := 0
	partials := 0
	for _, r := range runs {
		switch r.Result.Status {
		case "success", "absent":
			successes++
		case "failed":
			failures++
		case "partial":
			partials++
		}
	}
	if failures > 0 && successes == 0 && partials == 0 {
		return "failed"
	}
	if failures > 0 || partials > 0 || forcePartial {
		return "partial"
	}
	return "success"
}

// sourceArtifactDescriptor builds an ArtifactDescriptor for the retained PCAP.
func sourceArtifactDescriptor(cfg *DecodeConfig) (ArtifactDescriptor, error) {
	fi, err := os.Stat(cfg.PCAPPath)
	if err != nil {
		return ArtifactDescriptor{}, err
	}
	return ArtifactDescriptor{
		ArtifactID:          deterministicUUID(cfg.SourceSHA256, "artifact", "source/capture.pcap"),
		RelativePath:        "source/capture.pcap",
		ArtifactType:        "pcap",
		MediaType:           "application/vnd.tcpdump.pcap",
		FormatSchemaVersion: "1.0",
		SHA256:              cfg.SourceSHA256,
		ByteSize:            fi.Size(),
		CreationStage:       "T01",
	}, nil
}
