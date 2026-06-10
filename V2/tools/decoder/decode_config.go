package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// DecodeConfig holds the fully validated parameters for the decode command.
type DecodeConfig struct {
	AnalysisID          string
	PCAPPath            string // absolute path to the retained source capture
	OutputDir           string // absolute path to <run>/decoder/
	RunRoot             string // absolute path to <run>/
	StagingDir          string // absolute path to <run>/staging/T01-<uuid>/
	SourceSHA256        string // sha256 of the PCAP, computed before any protocol work
	Protocols           map[string]bool
	RetainRaw           bool
	PacketAccessIndex   bool
	Parallel            bool
	TsharkPath          string
	EnabledCapabilities []string
	PolicyVersions      map[string]string
}

// parseDecodeArgs parses the argv after "decode" and builds a DecodeConfig.
// Returns an *exitCodeError with code 2 for invalid arguments.
func parseDecodeArgs(args []string) (*DecodeConfig, error) {
	fs := flag.NewFlagSet("decode", flag.ContinueOnError)

	var (
		analysisID      = fs.String("analysis-id", "", "analysis UUID (required)")
		outputDir       = fs.String("output-dir", "", "decoder output directory (required)")
		format          = fs.String("format", "v2", "output format (v2 only)")
		retainRaw       = fs.Bool("retain-raw", true, "retain raw tshark packet records")
		packetAccessIdx = fs.Bool("packet-access-index", false, "build T20 packet-access index")
		parallel        = fs.Bool("parallel", true, "run protocol decoders concurrently")
		tsharkPath      = fs.String("tshark", "", "path to tshark binary")
		protocolFlag    multiFlag
		capabilities    multiFlag
		policyVersions  keyValueFlag
	)
	fs.Var(&protocolFlag, "protocol", "protocol filter: all|http2|ngap|pfcp (repeatable)")
	fs.Var(&capabilities, "capability", "enabled capability name (repeatable)")
	fs.Var(&policyVersions, "policy-version", "policy version key=value (repeatable)")

	// Go's flag package stops at the first non-flag argument, so if the PCAP
	// path is passed before any flags we extract it first, then parse the rest.
	var pcapPath string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		pcapPath = args[0]
		args = args[1:]
	}

	if err := fs.Parse(args); err != nil {
		return nil, &exitCodeError{code: 2, msg: "argument error: " + err.Error()}
	}

	if *format != "v2" {
		return nil, &exitCodeError{code: 2, msg: "--format must be v2"}
	}

	// If PCAP was not positional, look in remaining non-flag args.
	if pcapPath == "" {
		remaining := fs.Args()
		if len(remaining) == 0 {
			return nil, &exitCodeError{code: 2, msg: "missing PCAP argument"}
		}
		pcapPath = remaining[0]
	}

	if *analysisID == "" {
		return nil, &exitCodeError{code: 2, msg: "--analysis-id is required"}
	}
	if *outputDir == "" {
		return nil, &exitCodeError{code: 2, msg: "--output-dir is required"}
	}

	// Resolve absolute paths.
	absOutputDir, err := filepath.Abs(*outputDir)
	if err != nil {
		return nil, &exitCodeError{code: 2, msg: "invalid --output-dir: " + err.Error()}
	}
	absPCAP, err := filepath.Abs(pcapPath)
	if err != nil {
		return nil, &exitCodeError{code: 2, msg: "invalid PCAP path: " + err.Error()}
	}

	// runRoot is the parent of decoder/
	runRoot := filepath.Dir(absOutputDir)

	// Build protocol set
	protocols := map[string]bool{}
	for _, p := range protocolFlag {
		switch strings.ToLower(p) {
		case "all":
			protocols["http2"] = true
			protocols["ngap"] = true
			protocols["pfcp"] = true
		case "http2", "ngap", "pfcp":
			protocols[strings.ToLower(p)] = true
		default:
			return nil, &exitCodeError{code: 2, msg: "unknown protocol: " + p}
		}
	}
	if len(protocols) == 0 {
		// default: all protocols
		protocols["http2"] = true
		protocols["ngap"] = true
		protocols["pfcp"] = true
	}
	if policyVersions == nil {
		policyVersions = keyValueFlag{}
	}

	// Mint a staging UUID (fresh per run; not the analysis-id so it's per-invocation).
	stagingUUID, err := newUUIDv4()
	if err != nil {
		return nil, fmt.Errorf("generate staging UUID: %w", err)
	}

	cfg := &DecodeConfig{
		AnalysisID:          *analysisID,
		PCAPPath:            absPCAP,
		OutputDir:           absOutputDir,
		RunRoot:             runRoot,
		StagingDir:          filepath.Join(runRoot, "staging", "T01-"+stagingUUID),
		Protocols:           protocols,
		RetainRaw:           *retainRaw,
		PacketAccessIndex:   *packetAccessIdx,
		Parallel:            *parallel,
		TsharkPath:          *tsharkPath,
		PolicyVersions:      policyVersions,
		EnabledCapabilities: capabilities,
	}
	return cfg, nil
}

// validate performs all pre-flight checks. Each failure maps to a specific
// exit code documented in the spec §5.1.
func (c *DecodeConfig) validate() error {
	// PCAP must be readable (exit 3).
	if _, err := os.Stat(c.PCAPPath); errors.Is(err, os.ErrNotExist) {
		return &exitCodeError{code: 3, msg: "PCAP not found: " + c.PCAPPath}
	} else if err != nil {
		return &exitCodeError{code: 3, msg: "PCAP unreadable: " + err.Error()}
	}

	// decoder/ must not already contain a published manifest (exit 2 — re-runs
	// create a new run directory per LLD §25.2).
	manifestPath := filepath.Join(c.OutputDir, "decoder_manifest.json")
	if _, err := os.Stat(manifestPath); err == nil {
		return &exitCodeError{code: 2, msg: "output-dir already contains a published decoder_manifest.json; create a new run directory"}
	}

	// Reject absolute paths that escape the run root.
	if err := validateRunRelPath(c.RunRoot, c.OutputDir); err != nil {
		return &exitCodeError{code: 2, msg: "output-dir escapes run root: " + err.Error()}
	}

	return nil
}

// computeSourceSHA256 streams the PCAP file and computes its SHA-256. Must be
// called after validate() confirms the file is readable.
func (c *DecodeConfig) computeSourceSHA256() error {
	f, err := os.Open(c.PCAPPath)
	if err != nil {
		return &exitCodeError{code: 3, msg: "open PCAP: " + err.Error()}
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("hash PCAP: %w", err)
	}
	c.SourceSHA256 = hex.EncodeToString(h.Sum(nil))
	return nil
}

// validateRunRelPath checks that target resolves inside runRoot after symlink
// resolution, preventing path traversal (spec §7, §16).
func validateRunRelPath(runRoot, target string) error {
	cleanRoot := filepath.Clean(runRoot)
	cleanTarget := filepath.Clean(target)

	real, err := filepath.EvalSymlinks(cleanTarget)
	if err != nil {
		// If the path doesn't exist yet, just check the lexical prefix.
		real = cleanTarget
	}

	if !strings.HasPrefix(real+string(filepath.Separator), cleanRoot+string(filepath.Separator)) &&
		real != cleanRoot {
		return fmt.Errorf("%q is outside %q", real, cleanRoot)
	}
	return nil
}

// validateDecoderRelPath rejects a relative path that contains "..", is
// absolute, or resolves outside the decoder/ tree inside runRoot.
func validateDecoderRelPath(runRoot, relPath string) error {
	if filepath.IsAbs(relPath) {
		return fmt.Errorf("absolute path not allowed: %q", relPath)
	}
	if strings.Contains(relPath, "..") {
		return fmt.Errorf("path traversal not allowed: %q", relPath)
	}
	return nil
}

// ---------------------------------------------------------------------------
// multiFlag is a flag.Value that accumulates repeated --flag values.
// ---------------------------------------------------------------------------

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

type keyValueFlag map[string]string

func (k *keyValueFlag) String() string {
	if k == nil || *k == nil {
		return ""
	}
	var parts []string
	for key, value := range *k {
		parts = append(parts, key+"="+value)
	}
	return strings.Join(parts, ",")
}

func (k *keyValueFlag) Set(s string) error {
	key, value, ok := strings.Cut(s, "=")
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if !ok || key == "" || value == "" {
		return fmt.Errorf("policy-version must be key=value, got %q", s)
	}
	if *k == nil {
		*k = map[string]string{}
	}
	(*k)[key] = value
	return nil
}
