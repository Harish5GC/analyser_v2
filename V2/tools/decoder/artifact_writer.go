package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ---------------------------------------------------------------------------
// Shared types matching LLD §23.2
// ---------------------------------------------------------------------------

// ArtifactDescriptor describes a single published artifact file.
type ArtifactDescriptor struct {
	ArtifactID          string `json:"artifact_id"`
	RelativePath        string `json:"relative_path"`
	ArtifactType        string `json:"artifact_type"`
	Protocol            string `json:"protocol,omitempty"`
	MediaType           string `json:"media_type"`
	FormatSchemaVersion string `json:"format_schema_version"`
	SHA256              string `json:"sha256"`
	ByteSize            int64  `json:"byte_size"`
	RecordCount         *int64 `json:"record_count,omitempty"`
	CreationStage       string `json:"creation_stage"`
	ParentSourceSHA256  string `json:"parent_source_sha256,omitempty"`
	Revision            string `json:"revision,omitempty"`
}

// CollectionMemberDescriptor describes one member of a collection (e.g. one
// HTTP/2 stream document).
type CollectionMemberDescriptor struct {
	RelativePath        string `json:"relative_path"`
	SHA256              string `json:"sha256"`
	ByteSize            int64  `json:"byte_size"`
	RecordCount         *int64 `json:"record_count,omitempty"`
	ArtifactType        string `json:"artifact_type"`
	MediaType           string `json:"media_type"`
	FormatSchemaVersion string `json:"format_schema_version"`
}

// CollectionDescriptor describes a set of related artifacts (e.g. all HTTP/2
// stream documents) and their shared index.
type CollectionDescriptor struct {
	CollectionID       string                       `json:"collection_id"`
	RelativeDir        string                       `json:"relative_dir"`
	ArtifactType       string                       `json:"artifact_type"`
	IndexArtifact      ArtifactDescriptor           `json:"index_artifact"`
	MemberCount        int                          `json:"member_count"`
	MembersSHA256      string                       `json:"members_sha256"`
	Members            []CollectionMemberDescriptor `json:"members"`
	ParentSourceSHA256 string                       `json:"parent_source_sha256,omitempty"`
	Revision           string                       `json:"revision,omitempty"`
}

// int64Ptr is a convenience helper.
func int64Ptr(n int64) *int64 { return &n }

// ---------------------------------------------------------------------------
// countWriter counts bytes that pass through it.
// ---------------------------------------------------------------------------

type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// ---------------------------------------------------------------------------
// ArtifactSink manages the staging directory and atomic publish to decoder/.
// All protocol decoders write through this to ensure manifest-last publication
// and checksum integrity (spec §7).
// ---------------------------------------------------------------------------

type ArtifactSink struct {
	stagingDir   string // <run>/staging/T01-<uuid>/
	runRoot      string // <run>/
	decoderDir   string // <run>/decoder/
	sourceSHA256 string
	mu           sync.Mutex
	published    []string
}

func newArtifactSink(runRoot, stagingDir, sourceSHA256 string) (*ArtifactSink, error) {
	decoderDir := filepath.Join(runRoot, "decoder")
	if err := os.MkdirAll(stagingDir, 0750); err != nil {
		return nil, fmt.Errorf("create staging dir: %w", err)
	}
	return &ArtifactSink{
		stagingDir:   stagingDir,
		runRoot:      runRoot,
		decoderDir:   decoderDir,
		sourceSHA256: sourceSHA256,
	}, nil
}

// cleanup removes the staging directory; called on cancellation so no partial
// files survive in staging (spec §7).
func (s *ArtifactSink) cleanup() {
	_ = os.RemoveAll(s.stagingDir)
}

// abortPublished removes files that this sink already promoted into decoder/.
// It is used on cancellation before decoder_manifest.json is published, so a
// timed-out run does not leave manifest-less evidence artifacts behind.
func (s *ArtifactSink) abortPublished() {
	s.mu.Lock()
	published := append([]string(nil), s.published...)
	s.published = nil
	s.mu.Unlock()

	for i := len(published) - 1; i >= 0; i-- {
		_ = os.Remove(published[i])
	}
	_ = os.RemoveAll(s.stagingDir)
	pruneEmptyDirs(s.decoderDir)
}

// stagingPath returns the absolute path inside staging for a decoder-relative path.
func (s *ArtifactSink) stagingPath(decoderRelPath string) string {
	return filepath.Join(s.stagingDir, filepath.FromSlash(decoderRelPath))
}

// finalPath returns the absolute path in decoder/ for a decoder-relative path.
func (s *ArtifactSink) finalPath(decoderRelPath string) string {
	return filepath.Join(s.decoderDir, filepath.FromSlash(decoderRelPath))
}

// runRelPath returns the path relative to runRoot, i.e. "decoder/<relPath>".
func runRelPath(decoderRelPath string) string {
	return "decoder/" + decoderRelPath
}

// artifactID derives a deterministic artifact identifier from the source
// checksum and the artifact's run-relative path (spec §7, AC#14).
func (s *ArtifactSink) artifactID(runRel string) string {
	return deterministicUUID(s.sourceSHA256, "artifact", runRel)
}

// publish atomically moves a staged file into the decoder/ tree.
func (s *ArtifactSink) publish(stagingAbs, decoderRelPath string) error {
	dst := s.finalPath(decoderRelPath)
	if err := os.MkdirAll(filepath.Dir(dst), 0750); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(dst), err)
	}
	if err := os.Rename(stagingAbs, dst); err != nil {
		return err
	}
	s.mu.Lock()
	s.published = append(s.published, dst)
	s.mu.Unlock()
	return nil
}

func pruneEmptyDirs(root string) {
	var dirs []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() || path == root {
			return nil
		}
		dirs = append(dirs, path)
		return nil
	})
	for i := len(dirs) - 1; i >= 0; i-- {
		_ = os.Remove(dirs[i])
	}
}

// ---------------------------------------------------------------------------
// JSONLSink: streaming JSONL writer that computes sha256 + byte count as
// records are written, and publishes atomically on Close.
// ---------------------------------------------------------------------------

// JSONLSink writes one JSON object per line to a staging temp file and
// promotes it to decoder/ atomically on Close.
type JSONLSink struct {
	sink         *ArtifactSink
	relPath      string // decoder-relative path (without leading "decoder/")
	tmpPath      string // full path to .tmp file in staging
	file         *os.File
	buf          *bufio.Writer
	hasher       hash.Hash
	counter      *countWriter
	records      int64
	artifactType string
	protocol     string
	mediaType    string
}

// openJSONL creates a new JSONL sink for the given decoder-relative path.
// The file is created in staging; call Close() to promote it.
func (s *ArtifactSink) openJSONL(decoderRelPath, artifactType, protocol, mediaType string) (*JSONLSink, error) {
	stgPath := s.stagingPath(decoderRelPath)
	if err := os.MkdirAll(filepath.Dir(stgPath), 0750); err != nil {
		return nil, fmt.Errorf("mkdir staging: %w", err)
	}
	tmpPath := stgPath + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	cw := &countWriter{}
	mw := io.MultiWriter(f, h, cw)
	return &JSONLSink{
		sink:         s,
		relPath:      decoderRelPath,
		tmpPath:      tmpPath,
		file:         f,
		buf:          bufio.NewWriterSize(mw, 64*1024),
		hasher:       h,
		counter:      cw,
		artifactType: artifactType,
		protocol:     protocol,
		mediaType:    mediaType,
	}, nil
}

// WriteRecord marshals v as compact JSON and writes it as one JSONL line.
func (j *JSONLSink) WriteRecord(v interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := j.buf.Write(b); err != nil {
		return err
	}
	if err := j.buf.WriteByte('\n'); err != nil {
		return err
	}
	j.records++
	return nil
}

// Close flushes, syncs, and atomically publishes the JSONL file to decoder/.
// Returns an ArtifactDescriptor describing the published file.
func (j *JSONLSink) Close() (ArtifactDescriptor, error) {
	if err := j.buf.Flush(); err != nil {
		j.file.Close()
		return ArtifactDescriptor{}, err
	}
	if err := j.file.Sync(); err != nil {
		j.file.Close()
		return ArtifactDescriptor{}, err
	}
	if err := j.file.Close(); err != nil {
		return ArtifactDescriptor{}, err
	}

	sha256hex := hex.EncodeToString(j.hasher.Sum(nil))
	byteSize := j.counter.n

	// atomic rename .tmp → staging final
	stagingFinal := strings.TrimSuffix(j.tmpPath, ".tmp")
	if err := os.Rename(j.tmpPath, stagingFinal); err != nil {
		return ArtifactDescriptor{}, err
	}
	j.tmpPath = stagingFinal

	// publish staging → decoder/
	if err := j.sink.publish(stagingFinal, j.relPath); err != nil {
		return ArtifactDescriptor{}, err
	}

	runRel := runRelPath(j.relPath)
	rc := j.records
	return ArtifactDescriptor{
		ArtifactID:          j.sink.artifactID(runRel),
		RelativePath:        runRel,
		ArtifactType:        j.artifactType,
		Protocol:            j.protocol,
		MediaType:           j.mediaType,
		FormatSchemaVersion: SchemaVersion,
		SHA256:              sha256hex,
		ByteSize:            byteSize,
		RecordCount:         &rc,
		CreationStage:       "T01",
		ParentSourceSHA256:  j.sink.sourceSHA256,
	}, nil
}

// ---------------------------------------------------------------------------
// WriteJSONDocument writes a single JSON document atomically to decoder/.
// ---------------------------------------------------------------------------

func (s *ArtifactSink) writeJSONDocument(
	decoderRelPath string,
	doc interface{},
	artifactType, protocol, mediaType string,
) (ArtifactDescriptor, error) {
	stgPath := s.stagingPath(decoderRelPath)
	if err := os.MkdirAll(filepath.Dir(stgPath), 0750); err != nil {
		return ArtifactDescriptor{}, fmt.Errorf("mkdir: %w", err)
	}
	tmpPath := stgPath + ".tmp"

	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		return ArtifactDescriptor{}, err
	}

	h := sha256.New()
	cw := &countWriter{}
	mw := io.MultiWriter(f, h, cw)
	bw := bufio.NewWriter(mw)
	enc := json.NewEncoder(bw)

	if err := enc.Encode(doc); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return ArtifactDescriptor{}, err
	}
	if err := bw.Flush(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return ArtifactDescriptor{}, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return ArtifactDescriptor{}, err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return ArtifactDescriptor{}, err
	}

	sha256hex := hex.EncodeToString(h.Sum(nil))
	byteSize := cw.n

	// .tmp → staging final
	if err := os.Rename(tmpPath, stgPath); err != nil {
		return ArtifactDescriptor{}, err
	}
	// staging → decoder/
	if err := s.publish(stgPath, decoderRelPath); err != nil {
		return ArtifactDescriptor{}, err
	}

	runRel := runRelPath(decoderRelPath)
	return ArtifactDescriptor{
		ArtifactID:          s.artifactID(runRel),
		RelativePath:        runRel,
		ArtifactType:        artifactType,
		Protocol:            protocol,
		MediaType:           mediaType,
		FormatSchemaVersion: SchemaVersion,
		SHA256:              sha256hex,
		ByteSize:            byteSize,
		CreationStage:       "T01",
		ParentSourceSHA256:  s.sourceSHA256,
	}, nil
}

// ---------------------------------------------------------------------------
// newUUIDv4 generates a random UUID v4 using crypto/rand.
// ---------------------------------------------------------------------------

func newUUIDv4() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
