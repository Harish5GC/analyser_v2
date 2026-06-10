package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// HTTP/2 V2 decoder — spec §8, §9, §12, §15
//
// Streams tshark JSON one packet at a time. Each HTTP/2 stream is tracked in
// an http2StreamState keyed by "tcp.stream:http2.streamid". When a stream
// completes (both END_STREAM flags seen, RST_STREAM received, or capture
// ends), the completed state is handed to http2StreamWriter which writes one
// UUID-named JSON document + one stream_index.jsonl entry.
//
// Key invariants that differ from the reference decoder:
//  - Headers are an ordered []Header slice — duplicates and pseudo-headers are
//    preserved (spec §9.1).
//  - Body segments retain the original raw hex bytes; decoded JSON is an extra
//    field only (spec §9.2).
//  - Completion state is one of the six values in spec §9.3.
//  - Full epoch timestamps are stored verbatim; no truncation.
//  - No NRF/UDR filtering, no header dropping, no lean output.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// V2 domain types (spec §9)
// ---------------------------------------------------------------------------

// Header is a single HTTP header as emitted by tshark, with its source frame.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Frame int    `json:"frame"`
}

// BodySegment holds the raw bytes from one DATA frame.
type BodySegment struct {
	Frame  int    `json:"frame"`
	RawHex string `json:"raw_hex"`
}

// Body describes a request or response body: raw segments + optional decoded
// interpretation. The raw bytes are never replaced by the decoded form.
type Body struct {
	ByteLength  int           `json:"byte_length"`
	SHA256      string        `json:"sha256"`
	ContentType string        `json:"content_type,omitempty"`
	Segments    []BodySegment `json:"segments"`
	DecodedJSON interface{}   `json:"decoded_json,omitempty"`
	Multipart   interface{}   `json:"multipart,omitempty"` // populated for multipart bodies
}

// MultipartPart holds one part of a multipart body; all parts retained.
type MultipartPart struct {
	ContentType string      `json:"content_type,omitempty"`
	RawHex      string      `json:"raw_hex"`
	ByteLength  int         `json:"byte_length"`
	SHA256      string      `json:"sha256"`
	DecodedJSON interface{} `json:"decoded_json,omitempty"`
}

// Endpoint is an IP:port pair.
type Endpoint struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// HTTP2Transport is the connection-level identity inside a stream document.
type HTTP2Transport struct {
	TCPStream     *int     `json:"tcp_stream"`
	HTTP2StreamID *int     `json:"http2_stream_id"`
	OriginalKey   string   `json:"original_key"`
	Client        Endpoint `json:"client"`
	Server        Endpoint `json:"server"`
}

// HTTP2Side holds one direction's headers, body, and timing.
type HTTP2Side struct {
	StartFrame     int      `json:"start_frame"`
	EndFrame       int      `json:"end_frame"`
	StartTimeEpoch string   `json:"start_time_epoch"`
	EndTimeEpoch   string   `json:"end_time_epoch"`
	Headers        []Header `json:"headers"`
	Method         string   `json:"method,omitempty"`
	URI            string   `json:"uri,omitempty"`
	Status         *int     `json:"status,omitempty"`
	Body           *Body    `json:"body,omitempty"`
}

// HTTP2Completion captures the stream's final state (spec §9.3).
type HTTP2Completion struct {
	State             string   `json:"state"` // complete|request_only|response_only|reset|truncated_capture|incomplete
	RequestEndStream  bool     `json:"request_end_stream"`
	ResponseEndStream bool     `json:"response_end_stream"`
	RstStream         bool     `json:"rst_stream"`
	CaptureTruncated  bool     `json:"capture_truncated"`
	Warnings          []string `json:"warnings"`
}

// HTTP2Document is the per-stream JSON document written to decoder/full/http2/streams/.
type HTTP2Document struct {
	SchemaVersion string          `json:"schema_version"`
	DocumentID    string          `json:"document_id"` // UUIDv4; also the filename
	Protocol      string          `json:"protocol"`    // "HTTP2"
	Transport     HTTP2Transport  `json:"transport"`
	Request       *HTTP2Side      `json:"request,omitempty"`
	Response      *HTTP2Side      `json:"response,omitempty"`
	Completion    HTTP2Completion `json:"completion"`
	SourceFrames  []int           `json:"source_frames"`
}

// HTTP2StreamIndexEntry is one line in decoder/full/http2/stream_index.jsonl
// (spec §8).
type HTTP2StreamIndexEntry struct {
	DocumentID      string  `json:"document_id"`
	RelativePath    string  `json:"relative_path"`
	TCPStream       *int    `json:"tcp_stream"`
	HTTP2StreamID   *int    `json:"http2_stream_id"`
	OriginalKey     *string `json:"original_key"`
	FirstFrame      int     `json:"first_frame"`
	LastFrame       int     `json:"last_frame"`
	RequestFrame    *int    `json:"request_frame"`
	ResponseFrame   *int    `json:"response_frame"`
	Method          *string `json:"method"`
	URI             *string `json:"uri"`
	Status          *int    `json:"status"`
	SrcIP           *string `json:"src_ip"`
	DstIP           *string `json:"dst_ip"`
	CompletionState string  `json:"completion_state"`
	SHA256          string  `json:"sha256"`
	ByteSize        int64   `json:"byte_size"`
}

// ---------------------------------------------------------------------------
// Internal stream-state machine
// ---------------------------------------------------------------------------

type http2StreamState struct {
	documentID  string
	originalKey string
	tcpStream   *int
	streamID    *int

	// Endpoints — set when first request/response headers are seen.
	clientIP   string
	clientPort int
	serverIP   string
	serverPort int

	// Request side.
	reqHeaders   []Header
	reqMethod    string
	reqURI       string
	reqSegments  []BodySegment
	reqStart     frameTime
	reqEnd       frameTime
	reqEndStream bool

	// Response side.
	respHeaders   []Header
	respStatus    *int
	respSegments  []BodySegment
	respStart     frameTime
	respEnd       frameTime
	respEndStream bool

	// Completion state.
	rstStream bool
	warnings  []string
	frames    []int // all source frames in encounter order
}

type frameTime struct {
	frame int
	epoch string
}

// ---------------------------------------------------------------------------
// HTTP/2 decode entry point
// ---------------------------------------------------------------------------

func decodeHTTP2(ctx context.Context, cfg *DecodeConfig, sink *ArtifactSink, runner *tsharkRunner) ProtocolRun {
	start := time.Now()
	run := ProtocolRun{
		Name: "http2",
		Result: ProtocolDecodeResult{
			Status:   "failed",
			Warnings: []DecodeWarning{},
		},
	}

	// ---- open sinks -------------------------------------------------------
	indexJSONL, err := sink.openJSONL("full/http2/stream_index.jsonl", "http2_stream_index", "http2", "application/x-ndjson")
	if err != nil {
		run.Result.Warnings = append(run.Result.Warnings, warnT01("SINK_OPEN", err.Error()))
		return run
	}

	var rawJSONL *JSONLSink
	if cfg.RetainRaw {
		rawJSONL, err = sink.openJSONL("raw/http2.packets.jsonl", "raw_packets", "http2", "application/x-ndjson")
		if err != nil {
			run.Result.Warnings = append(run.Result.Warnings, warnT01("RAW_SINK_OPEN", err.Error()))
		}
	}

	// ---- start tshark stream --------------------------------------------
	// Type 3 = RST_STREAM added vs. reference to detect reset state.
	displayFilter := "http2 && (http2.type == 0 || http2.type == 1 || http2.type == 3 || " +
		"http2.type == 4 || http2.type == 5 || http2.type == 8 || http2.type == 9)"
	session, err := runner.stream(
		ctx,
		cfg.PCAPPath,
		displayFilter,
		"frame eth ip ipv6 tcp http2",
		"-d", "tcp.port==0-65535,http2", // decode any TCP port as HTTP/2 (http2-only)
	)
	if err != nil {
		run.Result.Warnings = append(run.Result.Warnings, warnT01("TSHARK_START", err.Error()))
		return run
	}

	// Ensure the stream output directory exists.
	if err := ensureDecoderDir(sink.decoderDir, "full/http2/streams"); err != nil {
		run.Result.Warnings = append(run.Result.Warnings, warnT01("MKDIR", err.Error()))
	}

	// ---- streaming parse ------------------------------------------------
	states := make(map[string]*http2StreamState)
	var inputPackets, written, incompleteWritten int64
	var allMembers []CollectionMemberDescriptor
	dec := session.decoder

	for dec.More() {
		var pkt map[string]interface{}
		if err := dec.Decode(&pkt); err != nil {
			run.Result.Warnings = append(run.Result.Warnings, warnT01("PACKET_DECODE", fmt.Sprintf("frame ~%d: %v", inputPackets+1, err)))
			continue
		}
		inputPackets++

		// Tee raw before any processing (spec §12).
		if rawJSONL != nil {
			if err := rawJSONL.WriteRecord(pkt); err != nil {
				run.Result.Warnings = append(run.Result.Warnings, warnT01("RAW_WRITE", err.Error()))
			}
		}

		layers := getPacketLayers(pkt)
		if layers == nil {
			continue
		}
		frame, _ := getFrameNumber(layers)
		epoch, _ := getTimeEpoch(layers)

		entries := getHTTP2Entries(pkt)
		for _, entry := range entries {
			stream, ok := entry["http2.stream"].(map[string]interface{})
			if !ok {
				continue
			}

			// Check RST_STREAM at the entry level.
			entryIsRST := isRSTStream(entry)

			streamIDStr, ok := getStreamID(stream)
			if !ok || streamIDStr == "" {
				continue
			}
			tcpStreamStr := getTCPStreamFromLayers(layers)
			var key string
			if tcpStreamStr != "" {
				key = tcpStreamStr + ":" + streamIDStr
			} else {
				// Lower-confidence fallback using addresses+ports (spec §8).
				key = fmt.Sprintf("%s:%s:%d:%d:%s",
					getSrcIP(layers), getDstIP(layers),
					getTCPSrcPort(layers), getTCPDstPort(layers),
					streamIDStr)
				run.Result.Warnings = append(run.Result.Warnings, warnT01("LOW_CONF_KEY", fmt.Sprintf("frame %d: tcp.stream absent, using tuple key", frame)))
			}

			if isPushPromise(stream) {
				continue
			}

			state := getOrCreateHTTP2State(states, key, tcpStreamStr, streamIDStr, sink.sourceSHA256)
			state.frames = appendUniq(state.frames, frame)

			if entryIsRST {
				state.rstStream = true
			}

			headers := extractHeadersV2(stream, frame)
			isRequest := headersContainV2(headers, ":method")
			isResponse := headersContainV2(headers, ":status")
			endStream := getEndStreamFlag(stream)

			srcIP := getSrcIP(layers)
			dstIP := getDstIP(layers)
			srcPort := getTCPSrcPort(layers)
			dstPort := getTCPDstPort(layers)

			if isRequest {
				// First request frame → set client endpoint.
				if state.clientIP == "" {
					state.clientIP = srcIP
					state.clientPort = srcPort
					state.serverIP = dstIP
					state.serverPort = dstPort
				}
				// Capture timing.
				if state.reqStart.epoch == "" {
					state.reqStart = frameTime{frame, epoch}
				}
				state.reqEnd = frameTime{frame, epoch}

				state.reqHeaders = append(state.reqHeaders, headers...)
				if state.reqMethod == "" {
					state.reqMethod = headerValueV2(headers, ":method")
				}
				if state.reqURI == "" {
					state.reqURI = buildURIFromHeaders(headers)
					if state.reqURI == "" {
						if v, ok := stream["http2.request.full_uri"].(string); ok {
							state.reqURI = v
						}
					}
				}

				if seg := extractSegmentV2(stream, frame); seg != nil {
					state.reqSegments = append(state.reqSegments, *seg)
				}
				if endStream {
					state.reqEndStream = true
					state.reqEnd = frameTime{frame, epoch}
				}
			} else if isResponse {
				// First response frame → set server endpoint if not already known.
				if state.serverIP == "" {
					state.serverIP = srcIP
					state.serverPort = srcPort
					state.clientIP = dstIP
					state.clientPort = dstPort
				}
				if state.respStart.epoch == "" {
					state.respStart = frameTime{frame, epoch}
				}
				state.respEnd = frameTime{frame, epoch}

				state.respHeaders = append(state.respHeaders, headers...)
				if state.respStatus == nil {
					if s := headerValueV2(headers, ":status"); s != "" {
						if n, err := strconv.Atoi(s); err == nil {
							state.respStatus = &n
						}
					}
				}

				if seg := extractSegmentV2(stream, frame); seg != nil {
					state.respSegments = append(state.respSegments, *seg)
				}
				if endStream {
					state.respEndStream = true
					state.respEnd = frameTime{frame, epoch}
				}
			} else {
				// Bare DATA frame — assign to response if response headers seen,
				// else request. Use a fallback warning when heuristic is needed.
				assignToResp := len(state.respHeaders) > 0
				if !assignToResp && state.clientIP == "" {
					// Can't tell which side; try source-port heuristic.
					if srcPort == 80 || srcPort == 443 || srcPort == 8080 {
						assignToResp = true
						state.warnings = append(state.warnings, fmt.Sprintf("frame %d: assigned DATA to response side via port heuristic", frame))
					}
				}
				if seg := extractSegmentV2(stream, frame); seg != nil {
					if assignToResp {
						state.respSegments = append(state.respSegments, *seg)
						if state.respStart.epoch == "" {
							state.respStart = frameTime{frame, epoch}
						}
						state.respEnd = frameTime{frame, epoch}
					} else {
						state.reqSegments = append(state.reqSegments, *seg)
						if state.reqStart.epoch == "" {
							state.reqStart = frameTime{frame, epoch}
						}
						state.reqEnd = frameTime{frame, epoch}
					}
				}
				if endStream {
					if assignToResp {
						state.respEndStream = true
					} else {
						state.reqEndStream = true
					}
				}
			}

			// Flush completed streams immediately to bound memory (spec §15).
			if streamIsComplete(state) {
				member, idxEntry, err := writeHTTP2Stream(state, sink, "full/http2/streams", false)
				if err != nil {
					run.Result.Warnings = append(run.Result.Warnings, warnT01("STREAM_WRITE", fmt.Sprintf("key %s: %v", key, err)))
				} else {
					allMembers = append(allMembers, member)
					if err := indexJSONL.WriteRecord(idxEntry); err != nil {
						run.Result.Warnings = append(run.Result.Warnings, warnT01("INDEX_WRITE", err.Error()))
					}
					written++
				}
				delete(states, key)
			}
		}
	}

	// ---- EOF flush — write all remaining in-flight streams (spec §9.3) --
	// Iterate in a deterministic (sorted) order. Go map iteration is randomised,
	// which would make stream_index.jsonl and the collection digest differ every
	// run and break revision determinism (AC#14).
	for _, key := range sortedStreamKeys(states) {
		state := states[key]
		state.warnings = append(state.warnings, "stream not fully closed at capture end")
		member, idxEntry, err := writeHTTP2Stream(state, sink, "full/http2/streams", true /* eof */)
		if err != nil {
			run.Result.Warnings = append(run.Result.Warnings, warnT01("STREAM_WRITE_EOF", fmt.Sprintf("key %s: %v", key, err)))
			continue
		}
		allMembers = append(allMembers, member)
		if err := indexJSONL.WriteRecord(idxEntry); err != nil {
			run.Result.Warnings = append(run.Result.Warnings, warnT01("INDEX_WRITE", err.Error()))
		}
		incompleteWritten++
		written++
	}
	states = nil

	// ---- finalise tshark process -----------------------------------------
	waitErr := session.Wait()
	if waitErr != nil && written == 0 {
		run.Result.Warnings = append(run.Result.Warnings, warnT01("TSHARK_EXIT", fmt.Sprintf("tshark non-zero: %v", waitErr)))
	}
	if stderr := session.StderrText(); stderr != "" {
		run.Result.Warnings = append(run.Result.Warnings, warnT01("TSHARK_STDERR", truncate(stderr, 512)))
	}

	// ---- close stream index (must be done after all entries written) ----
	idxDesc, err := indexJSONL.Close()
	if err != nil {
		run.Result.Warnings = append(run.Result.Warnings, warnT01("INDEX_PUBLISH", err.Error()))
		return run
	}

	if rawJSONL != nil {
		rawDesc, err := rawJSONL.Close()
		if err != nil {
			run.Result.Warnings = append(run.Result.Warnings, warnT01("RAW_PUBLISH", err.Error()))
		} else {
			run.Artifacts = append(run.Artifacts, rawDesc)
		}
	}

	// ---- build CollectionDescriptor for the stream docs ------------------
	if len(allMembers) > 0 {
		membersDigest := hashMembers(allMembers)
		coll := CollectionDescriptor{
			CollectionID:       deterministicUUID(sink.sourceSHA256, "http2_stream_collection", "decoder/full/http2/streams"),
			RelativeDir:        "decoder/full/http2/streams",
			ArtifactType:       "http2_stream_collection",
			IndexArtifact:      idxDesc,
			MemberCount:        len(allMembers),
			MembersSHA256:      membersDigest,
			Members:            allMembers,
			ParentSourceSHA256: sink.sourceSHA256,
		}
		run.Collections = append(run.Collections, coll)
	} else {
		// No stream docs, but publish the (empty) index as a plain artifact.
		run.Artifacts = append(run.Artifacts, idxDesc)
	}

	// ---- set status and metrics ------------------------------------------
	run.Result.InputPackets = inputPackets
	run.Result.RecordsWritten = written
	run.Result.IncompleteRecords = incompleteWritten
	run.Result.ElapsedMS = time.Since(start).Milliseconds()

	switch {
	case inputPackets == 0:
		run.Result.Status = "absent"
	case waitErr != nil:
		run.Result.Status = "partial"
	case written == 0:
		// HTTP/2 packets were seen but no stream document was produced.
		run.Result.Warnings = append(run.Result.Warnings, warnT01("NO_STREAMS", "http2 packets present but no streams reconstructed"))
		run.Result.Status = "partial"
	default:
		run.Result.Status = "success"
	}

	return run
}

// ---------------------------------------------------------------------------
// State machine helpers
// ---------------------------------------------------------------------------

// sortedStreamKeys returns the keys of the live-stream map in deterministic
// lexical order so EOF-flush output is reproducible (spec §13, AC#14).
func sortedStreamKeys(states map[string]*http2StreamState) []string {
	keys := make([]string, 0, len(states))
	for k := range states {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func getOrCreateHTTP2State(states map[string]*http2StreamState, key, tcpStream, streamIDStr, sourceSHA256 string) *http2StreamState {
	if s, ok := states[key]; ok {
		return s
	}
	// Deterministic document id: stable for the same source + stream key so
	// the stream document bytes (and therefore its checksum) reproduce exactly
	// across runs (spec §7, AC#14).
	s := &http2StreamState{
		documentID:  deterministicUUID(sourceSHA256, "http2_stream", key),
		originalKey: key,
	}
	if tcpStream != "" {
		if n, err := strconv.Atoi(tcpStream); err == nil {
			s.tcpStream = &n
		}
	}
	if n, err := strconv.Atoi(streamIDStr); err == nil {
		s.streamID = &n
	}
	states[key] = s
	return s
}

// streamIsComplete returns true when both end_stream flags are set (normal
// close) or when RST_STREAM has been received.
func streamIsComplete(s *http2StreamState) bool {
	if s.rstStream {
		return true
	}
	// Both sides signalled end-of-stream.
	if s.reqEndStream && s.respEndStream {
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Header extraction — ordered slice preserving duplicates (spec §9.1)
// ---------------------------------------------------------------------------

func extractHeadersV2(stream map[string]interface{}, frame int) []Header {
	raw, ok := stream["http2.header"]
	if !ok {
		return nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		// Single header object (not an array).
		if m, ok := raw.(map[string]interface{}); ok {
			list = []interface{}{m}
		} else {
			return nil
		}
	}
	var headers []Header
	for _, item := range list {
		hdr, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := hdr["http2.header.name"].(string)
		if name == "" {
			continue
		}
		value := ""
		if v, ok := hdr["http2.header.value"].(string); ok {
			value = v
		}
		headers = append(headers, Header{Name: name, Value: value, Frame: frame})
	}
	return headers
}

func headersContainV2(headers []Header, name string) bool {
	for _, h := range headers {
		if h.Name == name {
			return true
		}
	}
	return false
}

func headerValueV2(headers []Header, name string) string {
	for _, h := range headers {
		if h.Name == name {
			return h.Value
		}
	}
	return ""
}

func buildURIFromHeaders(headers []Header) string {
	var scheme, authority, path string
	for _, h := range headers {
		switch h.Name {
		case ":scheme":
			scheme = h.Value
		case ":authority":
			authority = h.Value
		case ":path":
			path = h.Value
		}
	}
	if scheme == "" && authority == "" {
		return path
	}
	if scheme == "" {
		scheme = "http"
	}
	if authority == "" {
		return path
	}
	if path == "" {
		path = "/"
	}
	return scheme + "://" + authority + path
}

// ---------------------------------------------------------------------------
// Body extraction — raw hex retained, decoded JSON as extra (spec §9.2)
// ---------------------------------------------------------------------------

func extractSegmentV2(stream map[string]interface{}, frame int) *BodySegment {
	data, ok := stream["http2.data.data"].(string)
	if !ok || data == "" {
		return nil
	}
	// Keep raw hex exactly as tshark emits it (colon-separated) but normalise
	// to no-separator lowercase hex for the raw_hex field.
	raw, err := decodeHexColon(data)
	if err != nil {
		// If we can't decode the hex, preserve the original string as-is.
		return &BodySegment{Frame: frame, RawHex: data}
	}
	return &BodySegment{Frame: frame, RawHex: hex.EncodeToString(raw)}
}

// assembleBody collects all segments for one side and produces a Body struct.
// The raw bytes from all segments are concatenated only for the purpose of
// computing the aggregate SHA-256 and length. The individual segments (with
// their source frames) are preserved in the Body.Segments field.
func assembleBody(segments []BodySegment, headers []Header) *Body {
	if len(segments) == 0 {
		return nil
	}

	// Decode all segments to compute aggregate checksum + length.
	h := sha256.New()
	totalLen := 0
	for _, seg := range segments {
		raw, err := hex.DecodeString(seg.RawHex)
		if err != nil {
			// Fallback: treat the hex string as bytes for counting purposes.
			raw = []byte(seg.RawHex)
		}
		h.Write(raw)
		totalLen += len(raw)
	}

	contentType := headerValueV2(headers, "content-type")
	body := &Body{
		ByteLength:  totalLen,
		SHA256:      hex.EncodeToString(h.Sum(nil)),
		ContentType: contentType,
		Segments:    segments,
	}

	// Build the full assembled bytes only for decoding (not stored separately).
	var assembled []byte
	for _, seg := range segments {
		raw, err := hex.DecodeString(seg.RawHex)
		if err != nil {
			assembled = append(assembled, []byte(seg.RawHex)...)
		} else {
			assembled = append(assembled, raw...)
		}
	}

	// Try multipart first; fall back to JSON.
	if contentType != "" && strings.Contains(strings.ToLower(contentType), "multipart") {
		if mp := parseMultipartV2(assembled, contentType); mp != nil {
			body.Multipart = mp
		}
	} else {
		var decoded interface{}
		if err := json.Unmarshal(assembled, &decoded); err == nil {
			body.DecodedJSON = decoded
		}
	}

	return body
}

// ---------------------------------------------------------------------------
// Multipart — all parts retained with raw bytes (spec §9.2)
// ---------------------------------------------------------------------------

func parseMultipartV2(body []byte, contentType string) []MultipartPart {
	boundary := parseMultipartBoundary(contentType)
	if boundary == "" {
		return nil
	}
	delimiter := []byte("--" + boundary)
	rawParts := bytes.Split(body, delimiter)

	var parts []MultipartPart
	for _, raw := range rawParts {
		if len(raw) == 0 {
			continue
		}
		if bytes.HasPrefix(raw, []byte("--")) {
			continue
		}
		raw = bytes.TrimPrefix(raw, []byte("\r\n"))

		headerEnd := bytes.Index(raw, []byte("\r\n\r\n"))
		if headerEnd == -1 {
			continue
		}
		rawHdrs := string(raw[:headerEnd])
		partBody := raw[headerEnd+4:]
		if bytes.HasSuffix(partBody, []byte("\r\n")) {
			partBody = partBody[:len(partBody)-2]
		}

		ct := parsePartContentType(rawHdrs)
		if ct == "" {
			ct = "application/octet-stream"
		}
		bodyBytes := append([]byte(nil), partBody...)
		h := sha256.New()
		h.Write(bodyBytes)

		part := MultipartPart{
			ContentType: ct,
			RawHex:      hex.EncodeToString(bodyBytes),
			ByteLength:  len(bodyBytes),
			SHA256:      hex.EncodeToString(h.Sum(nil)),
		}

		// Try to decode JSON for the extra field.
		var decoded interface{}
		if err := json.Unmarshal(bodyBytes, &decoded); err == nil {
			part.DecodedJSON = decoded
		}
		parts = append(parts, part)
	}
	return parts
}

func parseMultipartBoundary(contentType string) string {
	lower := strings.ToLower(contentType)
	idx := strings.Index(lower, "boundary=")
	if idx == -1 {
		return ""
	}
	b := contentType[idx+len("boundary="):]
	if semi := strings.Index(b, ";"); semi != -1 {
		b = b[:semi]
	}
	b = strings.TrimSpace(b)
	b = strings.Trim(b, "\"")
	return b
}

func parsePartContentType(rawHeaders string) string {
	for _, line := range strings.Split(rawHeaders, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "content-type:") {
			return strings.TrimSpace(line[len("content-type:"):])
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Completion state assignment (spec §9.3)
// ---------------------------------------------------------------------------

func completionState(state *http2StreamState, atEOF bool) string {
	if state.rstStream {
		return "reset"
	}
	hasReq := len(state.reqHeaders) > 0 || len(state.reqSegments) > 0
	hasResp := len(state.respHeaders) > 0 || len(state.respSegments) > 0

	if state.reqEndStream && state.respEndStream {
		return "complete"
	}
	if atEOF {
		if hasReq && !hasResp {
			return "request_only"
		}
		if !hasReq && hasResp {
			return "response_only"
		}
		// Both sides seen but at least one didn't signal end-of-stream.
		return "truncated_capture"
	}
	return "incomplete"
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

func appendUniq(slice []int, v int) []int {
	for _, existing := range slice {
		if existing == v {
			return slice
		}
	}
	return append(slice, v)
}

// sha256Sum returns the hex SHA-256 of b.
func sha256Sum(b []byte) string {
	h := sha256.New()
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// hashMembers produces a stable SHA-256 over an ordered list of member
// checksums — used as CollectionDescriptor.MembersSHA256.
func hashMembers(members []CollectionMemberDescriptor) string {
	h := sha256.New()
	for _, m := range members {
		h.Write([]byte(m.SHA256))
		h.Write([]byte("\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// truncate shortens s to at most max bytes without splitting a UTF-8 rune.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func ensureDecoderDir(decoderDir, rel string) error {
	return os.MkdirAll(filepath.Join(decoderDir, filepath.FromSlash(rel)), 0750)
}
