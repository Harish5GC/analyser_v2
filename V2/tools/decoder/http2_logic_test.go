package main

import (
	"encoding/hex"
	"testing"
)

func hdrStream(pairs ...[2]string) map[string]interface{} {
	var list []interface{}
	for _, p := range pairs {
		list = append(list, map[string]interface{}{
			"http2.header.name":  p[0],
			"http2.header.value": p[1],
		})
	}
	return map[string]interface{}{"http2.header": list}
}

// §9.1 — order, duplicates, and pseudo-headers must all be preserved.
func TestExtractHeadersOrderDuplicatesPseudo(t *testing.T) {
	stream := hdrStream(
		[2]string{":method", "POST"},
		[2]string{":path", "/x"},
		[2]string{"content-type", "application/json"},
		[2]string{"set-cookie", "a=1"},
		[2]string{"set-cookie", "b=2"}, // duplicate name
	)
	got := extractHeadersV2(stream, 100)
	if len(got) != 5 {
		t.Fatalf("expected 5 headers, got %d", len(got))
	}
	if got[0].Name != ":method" || got[1].Name != ":path" {
		t.Fatalf("pseudo-header order not preserved: %+v", got[:2])
	}
	if got[3].Value != "a=1" || got[4].Value != "b=2" {
		t.Fatalf("duplicate headers collapsed or reordered: %+v", got[3:])
	}
	for _, h := range got {
		if h.Frame != 100 {
			t.Fatalf("frame not stamped on header: %+v", h)
		}
	}
}

// §9.2 — raw body bytes retained as hex; aggregate sha256 + length computed.
func TestAssembleBodyRetainsRawHexAndChecksum(t *testing.T) {
	payload := []byte(`{"a":1}`)
	seg := BodySegment{Frame: 7, RawHex: hex.EncodeToString(payload)}
	body := assembleBody([]BodySegment{seg}, []Header{{Name: "content-type", Value: "application/json"}})
	if body == nil {
		t.Fatal("nil body")
	}
	if body.ByteLength != len(payload) {
		t.Fatalf("byte_length = %d, want %d", body.ByteLength, len(payload))
	}
	if len(body.Segments) != 1 || body.Segments[0].RawHex != seg.RawHex {
		t.Fatal("raw segment hex not retained")
	}
	if body.SHA256 == "" {
		t.Fatal("missing body sha256")
	}
	// decoded_json is an EXTRA representation, never a replacement.
	if body.DecodedJSON == nil {
		t.Fatal("decoded_json should be populated for valid JSON")
	}
	m, ok := body.DecodedJSON.(map[string]interface{})
	if !ok || m["a"] != float64(1) {
		t.Fatalf("decoded_json wrong: %#v", body.DecodedJSON)
	}
}

// §9.2 — malformed JSON must NOT drop bytes; raw hex stays, decoded_json nil.
func TestAssembleBodyMalformedJSONKeepsBytes(t *testing.T) {
	payload := []byte(`{not json`)
	seg := BodySegment{Frame: 1, RawHex: hex.EncodeToString(payload)}
	body := assembleBody([]BodySegment{seg}, nil)
	if body == nil || len(body.Segments) != 1 {
		t.Fatal("body/segment lost for malformed JSON")
	}
	if body.DecodedJSON != nil {
		t.Fatal("decoded_json should be nil for malformed JSON")
	}
	if body.ByteLength != len(payload) {
		t.Fatal("byte_length wrong for malformed body")
	}
}

// §9.2 — multipart: every part retained with raw hex + checksum.
func TestParseMultipartRetainsAllParts(t *testing.T) {
	ct := `multipart/related; boundary=abc`
	body := "--abc\r\n" +
		"Content-Type: application/json\r\n\r\n" +
		`{"k":1}` + "\r\n" +
		"--abc\r\n" +
		"Content-Type: application/octet-stream\r\n\r\n" +
		"BINARYDATA\r\n" +
		"--abc--\r\n"
	parts := parseMultipartV2([]byte(body), ct)
	if len(parts) != 2 {
		t.Fatalf("expected 2 parts, got %d", len(parts))
	}
	if parts[0].DecodedJSON == nil {
		t.Fatal("json part should decode")
	}
	if parts[1].RawHex == "" || parts[1].ByteLength == 0 {
		t.Fatal("binary part raw hex not retained")
	}
	if parts[1].DecodedJSON != nil {
		t.Fatal("binary part should not decode as JSON")
	}
}

func TestParseMultipartPreservesBinaryPartBytes(t *testing.T) {
	ct := `multipart/related; boundary=abc`
	payload := []byte{' ', 0x00, 'A', '\n', ' '}
	body := append([]byte("--abc\r\nContent-Type: application/octet-stream\r\n\r\n"), payload...)
	body = append(body, []byte("\r\n--abc--\r\n")...)

	parts := parseMultipartV2(body, ct)
	if len(parts) != 1 {
		t.Fatalf("expected 1 part, got %d", len(parts))
	}
	if got, want := parts[0].RawHex, hex.EncodeToString(payload); got != want {
		t.Fatalf("raw_hex = %q, want %q", got, want)
	}
	if got, want := parts[0].ByteLength, len(payload); got != want {
		t.Fatalf("byte_length = %d, want %d", got, want)
	}
}

// §9.3 — completion-state machine.
func TestCompletionStates(t *testing.T) {
	withReqResp := func() *http2StreamState {
		return &http2StreamState{
			reqHeaders:  []Header{{Name: ":method"}},
			respHeaders: []Header{{Name: ":status"}},
		}
	}

	// complete
	s := withReqResp()
	s.reqEndStream, s.respEndStream = true, true
	if got := completionState(s, false); got != "complete" {
		t.Errorf("complete: got %s", got)
	}

	// reset
	s = withReqResp()
	s.rstStream = true
	if got := completionState(s, false); got != "reset" {
		t.Errorf("reset: got %s", got)
	}

	// incomplete (mid-capture, not done)
	s = withReqResp()
	if got := completionState(s, false); got != "incomplete" {
		t.Errorf("incomplete: got %s", got)
	}

	// request_only at EOF
	s = &http2StreamState{reqHeaders: []Header{{Name: ":method"}}}
	if got := completionState(s, true); got != "request_only" {
		t.Errorf("request_only: got %s", got)
	}

	// response_only at EOF
	s = &http2StreamState{respHeaders: []Header{{Name: ":status"}}}
	if got := completionState(s, true); got != "response_only" {
		t.Errorf("response_only: got %s", got)
	}

	// truncated_capture at EOF (both sides seen, neither end_stream)
	s = withReqResp()
	if got := completionState(s, true); got != "truncated_capture" {
		t.Errorf("truncated_capture: got %s", got)
	}
}

func TestBuildURIFromHeaders(t *testing.T) {
	h := []Header{
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: "nf.example:7777"},
		{Name: ":path", Value: "/nnrf/v1/x"},
	}
	if got := buildURIFromHeaders(h); got != "http://nf.example:7777/nnrf/v1/x" {
		t.Fatalf("uri = %q", got)
	}
}

// C1.4 — EOF flush key ordering must be deterministic (sorted).
func TestSortedStreamKeys(t *testing.T) {
	states := map[string]*http2StreamState{
		"9:1": {}, "10:2": {}, "1:1": {}, "2:30": {},
	}
	got := sortedStreamKeys(states)
	// Lexical (byte) order: ':' (0x3a) > '0' (0x30), so "10:2" precedes "1:1".
	// The exact order doesn't matter for correctness — only that it is stable.
	want := []string{"10:2", "1:1", "2:30", "9:1"}
	if len(got) != len(want) {
		t.Fatalf("len = %d", len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sortedStreamKeys = %v, want %v", got, want)
		}
	}
}

func TestTruncateRuneSafe(t *testing.T) {
	s := "abc" + "€" + "xyz" // '€' is 3 bytes
	// Cut in the middle of the euro sign; must not produce invalid UTF-8.
	out := truncate(s, 4)
	for _, r := range out {
		if r == '�' {
			t.Fatalf("truncate split a rune: %q", out)
		}
	}
}
