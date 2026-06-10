// Copyright (c) 2026 Harish5GC. All rights reserved.
// Unauthorized copying, distribution, or modification of this file, via any medium,
// is strictly prohibited without prior written permission from Harish5GC.
// No license is granted, and no rights are implied beyond this notice.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type HTTP2Decoder struct {
	PcapPath string
}

const leanIncludeRequestEpochMeta = true

var extraLean = getEnvBool("EXTRA_LEAN", true)
var extraLeanHeaderDrop = map[string]struct{}{
	"x-forwarded-client-cert": {},
	"3gpp-sbi-binding":        {},
	"3gpp-sbi-nf-peer-info":   {},
	"authorization":           {},
}

func NewHTTP2Decoder(pcap string) *HTTP2Decoder {
	return &HTTP2Decoder{PcapPath: pcap}
}

type HTTPMessage struct {
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    interface{}       `json:"body,omitempty"`
}

type FlowMeta struct {
	Frame string `json:"frame,omitempty"`
	Time  string `json:"time,omitempty"`
	SrcIP string `json:"src_ip,omitempty"`
	DstIP string `json:"dst_ip,omitempty"`
}

type HTTPConversation struct {
	Meta     FlowMeta    `json:"meta,omitempty"`
	Request  HTTPMessage `json:"request,omitempty"`
	Response HTTPMessage `json:"response,omitempty"`
}

type LeanHTTPConversation struct {
	Time     string          `json:"time,omitempty"`
	Request  LeanHTTPMessage `json:"request,omitempty"`
	Response LeanHTTPMessage `json:"response,omitempty"`
}

type LeanHTTPMessage struct {
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    interface{}       `json:"body,omitempty"`
}

type streamState struct {
	Conv            HTTPConversation
	ReqHeadersSeen  bool
	RespHeadersSeen bool
	ReqBodySeen     bool
	RespBodySeen    bool
	ReqEnded        bool
	RespEnded       bool
	RequestMetaSet  bool
}

func (d *HTTP2Decoder) StreamHTTPMapToJSONMap(jsonPath, leanPath string) error {
	tmpFile, err := os.CreateTemp("", "http2_stream_*.ndjson")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		return err
	}
	defer os.Remove(tmpPath)

	if err := d.streamHTTPMapToNDJSON(tmpPath); err != nil {
		return err
	}
	return ConvertNDJSONToJSONMaps(tmpPath, jsonPath, leanPath)
}

func (d *HTTP2Decoder) streamHTTPMapToNDJSON(path string) error {
	cmd := exec.Command(
		"tshark",
		"-r", d.PcapPath,
		"-Y", "http2 && (http2.type == 0 || http2.type == 1 || http2.type == 4 || http2.type == 5 || http2.type == 8 || http2.type == 9)",
		"-d", "tcp.port==0-65535,http2",
		"-T", "json",
		"-J", "frame eth ip ipv6 tcp http2",
		"--no-duplicate-keys",
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	start := time.Now()
	fmt.Fprintln(os.Stderr, "[HTTP2Stream] START:", start)

	if err := cmd.Start(); err != nil {
		return err
	}

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			fmt.Fprintln(os.Stderr, "[tshark]", scanner.Text())
		}
	}()

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	encoder := json.NewEncoder(writer)

	decoder := json.NewDecoder(stdout)
	if _, err := decoder.Token(); err != nil {
		return err
	}

	states := make(map[string]*streamState)
	count := 0
	for decoder.More() {
		var pkt map[string]interface{}
		if err := decoder.Decode(&pkt); err != nil {
			fmt.Fprintln(os.Stderr, "Decode error:", err)
			continue
		}
		count++
		processPacketForHTTPMap(states, pkt, encoder)
	}

	for key, state := range states {
		writeHTTPMapEntry(encoder, key, state.Conv)
	}

	if err := cmd.Wait(); err != nil {
		return err
	}

	end := time.Now()
	fmt.Fprintln(os.Stderr, "[HTTP2Stream] END:", end)
	fmt.Fprintf(os.Stderr, "[HTTP2Stream] ELAPSED: %v\n", end.Sub(start))
	fmt.Fprintln(os.Stderr, "[HTTP2Stream] PACKETS:", count)
	fmt.Fprintln(os.Stderr, "[HTTP2Stream] NDJSON written:", path)

	return nil
}

func ConvertNDJSONToJSONMaps(ndjsonPath, jsonPath, leanPath string) error {
	in, err := os.Open(ndjsonPath)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(jsonPath)
	if err != nil {
		return err
	}
	defer out.Close()

	leanOut, err := os.Create(leanPath)
	if err != nil {
		return err
	}
	defer leanOut.Close()

	reader := bufio.NewScanner(in)
	reader.Buffer(make([]byte, 0, 64*1024), 1024*1024*50)
	writer := bufio.NewWriter(out)
	defer writer.Flush()

	leanWriter := bufio.NewWriter(leanOut)
	defer leanWriter.Flush()

	if _, err := writer.WriteString("{"); err != nil {
		return err
	}
	if _, err := leanWriter.WriteString("{"); err != nil {
		return err
	}

	first := true
	leanFirst := true
	for reader.Scan() {
		line := strings.TrimSpace(reader.Text())
		if line == "" {
			continue
		}
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return err
		}
		key, _ := entry["key"].(string)
		if key == "" {
			continue
		}
		data := entry["data"]

		keyJSON, err := json.Marshal(key)
		if err != nil {
			return err
		}
		dataJSON, err := json.Marshal(data)
		if err != nil {
			return err
		}

		if first {
			first = false
		} else {
			if _, err := writer.WriteString(","); err != nil {
				return err
			}
		}
		if _, err := writer.WriteString("\n"); err != nil {
			return err
		}
		if _, err := writer.Write(keyJSON); err != nil {
			return err
		}
		if _, err := writer.WriteString(":"); err != nil {
			return err
		}
		if _, err := writer.Write(dataJSON); err != nil {
			return err
		}

		var conv HTTPConversation
		if b, err := json.Marshal(data); err == nil {
			_ = json.Unmarshal(b, &conv)
		}
		leanConv, ok := buildLeanConversation(conv)
		if !ok {
			continue
		}
		leanDataJSON, err := json.Marshal(leanConv)
		if err != nil {
			return err
		}

		if leanFirst {
			leanFirst = false
		} else {
			if _, err := leanWriter.WriteString(","); err != nil {
				return err
			}
		}
		if _, err := leanWriter.WriteString("\n"); err != nil {
			return err
		}
		if _, err := leanWriter.Write(keyJSON); err != nil {
			return err
		}
		if _, err := leanWriter.WriteString(":"); err != nil {
			return err
		}
		if _, err := leanWriter.Write(leanDataJSON); err != nil {
			return err
		}
	}
	if err := reader.Err(); err != nil {
		return err
	}

	if _, err := writer.WriteString("\n}\n"); err != nil {
		return err
	}
	if _, err := leanWriter.WriteString("\n}\n"); err != nil {
		return err
	}
	return nil
}

func processPacketForHTTPMap(states map[string]*streamState, pkt map[string]interface{}, encoder *json.Encoder) {
	layers := getPacketLayers(pkt)
	tcpStream := getTCPStreamFromLayers(layers)
	if tcpStream == "" {
		return
	}
	entries := getHTTP2Entries(pkt)
	for _, entry := range entries {
		stream, ok := entry["http2.stream"].(map[string]interface{})
		if !ok {
			continue
		}
		streamID, ok := getStreamID(stream)
		if !ok || streamID == "" {
			continue
		}
		key := fmt.Sprintf("%s:%s", tcpStream, streamID)

		if isPushPromise(stream) {
			continue
		}

		state := getOrCreateState(states, key)
		headers := extractHeaders(stream)
		isRequest := headersContain(headers, ":method")
		isResponse := headersContain(headers, ":status")
		endStream := getEndStreamFlag(stream)

		if isRequest {
			if !state.RequestMetaSet {
				state.Conv.Meta = extractFlowMeta(layers)
				state.RequestMetaSet = true
			}
			if state.Conv.Request.Headers == nil {
				state.Conv.Request.Headers = make(map[string]string)
			}
			mergeHeaders(state.Conv.Request.Headers, headers)
			state.ReqHeadersSeen = true
			if state.Conv.Request.URL == "" {
				if url, ok := stream["http2.request.full_uri"].(string); ok {
					state.Conv.Request.URL = url
				} else {
					state.Conv.Request.URL = buildURLFromHeaders(headers)
				}
			}
			bodyHeaders := headers
			if len(bodyHeaders) == 0 && state.Conv.Request.Headers != nil {
				bodyHeaders = state.Conv.Request.Headers
			}
			if body := extractBody(entry, stream, layers, bodyHeaders); body != nil {
				state.Conv.Request.Body = appendBody(state.Conv.Request.Body, body)
				state.ReqBodySeen = true
			}
			if endStream {
				state.ReqEnded = true
			}
		} else if isResponse {
			if state.Conv.Response.Headers == nil {
				state.Conv.Response.Headers = make(map[string]string)
			}
			mergeHeaders(state.Conv.Response.Headers, headers)
			state.RespHeadersSeen = true
			bodyHeaders := headers
			if len(bodyHeaders) == 0 && state.Conv.Response.Headers != nil {
				bodyHeaders = state.Conv.Response.Headers
			}
			if body := extractBody(entry, stream, layers, bodyHeaders); body != nil {
				state.Conv.Response.Body = appendBody(state.Conv.Response.Body, body)
				state.RespBodySeen = true
			}
			if endStream {
				state.RespEnded = true
			}
		} else {
			if isResponseBody(layers, state.Conv) {
				bodyHeaders := state.Conv.Response.Headers
				if body := extractBody(entry, stream, layers, bodyHeaders); body != nil {
					state.Conv.Response.Body = appendBody(state.Conv.Response.Body, body)
					state.RespBodySeen = true
				}
				if endStream {
					state.RespEnded = true
				}
			} else {
				bodyHeaders := state.Conv.Request.Headers
				if body := extractBody(entry, stream, layers, bodyHeaders); body != nil {
					state.Conv.Request.Body = appendBody(state.Conv.Request.Body, body)
					state.ReqBodySeen = true
				}
				if endStream {
					state.ReqEnded = true
				}
			}
		}

		if state.RespEnded && (state.ReqEnded || !state.ReqBodySeen) {
			writeHTTPMapEntry(encoder, key, state.Conv)
			delete(states, key)
		}
	}
}

func getOrCreateState(states map[string]*streamState, key string) *streamState {
	state, ok := states[key]
	if !ok {
		state = &streamState{}
		states[key] = state
	}
	return state
}

func writeHTTPMapEntry(encoder *json.Encoder, key string, conv HTTPConversation) {
	_ = encoder.Encode(map[string]interface{}{
		"key":  key,
		"data": conv,
	})
}

func getEndStreamFlag(stream map[string]interface{}) bool {
	if v, ok := findNestedKey(stream, "http2.flags.end_stream"); ok {
		if s, ok := stringifyLayerValue(v); ok {
			return s == "1" || strings.EqualFold(s, "true")
		}
	}
	return false
}

func extractFlowMeta(layers map[string]interface{}) FlowMeta {
	var meta FlowMeta
	if layers == nil {
		return meta
	}
	if v, ok := getLayerString(map[string]interface{}{"_source": map[string]interface{}{"layers": layers}}, "frame.number"); ok {
		meta.Frame = v
	}
	if v, ok := getLayerString(map[string]interface{}{"_source": map[string]interface{}{"layers": layers}}, "frame.time_epoch"); ok {
		meta.Time = epochToTimeOnly(v)
	}
	if v, ok := getLayerString(map[string]interface{}{"_source": map[string]interface{}{"layers": layers}}, "ip.src"); ok {
		meta.SrcIP = v
	}
	if v, ok := getLayerString(map[string]interface{}{"_source": map[string]interface{}{"layers": layers}}, "ip.dst"); ok {
		meta.DstIP = v
	}
	return meta
}

func getPacketLayers(pkt map[string]interface{}) map[string]interface{} {
	source, ok := pkt["_source"].(map[string]interface{})
	if !ok {
		return nil
	}
	layers, ok := source["layers"].(map[string]interface{})
	if !ok {
		return nil
	}
	return layers
}

func getTCPStreamFromLayers(layers map[string]interface{}) string {
	if layers == nil {
		return ""
	}
	tcp, ok := layers["tcp"].(map[string]interface{})
	if !ok {
		return ""
	}
	if v, ok := tcp["tcp.stream"]; ok {
		if s, ok := stringifyLayerValue(v); ok {
			return s
		}
	}
	return ""
}

func getHTTP2Entries(pkt map[string]interface{}) []map[string]interface{} {
	layers := getPacketLayers(pkt)
	if layers == nil {
		return nil
	}
	raw := layers["http2"]
	switch v := raw.(type) {
	case map[string]interface{}:
		return []map[string]interface{}{v}
	case []interface{}:
		out := make([]map[string]interface{}, 0, len(v))
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				out = append(out, m)
			}
		}
		return out
	default:
		return nil
	}
}

func getStreamID(stream map[string]interface{}) (string, bool) {
	if v, ok := stream["http2.streamid"]; ok {
		return stringifyLayerValue(v)
	}
	if v, ok := stream["http2.stream"]; ok {
		return stringifyLayerValue(v)
	}
	return "", false
}

func extractHeaders(stream map[string]interface{}) map[string]string {
	headers := make(map[string]string)
	raw := stream["http2.header"]
	list, ok := raw.([]interface{})
	if !ok {
		return headers
	}
	for _, item := range list {
		hdr, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := hdr["http2.header.name"].(string)
		if name == "" {
			continue
		}
		if value, ok := hdr["http2.header.value"].(string); ok {
			headers[name] = value
		}
	}
	return headers
}

func buildURLFromHeaders(headers map[string]string) string {
	if headers == nil {
		return ""
	}
	scheme := headers[":scheme"]
	authority := headers[":authority"]
	path := headers[":path"]
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
	return fmt.Sprintf("%s://%s%s", scheme, authority, path)
}

func headersContain(headers map[string]string, key string) bool {
	_, ok := headers[key]
	return ok
}

func mergeHeaders(dst, src map[string]string) {
	for k, v := range src {
		dst[k] = v
	}
}

func extractBody(entry, stream map[string]interface{}, layers map[string]interface{}, headers map[string]string) interface{} {
	if raw, ok := entry["json"].(map[string]interface{}); ok {
		if obj, ok := raw["json.object"].(string); ok && obj != "" {
			var decoded interface{}
			if err := json.Unmarshal([]byte(obj), &decoded); err == nil {
				return decoded
			}
			return obj
		}
	}
	if layers != nil {
		if raw, ok := layers["json"].(map[string]interface{}); ok {
			if obj, ok := raw["json.object"].(string); ok && obj != "" {
				var decoded interface{}
				if err := json.Unmarshal([]byte(obj), &decoded); err == nil {
					return decoded
				}
				return obj
			}
		}
	}
	if data, ok := stream["http2.data.data"].(string); ok && data != "" {
		decoded, err := decodeHexColon(data)
		if err != nil {
			return data
		}
		contentType := ""
		if headers != nil {
			contentType = headers["content-type"]
		}
		if contentType != "" {
			if multipartJSON := extractMultipartJSON(decoded, contentType); multipartJSON != nil {
				return multipartJSON
			}
		}
		var jsonBody interface{}
		if err := json.Unmarshal(decoded, &jsonBody); err == nil {
			return jsonBody
		}
		return string(decoded)
	}
	return nil
}

func appendBody(existing interface{}, incoming interface{}) interface{} {
	if existing == nil {
		return incoming
	}
	if list, ok := existing.([]interface{}); ok {
		return append(list, incoming)
	}
	return []interface{}{existing, incoming}
}

func isResponseBody(layers map[string]interface{}, conv HTTPConversation) bool {
	if headersContain(conv.Response.Headers, ":status") {
		return true
	}
	if layers == nil {
		return false
	}
	if srcPort, ok := getLayerString(map[string]interface{}{"_source": map[string]interface{}{"layers": layers}}, "tcp.srcport"); ok {
		if srcPort == "80" || srcPort == "443" {
			return true
		}
	}
	if conv.Request.Headers != nil && len(conv.Request.Headers) > 0 && conv.Response.Headers == nil {
		return false
	}
	return false
}

func isPushPromise(stream map[string]interface{}) bool {
	if stream == nil {
		return false
	}
	if v, ok := stream["http2.type"]; ok {
		if s, ok := stringifyLayerValue(v); ok {
			return s == "5"
		}
	}
	return false
}

func findPromisedStreamID(entry map[string]interface{}, stream map[string]interface{}) (string, bool) {
	candidates := []string{
		"http2.push_promise.promised_streamid",
		"http2.push_promise.promised_stream_id",
		"http2.push_promise.streamid",
		"http2.promised_streamid",
		"http2.promised_stream_id",
	}
	for _, key := range candidates {
		if v, ok := stream[key]; ok {
			return stringifyLayerValue(v)
		}
		if v, ok := entry[key]; ok {
			return stringifyLayerValue(v)
		}
	}
	if v, ok := findStringByKeyContains(stream, "promised", "stream"); ok {
		return v, true
	}
	if v, ok := findStringByKeyContains(entry, "promised", "stream"); ok {
		return v, true
	}
	return "", false
}

func findStringByKeyContains(m map[string]interface{}, tokens ...string) (string, bool) {
	for k, v := range m {
		match := true
		lower := strings.ToLower(k)
		for _, t := range tokens {
			if !strings.Contains(lower, t) {
				match = false
				break
			}
		}
		if match {
			if s, ok := stringifyLayerValue(v); ok {
				return s, true
			}
		}
		switch child := v.(type) {
		case map[string]interface{}:
			if s, ok := findStringByKeyContains(child, tokens...); ok {
				return s, true
			}
		case []interface{}:
			for _, item := range child {
				if m2, ok := item.(map[string]interface{}); ok {
					if s, ok := findStringByKeyContains(m2, tokens...); ok {
						return s, true
					}
				}
			}
		}
	}
	return "", false
}

func getLayerString(pkt map[string]interface{}, key string) (string, bool) {
	source, ok := pkt["_source"].(map[string]interface{})
	if !ok {
		return "", false
	}
	layers, ok := source["layers"].(map[string]interface{})
	if !ok {
		return "", false
	}
	if val, ok := layers[key]; ok {
		return stringifyLayerValue(val)
	}
	if dot := strings.IndexByte(key, '.'); dot != -1 {
		if proto, ok := layers[key[:dot]].(map[string]interface{}); ok {
			if val, ok := proto[key]; ok {
				return stringifyLayerValue(val)
			}
		}
	}
	val, ok := findNestedKey(layers, key)
	if !ok {
		return "", false
	}
	return stringifyLayerValue(val)
}

func stringifyLayerValue(val interface{}) (string, bool) {
	switch v := val.(type) {
	case []interface{}:
		if len(v) == 0 {
			return "", false
		}
		return fmt.Sprint(v[0]), true
	case string:
		return v, true
	default:
		return fmt.Sprint(v), true
	}
}

func findNestedKey(m map[string]interface{}, key string) (interface{}, bool) {
	if v, ok := m[key]; ok {
		return v, true
	}
	for _, v := range m {
		switch child := v.(type) {
		case map[string]interface{}:
			if res, ok := findNestedKey(child, key); ok {
				return res, true
			}
		case []interface{}:
			for _, item := range child {
				if m2, ok := item.(map[string]interface{}); ok {
					if res, ok := findNestedKey(m2, key); ok {
						return res, true
					}
				}
			}
		}
	}
	return nil, false
}

func decodeHexColon(input string) ([]byte, error) {
	cleaned := strings.ReplaceAll(input, ":", "")
	if len(cleaned)%2 != 0 {
		return nil, fmt.Errorf("odd hex length")
	}
	return hex.DecodeString(cleaned)
}

func extractMultipartJSON(body []byte, contentType string) interface{} {
	boundary := parseMultipartBoundary(contentType)
	if boundary == "" {
		return nil
	}
	delimiter := "--" + boundary
	parts := strings.Split(string(body), delimiter)
	var jsonParts []interface{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || part == "--" {
			continue
		}
		if strings.HasPrefix(part, "\r\n") {
			part = strings.TrimPrefix(part, "\r\n")
		}
		headerEnd := strings.Index(part, "\r\n\r\n")
		if headerEnd == -1 {
			continue
		}
		rawHeaders := part[:headerEnd]
		partBody := part[headerEnd+4:]
		partBody = strings.TrimSuffix(partBody, "\r\n")
		partBody = strings.TrimSuffix(partBody, "--")
		partBody = strings.TrimSuffix(partBody, "\r\n")
		partContentType := parsePartContentType(rawHeaders)
		if partContentType == "" {
			partContentType = "application/octet-stream"
		}
		if strings.Contains(partContentType, "application/json") ||
			strings.Contains(partContentType, "application/problem+json") ||
			looksLikeJSON(partBody) {
			var decoded interface{}
			if err := json.Unmarshal([]byte(partBody), &decoded); err == nil {
				jsonParts = append(jsonParts, decoded)
			}
		}
	}
	if len(jsonParts) == 1 {
		return jsonParts[0]
	}
	if len(jsonParts) > 1 {
		return jsonParts
	}
	return nil
}

func parseMultipartBoundary(contentType string) string {
	lower := strings.ToLower(contentType)
	idx := strings.Index(lower, "boundary=")
	if idx == -1 {
		return ""
	}
	boundary := contentType[idx+len("boundary="):]
	if semi := strings.Index(boundary, ";"); semi != -1 {
		boundary = boundary[:semi]
	}
	boundary = strings.TrimSpace(boundary)
	boundary = strings.Trim(boundary, "\"")
	return boundary
}

func parsePartContentType(rawHeaders string) string {
	lines := strings.Split(rawHeaders, "\r\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "content-type:") {
			return strings.TrimSpace(line[len("content-type:"):])
		}
	}
	return ""
}

func looksLikeJSON(input string) bool {
	trimmed := strings.TrimSpace(input)
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}

func buildLeanConversation(conv HTTPConversation) (LeanHTTPConversation, bool) {
	if conv.Request.URL == "" {
		conv.Request.URL = buildURLFromHeaders(conv.Request.Headers)
	}

	status := getHeaderValueIgnoreCase(conv.Response.Headers, ":status")
	url := conv.Request.URL
	lowerURL := strings.ToLower(url)
	if status != "" && (strings.Contains(lowerURL, "/nnrf-") || strings.Contains(lowerURL, "/nudr-")) {
		if !strings.HasPrefix(status, "4") && !strings.HasPrefix(status, "5") {
			return LeanHTTPConversation{}, false
		}
	}

	conv.Request.Headers = dropHeaders(conv.Request.Headers, requestHeaderDrop())
	conv.Response.Headers = dropHeaders(conv.Response.Headers, responseHeaderDrop())
	if len(conv.Request.Headers) == 0 {
		conv.Request.Headers = nil
	}
	if len(conv.Response.Headers) == 0 {
		conv.Response.Headers = nil
	}
	if isEmptyHTTPMessage(conv.Request) && isEmptyHTTPMessage(conv.Response) {
		return LeanHTTPConversation{}, false
	}

	leanReq := LeanHTTPMessage{
		URL:     conv.Request.URL,
		Headers: conv.Request.Headers,
		Body:    conv.Request.Body,
	}
	leanResp := LeanHTTPMessage{
		URL:     conv.Response.URL,
		Headers: conv.Response.Headers,
		Body:    conv.Response.Body,
	}
	leanConv := LeanHTTPConversation{Request: leanReq, Response: leanResp}
	if leanIncludeRequestEpochMeta && conv.Meta.Time != "" {
		leanConv.Time = conv.Meta.Time
	}
	return leanConv, true
}

func epochToTimeOnly(value string) string {
	if value == "" {
		return value
	}
	if idx := strings.IndexByte(value, 'T'); idx != -1 {
		value = value[idx+1:]
	}
	value = strings.TrimSuffix(value, "Z")
	return trimTimestamp(value)
}

func trimTimestamp(value string) string {
	if value == "" {
		return value
	}
	if dot := strings.IndexByte(value, '.'); dot != -1 {
		intPart := value[:dot]
		frac := strings.TrimRight(value[dot+1:], "0")
		if frac == "" {
			return intPart
		}
		return intPart + "." + frac
	}
	return value
}

func isEmptyHTTPMessage(msg HTTPMessage) bool {
	return msg.URL == "" && len(msg.Headers) == 0 && msg.Body == nil
}

func requestHeaderDrop() map[string]struct{} {
	return map[string]struct{}{
		"3gpp-sbi-max-rsp-time":     {},
		"3gpp-sbi-sender-timestamp": {},
		"authority":                 {},
		":authority":                {},
		"path":                      {},
		":path":                     {},
		"scheme":                    {},
		":scheme":                   {},
		"accept":                    {},
		"content-length":            {},
		"content-type":              {},
	}
}

func responseHeaderDrop() map[string]struct{} {
	return map[string]struct{}{
		"date":           {},
		"content-length": {},
		"content-type":   {},
	}
}

func dropHeaders(headers map[string]string, drop map[string]struct{}) map[string]string {
	if headers == nil {
		return nil
	}
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		lowerKey := strings.ToLower(k)
		if _, ok := drop[lowerKey]; ok {
			continue
		}
		if extraLean {
			if strings.HasPrefix(lowerKey, "x-") {
				continue
			}
			if _, ok := extraLeanHeaderDrop[lowerKey]; ok {
				continue
			}
		}
		out[k] = v
	}
	return out
}

func getHeaderValueIgnoreCase(headers map[string]string, key string) string {
	if headers == nil {
		return ""
	}
	lowerKey := strings.ToLower(key)
	for k, v := range headers {
		if strings.ToLower(k) == lowerKey {
			return v
		}
	}
	return ""
}

func getEnvBool(key string, defaultVal bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return defaultVal
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return defaultVal
	}
}
