package main

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// Packet-tree navigation helpers — shared by all three protocol decoders.
// These are kept verbatim from the reference decoder (http2_decoder.go) and
// extended with IPv4/IPv6, port, frame-number, and epoch helpers for V2.
// ---------------------------------------------------------------------------

// wrapLayers re-creates the full packet envelope from an already-extracted
// layers map so that getLayerString can be reused without change.
func wrapLayers(layers map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"_source": map[string]interface{}{"layers": layers},
	}
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
	}
	return nil
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

func getEndStreamFlag(stream map[string]interface{}) bool {
	if v, ok := findNestedKey(stream, "http2.flags.end_stream"); ok {
		if s, ok := stringifyLayerValue(v); ok {
			return s == "1" || strings.EqualFold(s, "true")
		}
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

func isRSTStream(entry map[string]interface{}) bool {
	// RST_STREAM is http2.type == 3; it may appear at the entry level or in http2.stream
	for _, target := range []map[string]interface{}{entry} {
		if v, ok := target["http2.type"]; ok {
			if s, ok := stringifyLayerValue(v); ok && s == "3" {
				return true
			}
		}
	}
	if stream, ok := entry["http2.stream"].(map[string]interface{}); ok {
		if v, ok := stream["http2.type"]; ok {
			if s, ok := stringifyLayerValue(v); ok && s == "3" {
				return true
			}
		}
	}
	return false
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
		return nil, fmt.Errorf("odd hex length after colon removal")
	}
	return hex.DecodeString(cleaned)
}

// ---------------------------------------------------------------------------
// V2 additions — frame, timestamp, and endpoint extraction helpers
// ---------------------------------------------------------------------------

func getFrameNumber(layers map[string]interface{}) (int, bool) {
	wrapped := wrapLayers(layers)
	s, ok := getLayerString(wrapped, "frame.number")
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, false
	}
	return n, true
}

// getTimeEpoch returns the raw frame.time_epoch string from tshark — full
// precision decimal with no truncation (spec §9, §10, §11).
func getTimeEpoch(layers map[string]interface{}) (string, bool) {
	wrapped := wrapLayers(layers)
	s, ok := getLayerString(wrapped, "frame.time_epoch")
	if !ok {
		return "", false
	}
	return strings.TrimSpace(s), true
}

func getSrcIP(layers map[string]interface{}) string {
	wrapped := wrapLayers(layers)
	if s, ok := getLayerString(wrapped, "ip.src"); ok && s != "" {
		return s
	}
	if s, ok := getLayerString(wrapped, "ipv6.src"); ok {
		return s
	}
	return ""
}

func getDstIP(layers map[string]interface{}) string {
	wrapped := wrapLayers(layers)
	if s, ok := getLayerString(wrapped, "ip.dst"); ok && s != "" {
		return s
	}
	if s, ok := getLayerString(wrapped, "ipv6.dst"); ok {
		return s
	}
	return ""
}

func getTCPSrcPort(layers map[string]interface{}) int {
	return getIntLayer(layers, "tcp.srcport")
}

func getTCPDstPort(layers map[string]interface{}) int {
	return getIntLayer(layers, "tcp.dstport")
}

func getUDPSrcPort(layers map[string]interface{}) int {
	return getIntLayer(layers, "udp.srcport")
}

func getUDPDstPort(layers map[string]interface{}) int {
	return getIntLayer(layers, "udp.dstport")
}

func getSCTPSrcPort(layers map[string]interface{}) int {
	return getIntLayer(layers, "sctp.srcport")
}

func getSCTPDstPort(layers map[string]interface{}) int {
	return getIntLayer(layers, "sctp.dstport")
}

func getIntLayer(layers map[string]interface{}, key string) int {
	wrapped := wrapLayers(layers)
	s, ok := getLayerString(wrapped, key)
	if !ok {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

// getNGAPLayer returns the ngap sub-layer from a packet's layers.
func getNGAPLayer(layers map[string]interface{}) (map[string]interface{}, bool) {
	raw, ok := layers["ngap"]
	if !ok {
		return nil, false
	}
	switch v := raw.(type) {
	case map[string]interface{}:
		return v, true
	case []interface{}:
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				return m, true
			}
		}
	}
	return nil, false
}

// getNASLayer looks for an embedded NAS-5GS layer within a packet.
func getNASLayer(layers map[string]interface{}) map[string]interface{} {
	for _, key := range []string{"nas-5gs", "nas-eps", "nas_pdu"} {
		if v, ok := layers[key]; ok {
			if m, ok := v.(map[string]interface{}); ok {
				return m
			}
		}
	}
	return nil
}
