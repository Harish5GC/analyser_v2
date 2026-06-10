// Copyright (c) 2026 Harish5GC. All rights reserved.
// Unauthorized copying, distribution, or modification of this file, via any medium,
// is strictly prohibited without prior written permission from Harish5GC.
// No license is granted, and no rights are implied beyond this notice.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type NGAPDecoder struct {
	PcapPath string
}

func NewNGAPDecoder(pcap string) *NGAPDecoder {
	return &NGAPDecoder{PcapPath: pcap}
}

func RunNGAPDecode(pcapPath, outPath, leanPath string) error {
	decoder := NewNGAPDecoder(pcapPath)
	fmt.Fprintln(os.Stderr, "[NGAP] Decoding from pcap:", pcapPath)
	if err := decoder.StreamNGAPToJSON(outPath, leanPath); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "[NGAP] Decode complete. JSON:", outPath, "Lean JSON:", leanPath)
	return nil
}

func (d *NGAPDecoder) StreamNGAPToJSON(jsonPath, leanPath string) error {
	cmd := exec.Command(
		"tshark",
		"-r", d.PcapPath,
		"-Y", "ngap",
		"-T", "json",
		"-J", "frame ip ipv6 sctp ngap",
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
	fmt.Fprintln(os.Stderr, "[NGAPStream] START:", start)

	if err := cmd.Start(); err != nil {
		return err
	}

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			fmt.Fprintln(os.Stderr, "[tshark]", scanner.Text())
		}
	}()

	out, err := os.Create(jsonPath)
	if err != nil {
		return err
	}
	defer out.Close()

	writer := bufio.NewWriter(out)
	defer writer.Flush()

	var leanWriter *bufio.Writer
	var leanOut *os.File
	if leanPath != "" {
		leanOut, err = os.Create(leanPath)
		if err != nil {
			return err
		}
		defer leanOut.Close()
		leanWriter = bufio.NewWriter(leanOut)
		defer leanWriter.Flush()
	}

	decoder := json.NewDecoder(stdout)
	if _, err := decoder.Token(); err != nil {
		return err
	}

	if _, err := writer.WriteString("["); err != nil {
		return err
	}
	if leanWriter != nil {
		if _, err := leanWriter.WriteString("["); err != nil {
			return err
		}
	}

	first := true
	leanFirst := true
	count := 0
	for decoder.More() {
		var pkt map[string]interface{}
		if err := decoder.Decode(&pkt); err != nil {
			fmt.Fprintln(os.Stderr, "Decode error:", err)
			continue
		}
		layers := getPacketLayers(pkt)
		if layers == nil {
			continue
		}
		ngapLayer, ok := getNGAPLayer(layers)
		if !ok || ngapLayer == nil {
			continue
		}
		fullLayer := sanitizeNGAPMapFull(ngapLayer)
		leanLayer := stripPERBlocksMap(fullLayer)
		meta := extractFlowMeta(layers)
		entry := map[string]interface{}{
			"meta": meta,
			"ngap": fullLayer,
		}

		b, err := json.Marshal(entry)
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
		if _, err := writer.Write(b); err != nil {
			return err
		}

		if leanWriter != nil {
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
			leanEntry := map[string]interface{}{
				"meta": meta,
				"ngap": leanLayer,
			}
			leanBytes, err := json.Marshal(leanEntry)
			if err != nil {
				return err
			}
			if _, err := leanWriter.Write(leanBytes); err != nil {
				return err
			}
		}

		count++
	}

	if _, err := writer.WriteString("\n]\n"); err != nil {
		return err
	}
	if leanWriter != nil {
		if _, err := leanWriter.WriteString("\n]\n"); err != nil {
			return err
		}
	}

	if err := cmd.Wait(); err != nil {
		return err
	}

	end := time.Now()
	fmt.Fprintln(os.Stderr, "[NGAPStream] END:", end)
	fmt.Fprintf(os.Stderr, "[NGAPStream] ELAPSED: %v\n", end.Sub(start))
	fmt.Fprintln(os.Stderr, "[NGAPStream] PACKETS:", count)
	fmt.Fprintln(os.Stderr, "[NGAPStream] JSON written:", jsonPath)
	if leanPath != "" {
		fmt.Fprintln(os.Stderr, "[NGAPStream] Lean JSON written:", leanPath)
	}

	return nil
}

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

func sanitizeNGAPMapFull(input map[string]interface{}) map[string]interface{} {
	if input == nil {
		return nil
	}
	out := make(map[string]interface{}, len(input))
	for key, value := range input {
		newKey := strings.ReplaceAll(key, "[Grouped IE]", "")
		newKey = strings.ReplaceAll(newKey, "ngap.", "")
		newKey = strings.TrimSpace(strings.ReplaceAll(newKey, "  ", " "))
		newKey = strings.ReplaceAll(newKey, " : ", ":")
		newKey = strings.ReplaceAll(newKey, " :", ":")
		newKey = strings.ReplaceAll(newKey, ": ", ":")
		newKey = strings.Trim(newKey, " :")

		switch v := value.(type) {
		case map[string]interface{}:
			out[newKey] = sanitizeNGAPMapFull(v)
		case []interface{}:
			out[newKey] = sanitizeNGAPSliceFull(v)
		default:
			if dot := strings.IndexByte(newKey, '.'); dot != -1 {
				prefix := newKey[:dot]
				field := newKey[dot+1:]
				if prefix == "" || field == "" {
					out[newKey] = v
					break
				}
				group, ok := out[prefix].(map[string]interface{})
				if !ok || group == nil {
					group = map[string]interface{}{}
					out[prefix] = group
				}
				group[field] = v
			} else {
				out[newKey] = v
			}
		}
	}
	return out
}

func sanitizeNGAPSliceFull(input []interface{}) []interface{} {
	out := make([]interface{}, 0, len(input))
	for _, item := range input {
		switch v := item.(type) {
		case map[string]interface{}:
			out = append(out, sanitizeNGAPMapFull(v))
		case []interface{}:
			out = append(out, sanitizeNGAPSliceFull(v))
		default:
			out = append(out, v)
		}
	}
	return out
}

func stripPERBlocksMap(input map[string]interface{}) map[string]interface{} {
	if input == nil {
		return nil
	}
	out := make(map[string]interface{}, len(input))
	for key, value := range input {
		key = mapLeanKey(key)
		lower := strings.ToLower(key)
		if shouldDropLeanKey(lower) {
			continue
		}
		if s, ok := value.(string); ok {
			if shouldDropColonValue(key, s) {
				continue
			}
		}
		if lower == "criticality" {
			if s, ok := stringifyLayerValue(value); ok && strings.TrimSpace(s) == "0" {
				continue
			}
		}
		if lower == "protocolies" {
			continue
		}
		if lower == "protocolies_tree" {
			if v, ok := value.(map[string]interface{}); ok {
				out["protocolIEs"] = stripPERBlocksMap(v)
			} else if v, ok := value.([]interface{}); ok {
				out["protocolIEs"] = stripPERBlocksSlice(v)
			}
			continue
		}
		if strings.EqualFold(key, "ProtocolIE_Field_element") {
			if v, ok := value.(map[string]interface{}); ok {
				flattened := stripPERBlocksMap(v)
				for fk, fv := range flattened {
					out[fk] = fv
				}
			}
			continue
		}
		switch v := value.(type) {
		case map[string]interface{}:
			cleaned := stripPERBlocksMap(v)
			if filtered, ok := filterFlagOnes(cleaned); ok {
				if len(filtered) == 0 {
					continue
				}
				out[key] = filtered
				continue
			}
			out[key] = cleaned
		case []interface{}:
			out[key] = stripPERBlocksSlice(v)
		default:
			out[key] = v
		}
	}
	return out
}

func stripPERBlocksSlice(input []interface{}) []interface{} {
	out := make([]interface{}, 0, len(input))
	for _, item := range input {
		switch v := item.(type) {
		case map[string]interface{}:
			out = append(out, stripPERBlocksMap(v))
		case []interface{}:
			out = append(out, stripPERBlocksSlice(v))
		default:
			out = append(out, v)
		}
	}
	return out
}

func filterFlagOnes(flags map[string]interface{}) (map[string]interface{}, bool) {
	if flags == nil || len(flags) == 0 {
		return nil, false
	}
	out := make(map[string]interface{}, len(flags))
	eligible := true
	for k, v := range flags {
		lower := strings.ToLower(k)
		if strings.Contains(lower, "reserved") || strings.Contains(lower, "spare") {
			continue
		}
		on, ok := normalizeFlagValue(v)
		if !ok {
			eligible = false
			break
		}
		if on {
			out[k] = "1"
		}
	}
	if !eligible {
		return nil, false
	}
	return out, true
}

func normalizeFlagValue(value interface{}) (bool, bool) {
	switch v := value.(type) {
	case string:
		if v == "0" {
			return false, true
		}
		if v == "1" {
			return true, true
		}
		return false, false
	case float64:
		if v == 0 {
			return false, true
		}
		if v == 1 {
			return true, true
		}
		return false, false
	default:
		return false, false
	}
}

func shouldDropLeanKey(lower string) bool {
	if lower == "per" || strings.HasPrefix(lower, "per.") {
		return true
	}
	if lower == "nas_pdu" || lower == "nas_pdu_tree" {
		return true
	}
	if lower == "pdusessionnas_pdu" || lower == "pdusessionnas_pdu_tree" {
		return true
	}
	if lower == "pdu_session_nas_pdu" || lower == "pdu_session_nas_pdu_tree" {
		return true
	}
	if strings.Contains(lower, "nas-pdu") {
		return true
	}
	if lower == "nas-5gs" || lower == "nas-eps" {
		return true
	}
	if strings.Contains(lower, "plain nas") || strings.Contains(lower, "security protected nas") {
		return true
	}
	if strings.Contains(lower, "encrypted data") {
		return true
	}
	return false
}

func mapLeanKey(key string) string {
	if key == "initiatingMessage_element" {
		return "initMsgElemt"
	}
	if key == "initiatingMessagevalue_element" {
		return "initMsgValElemt"
	}
	if key == "successfulOutcome_element" {
		return "succOutElemt"
	}
	if key == "unsuccessfulOutcome_element" {
		return "unsuccOutElemt"
	}
	if strings.Contains(key, "Uplink") {
		return strings.ReplaceAll(key, "Uplink", "UL")
	}
	if strings.Contains(key, "Downlink") {
		return strings.ReplaceAll(key, "Downlink", "DL")
	}
	return key
}

func shouldDropColonValue(key, value string) bool {
	if value == "" {
		return false
	}
	if key == "time" {
		return false
	}
	s := strings.TrimSpace(value)
	if !strings.Contains(s, ":") {
		return false
	}
	parts := strings.Split(s, ":")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if !isHexDigit(r) {
				return false
			}
		}
	}
	return true
}

func isHexDigit(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}
