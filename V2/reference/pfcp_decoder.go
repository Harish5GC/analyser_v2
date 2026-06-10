// Copyright (c) 2026 Harish5GC. All rights reserved.
// Unauthorized copying, distribution, or modification of this file, via any medium,
// is strictly prohibited without prior written permission from Harish5GC.
// No license is granted, and no rights are implied beyond this notice.
//
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

type PFCPDecoder struct {
	PcapPath string
}

func NewPFCPDecoder(pcap string) *PFCPDecoder {
	return &PFCPDecoder{PcapPath: pcap}
}


func RunPFCPDecode(pcapPath, outPath string) error {
	decoder := NewPFCPDecoder(pcapPath)
	fmt.Fprintln(os.Stderr, "[PFCP] Decoding from pcap:", pcapPath)
	if err := decoder.StreamPFCPToJSON(outPath); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "[PFCP] Decode complete. JSON:", outPath)
	return nil
}

func (d *PFCPDecoder) StreamPFCPToJSON(jsonPath string) error {
	cmd := exec.Command(
		"tshark",
		"-r", d.PcapPath,
		"-Y", "pfcp",
		"-T", "json",
		"-J", "frame ip ipv6 udp pfcp",
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
	fmt.Fprintln(os.Stderr, "[PFCPStream] START:", start)

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

	decoder := json.NewDecoder(stdout)
	if _, err := decoder.Token(); err != nil {
		return err
	}

	if _, err := writer.WriteString("["); err != nil {
		return err
	}

	first := true
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
		pfcpLayer, ok := layers["pfcp"].(map[string]interface{})
		if !ok {
			continue
		}
		if isPFCPHeartbeat(pfcpLayer) {
			continue
		}
		pfcpLayer = sanitizePFCPMap(pfcpLayer)
		entry := map[string]interface{}{
			"meta": extractFlowMeta(layers),
			"pfcp": pfcpLayer,
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
		count++
	}

	if _, err := writer.WriteString("\n]\n"); err != nil {
		return err
	}

	if err := cmd.Wait(); err != nil {
		return err
	}

	end := time.Now()
	fmt.Fprintln(os.Stderr, "[PFCPStream] END:", end)
	fmt.Fprintf(os.Stderr, "[PFCPStream] ELAPSED: %v\n", end.Sub(start))
	fmt.Fprintln(os.Stderr, "[PFCPStream] PACKETS:", count)
	fmt.Fprintln(os.Stderr, "[PFCPStream] JSON written:", jsonPath)

	return nil
}

func isPFCPHeartbeat(pfcpLayer map[string]interface{}) bool {
	if pfcpLayer == nil {
		return false
	}
	if v, ok := pfcpLayer["pfcp.msg_type"]; ok {
		if s, ok := stringifyLayerValue(v); ok {
			return s == "1" || s == "2"
		}
	}
	if v, ok := findNestedKey(pfcpLayer, "pfcp.msg_type"); ok {
		if s, ok := stringifyLayerValue(v); ok {
			return s == "1" || s == "2"
		}
	}
	return false
}

func sanitizePFCPMap(input map[string]interface{}) map[string]interface{} {
	if input == nil {
		return nil
	}
	out := make(map[string]interface{}, len(input))
	for key, value := range input {
		if key == "pfcp.ie_len" || key == "pfcp.ie_type" || key == "pfcp.length" || key == "pfcp.flags_tree" || strings.Contains(key, "pfcp.spare") {
			continue
		}
		newKey := strings.ReplaceAll(key, "[Grouped IE]", "")
		newKey = strings.ReplaceAll(newKey, "pfcp.", "")
		newKey = strings.TrimSpace(strings.ReplaceAll(newKey, "  ", " "))
		newKey = strings.ReplaceAll(newKey, " : ", ":")
		newKey = strings.ReplaceAll(newKey, " :", ":")
		newKey = strings.ReplaceAll(newKey, ": ", ":")
		newKey = strings.Trim(newKey, " :")
		if shouldCollapseKeySpaces(newKey) {
			newKey = strings.ReplaceAll(newKey, " ", "")
		}

		if newKey == "length" || newKey == "flags_tree" || newKey == "flags" || newKey == "response_time" {
			continue
		}

		switch v := value.(type) {
		case map[string]interface{}:
			child := sanitizePFCPMap(v)
			if hdr, ok := child["pfcp_outer_hdr_desc"].(map[string]interface{}); ok {
				if flags := buildFlagOnes(hdr); flags != nil {
					child["pfcp_outer_hdr_desc"] = flags
				} else {
					delete(child, "pfcp_outer_hdr_desc")
				}
			}
			if newKey == "fteid_flg" {
				delete(child, "spare")
				if len(child) == 0 {
					continue
				}
			}
			if handled := applySpecialIETransforms(newKey, child, out); handled {
				continue
			}
			out[newKey] = child
		case []interface{}:
			child := sanitizePFCPSlice(v)
			if handled := applySpecialIETransforms(newKey, child, out); handled {
				continue
			}
			out[newKey] = child
		default:
			if handled := applySpecialIETransforms(newKey, v, out); handled {
				continue
			}
			if newKey == "msg_type" {
				if s, ok := stringifyLayerValue(v); ok {
					if name, ok := pfcpMsgTypeName(s); ok {
						out[newKey] = name
						break
					}
				}
			}
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

func applySpecialIETransforms(key string, value interface{}, out map[string]interface{}) bool {
	m, ok := unwrapToMap(value)
	if !ok {
		return false
	}
	keyNoSpaces := strings.ReplaceAll(key, " ", "")
	switch {
	case strings.HasPrefix(keyNoSpaces, "NodeID"):
		if v, ok := m["node_id_ipv4"]; ok {
			out["node_id_ipv4"] = v
			return true
		}
	case strings.HasPrefix(keyNoSpaces, "RecoveryTimeStamp"):
		if v, ok := m["recovery_time_stamp"]; ok {
			out["recovery_time_stamp"] = trimTimestampPFCP(fmt.Sprint(v))
			return true
		}
	case strings.HasPrefix(keyNoSpaces, "Cause"):
		if v, ok := m["cause"]; ok {
			out["cause"] = v
			return true
		}
	case strings.HasPrefix(keyNoSpaces, "APN/DNN"):
		if v, ok := m["apn_dnn"]; ok {
			out["apn_dnn"] = v
			return true
		}
	case strings.HasPrefix(keyNoSpaces, "NetworkInstance"):
		if v, ok := m["network_instance"]; ok {
			out["network_instance"] = v
			return true
		}
	case strings.HasPrefix(keyNoSpaces, "3GPPInterfaceType"):
		if v, ok := m["tgpp_interface_type"]; ok {
			label := enumLabelOrValue("tgpp_interface_type", v)
			out["3gpp_interface_type"] = label
			return true
		}
	case strings.HasPrefix(keyNoSpaces, "DestinationInterface"):
		if v, ok := m["dst_interface"]; ok {
			label := enumLabelOrValue("dst_interface", v)
			out["destination_interface"] = label
			return true
		}
	case keyNoSpaces == "CPFunctionFeatures":
		if v, ok := m["cp_function_features"].(map[string]interface{}); ok {
			if flags := buildFlagOnes(v); flags != nil {
				out[strings.ReplaceAll(key, " ", "")] = flags
			}
			return true
		}
	case keyNoSpaces == "UPFunctionFeatures":
		if v, ok := m["up_function_features"].(map[string]interface{}); ok {
			if flags := buildFlagOnes(v); flags != nil {
				out[strings.ReplaceAll(key, " ", "")] = flags
			}
			return true
		}
	case keyNoSpaces == "UEIPAddress":
		ue := map[string]interface{}{}
		if v, ok := m["ue_ip_addr_ipv4"]; ok {
			ue["ipv4"] = v
		}
		if flags, ok := m["ue_ip_address_flag"].(map[string]interface{}); ok {
			if filtered := buildFlagOnes(flags); filtered != nil {
				ue["flag"] = filtered
			}
		}
		if len(ue) > 0 {
			out[strings.ReplaceAll(key, " ", "")] = ue
			return true
		}
	case keyNoSpaces == "ApplyAction":
		if v, ok := m["apply_action"].(map[string]interface{}); ok {
			if flags := buildFlagOnes(v); flags != nil {
				out[strings.ReplaceAll(key, " ", "")] = flags
			}
			return true
		}
	case keyNoSpaces == "pfcp_outer_hdr_desc":
		if flags := buildFlagOnes(m); flags != nil {
			out[key] = flags
		}
		return true
	case strings.HasPrefix(keyNoSpaces, "BARID"):
		return collapseIDField(out, "bar_id", m)
	case strings.HasPrefix(keyNoSpaces, "FARID"):
		return collapseIDField(out, "far_id", m)
	case strings.HasPrefix(keyNoSpaces, "QERID"):
		return collapseIDField(out, "qer_id", m)
	case strings.HasPrefix(keyNoSpaces, "URRID"):
		return collapseIDField(out, "urr_id", m)
	case strings.HasPrefix(keyNoSpaces, "MARID"):
		return collapseIDField(out, "mar_id", m)
	case strings.HasPrefix(keyNoSpaces, "SRRID"):
		return collapseIDField(out, "srr_id", m)
	}
	return false
}

func unwrapToMap(value interface{}) (map[string]interface{}, bool) {
	if m, ok := value.(map[string]interface{}); ok {
		return m, true
	}
	if list, ok := value.([]interface{}); ok && len(list) == 1 {
		if m, ok := list[0].(map[string]interface{}); ok {
			return m, true
		}
	}
	return nil, false
}

func buildFlagOnes(flags map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(flags))
	for k, v := range flags {
		if s, ok := stringifyLayerValue(v); ok && strings.TrimSpace(s) == "1" {
			out[k] = "1"
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func collapseIDField(out map[string]interface{}, field string, m map[string]interface{}) bool {
	if v, ok := m[field]; ok {
		out[field] = v
		return true
	}
	return false
}

func enumLabelOrValue(field string, val interface{}) string {
	if s, ok := stringifyLayerValue(val); ok {
		if labels, ok := pfcpEnumLabels[field]; ok {
			if label, ok := labels[strings.TrimSpace(s)]; ok {
				return strings.ReplaceAll(label, " ", "")
			}
		}
		return strings.ReplaceAll(s, " ", "")
	}
	return ""
}

var pfcpEnumLabels = map[string]map[string]string{
	"dst_interface": {
		"0": "Access",
		"1": "Core",
		"2": "SGi-LAN/N6-LAN",
		"3": "CP-function",
		"4": "LI function",
	},
	"tgpp_interface_type": {
		"11": "N3 3GPP Access",
		"12": "N3 Trusted Non-3GPP Access",
		"13": "N3 Untrusted Non-3GPP Access",
		"14": "N3 for data forwarding",
		"15": "N9",
		"17": "N6",
	},
}

func shouldCollapseKeySpaces(key string) bool {
	if !strings.Contains(key, " ") || strings.Contains(key, ":") {
		return false
	}
	parts := strings.Fields(key)
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		first := part[0]
		if first < 'A' || first > 'Z' {
			return false
		}
		for i := 0; i < len(part); i++ {
			b := part[i]
			if (b < 'A' || b > 'Z') && (b < 'a' || b > 'z') && (b < '0' || b > '9') {
				return false
			}
		}
	}
	return true
}

func trimTimestampPFCP(value string) string {
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

func sanitizePFCPSlice(input []interface{}) []interface{} {
	out := make([]interface{}, 0, len(input))
	for _, item := range input {
		switch v := item.(type) {
		case map[string]interface{}:
			out = append(out, sanitizePFCPMap(v))
		case []interface{}:
			out = append(out, sanitizePFCPSlice(v))
		default:
			out = append(out, v)
		}
	}
	return out
}

func pfcpMsgTypeName(code string) (string, bool) {
	switch strings.TrimSpace(code) {
	case "1":
		return "HbReq", true
	case "2":
		return "HbRsp", true
	case "3":
		return "PfdMgmtReq", true
	case "4":
		return "PfdMgmtRsp", true
	case "5":
		return "AssocSetupReq", true
	case "6":
		return "AssocSetupRsp", true
	case "7":
		return "AssocUpdateReq", true
	case "8":
		return "AssocUpdateRsp", true
	case "9":
		return "AssocReleaseReq", true
	case "10":
		return "AssocReleaseRsp", true
	case "11":
		return "VerNotSupRsp", true
	case "12":
		return "NodeReportReq", true
	case "13":
		return "NodeReportRsp", true
	case "14":
		return "SessSetDelReq", true
	case "15":
		return "SessSetDelRsp", true
	case "50":
		return "SessEstReq", true
	case "51":
		return "SessEstRsp", true
	case "52":
		return "SessModReq", true
	case "53":
		return "SessModRsp", true
	case "54":
		return "SessDelReq", true
	case "55":
		return "SessDelRsp", true
	case "56":
		return "SessReportReq", true
	case "57":
		return "SessReportRsp", true
	default:
		return "", false
	}
}
