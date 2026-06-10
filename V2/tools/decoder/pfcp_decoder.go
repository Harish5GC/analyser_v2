package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// PFCP V2 decoder — spec §11, §12
//
// Writes every PFCP packet as one JSON record per line in messages.jsonl and
// a parallel message_index.jsonl for cheap lookup. Heartbeats are RETAINED
// (spec §11: "must remain in full output"). The raw tshark packet object is
// teed to raw/pfcp.packets.jsonl verbatim when retain-raw is enabled.
//
// The complete tshark pfcp tree is preserved unmodified — no key renaming,
// no field removal, no msg_type translation. That belongs to normalization.
// ---------------------------------------------------------------------------

// PFCPTransport captures the UDP transport addresses for a PFCP packet.
type PFCPTransport struct {
	SrcIP   string `json:"src_ip,omitempty"`
	DstIP   string `json:"dst_ip,omitempty"`
	SrcPort int    `json:"src_port,omitempty"`
	DstPort int    `json:"dst_port,omitempty"`
}

// PFCPRecord is one line in decoder/full/pfcp/messages.jsonl.
type PFCPRecord struct {
	SchemaVersion  string        `json:"schema_version"`
	RecordID       string        `json:"record_id"`
	Protocol       string        `json:"protocol"`
	Frame          int           `json:"frame"`
	TimeEpoch      string        `json:"time_epoch"`
	Transport      PFCPTransport `json:"transport"`
	IsHeartbeat    bool          `json:"is_heartbeat"`
	MsgType        interface{}   `json:"msg_type,omitempty"`
	SeqNum         interface{}   `json:"seq_num,omitempty"`
	SEID           interface{}   `json:"seid,omitempty"`
	ResponseIn     interface{}   `json:"response_in,omitempty"`
	ResponseTo     interface{}   `json:"response_to,omitempty"`
	PFCP           interface{}   `json:"pfcp"` // raw, unmodified tshark pfcp layer
	RawRecordIndex *int64        `json:"raw_record_index,omitempty"`
	DecodeWarnings []string      `json:"decode_warnings,omitempty"`
}

// PFCPIndexEntry is one line in decoder/full/pfcp/message_index.jsonl.
type PFCPIndexEntry struct {
	RecordID    string `json:"record_id"`
	Frame       int    `json:"frame"`
	TimeEpoch   string `json:"time_epoch"`
	SrcIP       string `json:"src_ip,omitempty"`
	DstIP       string `json:"dst_ip,omitempty"`
	IsHeartbeat bool   `json:"is_heartbeat"`
	MsgType     string `json:"msg_type,omitempty"`
	SHA256      string `json:"sha256"`
	ByteSize    int64  `json:"byte_size"`
}

// isPFCPHeartbeat returns true for PFCP Heartbeat Request (msg_type=1) and
// Heartbeat Response (msg_type=2). We detect but NEVER drop heartbeats.
func isPFCPHeartbeat(pfcpLayer map[string]interface{}) bool {
	if pfcpLayer == nil {
		return false
	}
	for _, key := range []string{"pfcp.msg_type", "msg_type"} {
		if v, ok := pfcpLayer[key]; ok {
			if s, ok := stringifyLayerValue(v); ok {
				trimmed := s
				return trimmed == "1" || trimmed == "2"
			}
		}
	}
	if v, ok := findNestedKey(pfcpLayer, "pfcp.msg_type"); ok {
		if s, ok := stringifyLayerValue(v); ok {
			return s == "1" || s == "2"
		}
	}
	return false
}

// decodePFCP runs the PFCP protocol decoder and writes all output artifacts.
// Returns a ProtocolRun describing what was produced (spec §11, §12, §13).
func decodePFCP(ctx context.Context, cfg *DecodeConfig, sink *ArtifactSink, runner *tsharkRunner) ProtocolRun {
	start := time.Now()
	run := ProtocolRun{
		Name: "pfcp",
		Result: ProtocolDecodeResult{
			Status:   "failed",
			Warnings: []DecodeWarning{},
		},
	}

	// ---- open output sinks ------------------------------------------------
	messagesJSONL, err := sink.openJSONL("full/pfcp/messages.jsonl", "pfcp_messages", "pfcp", "application/x-ndjson")
	if err != nil {
		run.Result.Warnings = append(run.Result.Warnings, warnT01("SINK_OPEN", fmt.Sprintf("open messages.jsonl: %v", err)))
		return run
	}

	indexJSONL, err := sink.openJSONL("full/pfcp/message_index.jsonl", "pfcp_message_index", "pfcp", "application/x-ndjson")
	if err != nil {
		run.Result.Warnings = append(run.Result.Warnings, warnT01("SINK_OPEN", fmt.Sprintf("open message_index.jsonl: %v", err)))
		return run
	}

	var rawJSONL *JSONLSink
	if cfg.RetainRaw {
		rawJSONL, err = sink.openJSONL("raw/pfcp.packets.jsonl", "raw_packets", "pfcp", "application/x-ndjson")
		if err != nil {
			run.Result.Warnings = append(run.Result.Warnings, warnT01("RAW_SINK_OPEN", fmt.Sprintf("open raw pfcp: %v", err)))
			// non-fatal: continue without raw retention
		}
	}

	// ---- start tshark stream ----------------------------------------------
	session, err := runner.stream(
		ctx,
		cfg.PCAPPath,
		"pfcp",
		"frame ip ipv6 udp pfcp",
	)
	if err != nil {
		run.Result.Warnings = append(run.Result.Warnings, warnT01("TSHARK_START", err.Error()))
		return run
	}

	// ---- streaming parse loop -------------------------------------------
	var inputPackets, written int64
	dec := session.decoder

	for dec.More() {
		var pkt map[string]interface{}
		if err := dec.Decode(&pkt); err != nil {
			run.Result.Warnings = append(run.Result.Warnings, warnT01("PACKET_DECODE", fmt.Sprintf("frame ~%d: %v", inputPackets+1, err)))
			continue
		}
		inputPackets++

		// Tee raw packet verbatim before any processing (spec §12).
		if rawJSONL != nil {
			if err := rawJSONL.WriteRecord(pkt); err != nil {
				run.Result.Warnings = append(run.Result.Warnings, warnT01("RAW_WRITE", err.Error()))
			}
		}

		layers := getPacketLayers(pkt)
		if layers == nil {
			continue
		}

		pfcpLayer, ok := layers["pfcp"]
		if !ok {
			continue
		}
		pfcpMap, _ := pfcpLayer.(map[string]interface{})

		frame, _ := getFrameNumber(layers)
		timeEpoch, _ := getTimeEpoch(layers)

		// Deterministic record id: stable for the same source + frame (AC#14).
		recordID := deterministicUUID(sink.sourceSHA256, "pfcp", fmt.Sprintf("%d:%d", frame, inputPackets-1))

		rec := PFCPRecord{
			SchemaVersion: SchemaVersion,
			RecordID:      recordID,
			Protocol:      "PFCP",
			Frame:         frame,
			TimeEpoch:     timeEpoch,
			Transport: PFCPTransport{
				SrcIP:   getSrcIP(layers),
				DstIP:   getDstIP(layers),
				SrcPort: getUDPSrcPort(layers),
				DstPort: getUDPDstPort(layers),
			},
			PFCP: pfcpLayer, // raw, unmodified
		}

		if pfcpMap != nil {
			rec.IsHeartbeat = isPFCPHeartbeat(pfcpMap)
			// Extract key PFCP fields raw-as-observed (spec §11).
			if v, ok := findNestedKey(pfcpMap, "pfcp.msg_type"); ok {
				rec.MsgType = v
			}
			if v, ok := findNestedKey(pfcpMap, "pfcp.seq_no"); ok {
				rec.SeqNum = v
			}
			if v, ok := findNestedKey(pfcpMap, "pfcp.seid"); ok {
				rec.SEID = v
			}
			if v, ok := findNestedKey(pfcpMap, "pfcp.response_in"); ok {
				rec.ResponseIn = v
			}
			if v, ok := findNestedKey(pfcpMap, "pfcp.response_to"); ok {
				rec.ResponseTo = v
			}
		}
		if cfg.RetainRaw {
			idx := inputPackets - 1
			rec.RawRecordIndex = &idx
		}

		// Marshal record to get sha256 + byte size for the index entry.
		recBytes, err := json.Marshal(rec)
		if err != nil {
			run.Result.Warnings = append(run.Result.Warnings, warnT01("MARSHAL", fmt.Sprintf("frame %d: %v", frame, err)))
			continue
		}

		// Build index entry from the marshalled record bytes.
		sha256hex := hashBytes(recBytes)
		msgTypeStr := ""
		if rec.MsgType != nil {
			if s, ok := stringifyLayerValue(rec.MsgType); ok {
				msgTypeStr = s
			}
		}

		idxEntry := PFCPIndexEntry{
			RecordID:    recordID,
			Frame:       frame,
			TimeEpoch:   timeEpoch,
			SrcIP:       rec.Transport.SrcIP,
			DstIP:       rec.Transport.DstIP,
			IsHeartbeat: rec.IsHeartbeat,
			MsgType:     msgTypeStr,
			SHA256:      sha256hex,
			ByteSize:    int64(len(recBytes)),
		}

		if err := messagesJSONL.WriteRecord(rec); err != nil {
			run.Result.Warnings = append(run.Result.Warnings, warnT01("WRITE", err.Error()))
			continue
		}
		if err := indexJSONL.WriteRecord(idxEntry); err != nil {
			run.Result.Warnings = append(run.Result.Warnings, warnT01("INDEX_WRITE", err.Error()))
		}
		written++
	}

	// ---- finalise tshark process -----------------------------------------
	waitErr := session.Wait()
	if waitErr != nil && written == 0 {
		run.Result.Warnings = append(run.Result.Warnings, warnT01("TSHARK_EXIT", fmt.Sprintf("tshark non-zero exit: %v", waitErr)))
	}
	if stderr := session.StderrText(); stderr != "" {
		run.Result.Warnings = append(run.Result.Warnings, warnT01("TSHARK_STDERR", truncate(stderr, 512)))
	}

	// ---- close and publish artifacts ------------------------------------
	// Append each artifact immediately after a successful Close so a later close
	// failure never leaves a published-but-unreferenced file in decoder/ (L4).
	publishFailed := false
	if msgDesc, err := messagesJSONL.Close(); err != nil {
		run.Result.Warnings = append(run.Result.Warnings, warnT01("PUBLISH", fmt.Sprintf("messages.jsonl: %v", err)))
		publishFailed = true
	} else {
		run.Artifacts = append(run.Artifacts, msgDesc)
	}
	if idxDesc, err := indexJSONL.Close(); err != nil {
		run.Result.Warnings = append(run.Result.Warnings, warnT01("PUBLISH", fmt.Sprintf("message_index.jsonl: %v", err)))
		publishFailed = true
	} else {
		run.Artifacts = append(run.Artifacts, idxDesc)
	}
	if rawJSONL != nil {
		if rawDesc, err := rawJSONL.Close(); err != nil {
			run.Result.Warnings = append(run.Result.Warnings, warnT01("RAW_PUBLISH", err.Error()))
			publishFailed = true
		} else {
			run.Artifacts = append(run.Artifacts, rawDesc)
		}
	}

	// ---- set status and metrics ------------------------------------------
	run.Result.InputPackets = inputPackets
	run.Result.RecordsWritten = written
	run.Result.ElapsedMS = time.Since(start).Milliseconds()

	switch {
	case inputPackets == 0:
		run.Result.Status = "absent"
	case publishFailed:
		run.Result.Status = "partial"
	case waitErr != nil:
		run.Result.Status = "partial"
	case written == 0:
		run.Result.Status = "partial"
	default:
		run.Result.Status = "success"
	}

	return run
}

// hashBytes returns the sha256 hex digest of b.
func hashBytes(b []byte) string {
	h := sha256Sum(b)
	return h
}
