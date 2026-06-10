package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// NGAP V2 decoder — spec §10, §12
//
// Writes every NGAP packet as one JSON record per line in messages.jsonl and
// a parallel message_index.jsonl. The complete tshark ngap tree (including
// embedded NAS) is preserved verbatim — no key stripping, no PER block
// removal, no NAS-PDU drops. That belongs to normalization (T02+).
//
// Raw tshark packets are teed to raw/ngap.packets.jsonl when enabled.
// ---------------------------------------------------------------------------

// NGAPTransport captures SCTP transport addresses for an NGAP packet.
type NGAPTransport struct {
	SrcIP   string `json:"src_ip,omitempty"`
	DstIP   string `json:"dst_ip,omitempty"`
	SrcPort int    `json:"src_port,omitempty"`
	DstPort int    `json:"dst_port,omitempty"`
}

// NGAPRecord is one line in decoder/full/ngap/messages.jsonl.
type NGAPRecord struct {
	SchemaVersion  string        `json:"schema_version"`
	RecordID       string        `json:"record_id"`
	Protocol       string        `json:"protocol"`
	Frame          int           `json:"frame"`
	TimeEpoch      string        `json:"time_epoch"`
	Transport      NGAPTransport `json:"transport"`
	NGAP           interface{}   `json:"ngap"`          // complete, unmodified tshark ngap tree (map or array of PDUs)
	NAS            interface{}   `json:"nas,omitempty"` // embedded NAS tree when tshark exposes it top-level
	RawRecordIndex *int64        `json:"raw_record_index,omitempty"`
	DecodeWarnings []string      `json:"decode_warnings,omitempty"`
}

// NGAPIndexEntry is one line in decoder/full/ngap/message_index.jsonl.
type NGAPIndexEntry struct {
	RecordID  string `json:"record_id"`
	Frame     int    `json:"frame"`
	TimeEpoch string `json:"time_epoch"`
	SrcIP     string `json:"src_ip,omitempty"`
	DstIP     string `json:"dst_ip,omitempty"`
	SHA256    string `json:"sha256"`
	ByteSize  int64  `json:"byte_size"`
}

// decodeNGAP runs the NGAP/NAS protocol decoder and writes all output
// artifacts. Returns a ProtocolRun describing what was produced.
func decodeNGAP(ctx context.Context, cfg *DecodeConfig, sink *ArtifactSink, runner *tsharkRunner) ProtocolRun {
	start := time.Now()
	run := ProtocolRun{
		Name: "ngap",
		Result: ProtocolDecodeResult{
			Status:   "failed",
			Warnings: []DecodeWarning{},
		},
	}

	// ---- open output sinks -----------------------------------------------
	messagesJSONL, err := sink.openJSONL("full/ngap/messages.jsonl", "ngap_messages", "ngap", "application/x-ndjson")
	if err != nil {
		run.Result.Warnings = append(run.Result.Warnings, warnT01("SINK_OPEN", fmt.Sprintf("open messages.jsonl: %v", err)))
		return run
	}

	indexJSONL, err := sink.openJSONL("full/ngap/message_index.jsonl", "ngap_message_index", "ngap", "application/x-ndjson")
	if err != nil {
		run.Result.Warnings = append(run.Result.Warnings, warnT01("SINK_OPEN", fmt.Sprintf("open message_index.jsonl: %v", err)))
		return run
	}

	var rawJSONL *JSONLSink
	if cfg.RetainRaw {
		rawJSONL, err = sink.openJSONL("raw/ngap.packets.jsonl", "raw_packets", "ngap", "application/x-ndjson")
		if err != nil {
			run.Result.Warnings = append(run.Result.Warnings, warnT01("RAW_SINK_OPEN", fmt.Sprintf("open raw ngap: %v", err)))
		}
	}

	// ---- start tshark stream ---------------------------------------------
	// Use the same field set as the reference (-J frame ip ipv6 sctp ngap),
	// adding nas-5gs to ensure NAS trees are included.
	session, err := runner.stream(
		ctx,
		cfg.PCAPPath,
		"ngap",
		"frame ip ipv6 sctp ngap nas-5gs",
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

		// Tee raw packet verbatim (spec §12).
		if rawJSONL != nil {
			if err := rawJSONL.WriteRecord(pkt); err != nil {
				run.Result.Warnings = append(run.Result.Warnings, warnT01("RAW_WRITE", err.Error()))
			}
		}

		layers := getPacketLayers(pkt)
		if layers == nil {
			continue
		}

		// Presence check; the stored value is the raw ngap layer, which may be
		// a single object or an array of bundled PDUs — preserve all of it (L1).
		if _, ok := getNGAPLayer(layers); !ok {
			continue
		}

		frame, _ := getFrameNumber(layers)
		timeEpoch, _ := getTimeEpoch(layers)
		// Deterministic record id: stable for the same source + frame (AC#14).
		recordID := deterministicUUID(sink.sourceSHA256, "ngap", fmt.Sprintf("%d:%d", frame, inputPackets-1))

		rec := NGAPRecord{
			SchemaVersion: SchemaVersion,
			RecordID:      recordID,
			Protocol:      "NGAP",
			Frame:         frame,
			TimeEpoch:     timeEpoch,
			Transport: NGAPTransport{
				SrcIP:   getSrcIP(layers),
				DstIP:   getDstIP(layers),
				SrcPort: getSCTPSrcPort(layers),
				DstPort: getSCTPDstPort(layers),
			},
			NGAP: layers["ngap"], // complete, unmodified — all bundled PDUs (spec §10)
		}
		if cfg.RetainRaw {
			idx := inputPackets - 1
			rec.RawRecordIndex = &idx
		}

		// Retain embedded NAS (spec §10: "preserve embedded NAS tree").
		if nasLayer := getNASLayer(layers); nasLayer != nil {
			rec.NAS = nasLayer
		}

		recBytes, err := json.Marshal(rec)
		if err != nil {
			run.Result.Warnings = append(run.Result.Warnings, warnT01("MARSHAL", fmt.Sprintf("frame %d: %v", frame, err)))
			continue
		}

		sha256hex := hashBytes(recBytes)
		idxEntry := NGAPIndexEntry{
			RecordID:  recordID,
			Frame:     frame,
			TimeEpoch: timeEpoch,
			SrcIP:     rec.Transport.SrcIP,
			DstIP:     rec.Transport.DstIP,
			SHA256:    sha256hex,
			ByteSize:  int64(len(recBytes)),
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

	// ---- finalise tshark process ----------------------------------------
	waitErr := session.Wait()
	if waitErr != nil && written == 0 {
		run.Result.Warnings = append(run.Result.Warnings, warnT01("TSHARK_EXIT", fmt.Sprintf("tshark non-zero: %v", waitErr)))
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
		// Some artifacts failed to publish; if the core messages file is missing
		// there is nothing usable, otherwise it is a recoverable partial.
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
