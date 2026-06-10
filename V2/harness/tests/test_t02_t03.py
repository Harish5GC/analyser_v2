from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from harness.decoder.manifest import (
    ArtifactDescriptor,
    CollectionDescriptor,
    CollectionMemberDescriptor,
    DecodeWarning,
    DecoderInfo,
    DecoderManifest,
    ProtocolDecodeResult,
)
from harness.decoder.runner import DecodeCaptureResult
from harness.identity import BuildIdentityGraphRequest, build_identity_graph
from harness.normalize import NormalizeEventsRequest, normalize_events, open_primary_event_reader
from harness.shared import CaptureMetadata, ProtocolCodepointRegistry, ResolvedPolicy, sha256_file


class NormalizeAndIdentityGraphTests(unittest.TestCase):
    def test_normalize_and_build_identity_graph(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            decode_result = self._build_decoder_run(run_dir)

            normalized = normalize_events(
                NormalizeEventsRequest(
                    analysis_id=decode_result.analysis_id,
                    decoder_result=decode_result,
                    run_dir=run_dir,
                    normalized_dir=run_dir / "normalized",
                    indexes_dir=run_dir / "indexes",
                    protocol_registry=ProtocolCodepointRegistry(
                        registry_name="5g_nas_ngap_pfcp",
                        registry_version="2026-06-10",
                        schema_version="2.0",
                        sha256="registry-sha",
                        nas_message_types={"65": "REGISTRATION_REQUEST"},
                        ngap_procedures={"14": "INITIAL_UE_MESSAGE"},
                        pfcp_message_types={"50": "SESSION_ESTABLISHMENT_REQUEST"},
                    ),
                    partition_policy=ResolvedPolicy(
                        name="dependency-partitions",
                        version="2026-06-10",
                        sha256="partition-sha",
                        payload={"udr_apis": ["nudr-dr"]},
                    ),
                    policy_versions={
                        "protocol_registry": "2026-06-10",
                        "partition_policy": "2026-06-10",
                    },
                )
            )

            self.assertEqual(normalized.status, "success")
            self.assertEqual(normalized.event_count, 4)
            self.assertEqual(normalized.partition_counts["primary"], 3)
            self.assertEqual(normalized.partition_counts["udr"], 1)
            self.assertEqual(normalized.protocol_counts["HTTP2"], 1)
            self.assertEqual(normalized.protocol_counts["NGAP"], 1)
            self.assertEqual(normalized.protocol_counts["NAS"], 1)
            self.assertEqual(normalized.protocol_counts["PFCP"], 1)

            primary_reader = open_primary_event_reader(normalized)
            self.assertEqual(len(list(primary_reader.by_frame(1, 100))), 3)
            self.assertEqual(len(list(primary_reader.by_protocol("NAS"))), 1)

            graph = build_identity_graph(
                BuildIdentityGraphRequest(
                    analysis_id=decode_result.analysis_id,
                    normalization=normalized,
                    primary_reader=primary_reader,
                    capture=CaptureMetadata(
                        first_frame=1,
                        last_frame=100,
                        first_timestamp=None,
                        last_timestamp=None,
                        packet_count=30,
                        source_sha256=decode_result.source.sha256,
                    ),
                    run_dir=run_dir,
                    identity_dir=run_dir / "normalized" / "identity",
                    indexes_dir=run_dir / "indexes",
                    identity_rules=ResolvedPolicy(
                        name="identity-rules",
                        version="2026-06-10",
                        sha256="identity-sha",
                        payload={"sensitive_identifier_kinds": ["suci"]},
                    ),
                    topology_rules=ResolvedPolicy(
                        name="topology-rules",
                        version="2026-06-10",
                        sha256="topology-sha",
                        payload={},
                    ),
                    masking_policy=ResolvedPolicy(
                        name="masking-policy",
                        version="2026-06-10",
                        sha256="masking-sha",
                        payload={"salt": "unit-test-salt"},
                    ),
                    policy_versions={
                        "identity_rules": "2026-06-10",
                        "topology_rules": "2026-06-10",
                        "masking_policy": "2026-06-10",
                    },
                )
            )

            self.assertEqual(graph.status, "success")
            self.assertGreaterEqual(graph.observation_count, 10)
            self.assertEqual(graph.ue_nodes, 1)
            self.assertEqual(graph.access_context_nodes, 1)
            self.assertEqual(graph.pdu_session_nodes, 1)
            self.assertGreaterEqual(graph.pfcp_session_nodes, 1)
            self.assertGreater(graph.accepted_edges, 0)
            self.assertEqual(graph.conflicts, 0)

    def _build_decoder_run(self, run_dir: Path) -> DecodeCaptureResult:
        source_dir = run_dir / "source"
        decoder_dir = run_dir / "decoder"
        http2_streams_dir = decoder_dir / "full" / "http2" / "streams"
        ngap_dir = decoder_dir / "full" / "ngap"
        pfcp_dir = decoder_dir / "full" / "pfcp"
        for directory in (source_dir, http2_streams_dir, ngap_dir, pfcp_dir):
            directory.mkdir(parents=True, exist_ok=True)

        capture_path = source_dir / "capture.pcap"
        capture_path.write_bytes(b"pcap-data")
        source_desc = ArtifactDescriptor(
            artifact_id=str(uuid4()),
            relative_path="source/capture.pcap",
            artifact_type="source_pcap",
            protocol=None,
            media_type="application/vnd.tcpdump.pcap",
            format_schema_version="2.0",
            sha256=sha256_file(capture_path),
            byte_size=capture_path.stat().st_size,
            record_count=None,
            creation_stage="T01",
            parent_source_sha256=None,
            revision=None,
        )

        http2_doc_id = str(uuid4())
        http2_doc_path = http2_streams_dir / f"{http2_doc_id}.json"
        http2_doc = {
            "schema_version": "2.0",
            "document_id": http2_doc_id,
            "protocol": "HTTP2",
            "transport": {
                "tcp_stream": 1,
                "http2_stream_id": 1,
                "original_key": "1:1",
                "client": {"ip": "10.0.0.1", "port": 1234},
                "server": {"ip": "10.0.0.2", "port": 443},
            },
            "request": {
                "start_frame": 10,
                "end_frame": 10,
                "start_time_epoch": "1.000001",
                "end_time_epoch": "1.000001",
                "headers": [
                    {"name": ":method", "value": "GET", "frame": 10},
                    {"name": ":path", "value": "/nudr-dr/v1/subscription-data/imsi-001", "frame": 10},
                ],
                "method": "GET",
                "uri": "https://udr.example/nudr-dr/v1/subscription-data/imsi-001",
            },
            "response": {
                "start_frame": 11,
                "end_frame": 11,
                "start_time_epoch": "1.000100",
                "end_time_epoch": "1.000100",
                "headers": [{"name": ":status", "value": "200", "frame": 11}],
                "status": 200,
            },
            "completion": {
                "state": "complete",
                "request_end_stream": True,
                "response_end_stream": True,
                "rst_stream": False,
                "capture_truncated": False,
                "warnings": [],
            },
            "source_frames": [10, 11],
        }
        http2_doc_path.write_text(json.dumps(http2_doc, indent=2), encoding="utf-8")
        http2_member = CollectionMemberDescriptor(
            relative_path=f"decoder/full/http2/streams/{http2_doc_id}.json",
            sha256=sha256_file(http2_doc_path),
            byte_size=http2_doc_path.stat().st_size,
            record_count=None,
            artifact_type="http2_stream_document",
            media_type="application/json",
            format_schema_version="2.0",
        )
        http2_index_path = decoder_dir / "full" / "http2" / "stream_index.jsonl"
        http2_index_record = {
            "document_id": http2_doc_id,
            "relative_path": http2_member.relative_path,
            "tcp_stream": 1,
            "http2_stream_id": 1,
            "original_key": "1:1",
            "first_frame": 10,
            "last_frame": 11,
            "completion_state": "complete",
            "sha256": http2_member.sha256,
            "byte_size": http2_member.byte_size,
        }
        http2_index_path.write_text(json.dumps(http2_index_record) + "\n", encoding="utf-8")
        http2_index_desc = ArtifactDescriptor(
            artifact_id=str(uuid4()),
            relative_path="decoder/full/http2/stream_index.jsonl",
            artifact_type="http2_stream_index",
            protocol="http2",
            media_type="application/x-ndjson",
            format_schema_version="2.0",
            sha256=sha256_file(http2_index_path),
            byte_size=http2_index_path.stat().st_size,
            record_count=1,
            creation_stage="T01",
            parent_source_sha256=source_desc.sha256,
            revision=None,
        )
        members_sha = self._members_digest([http2_member.sha256])
        http2_collection = CollectionDescriptor(
            collection_id=str(uuid4()),
            relative_dir="decoder/full/http2/streams",
            artifact_type="http2_stream_collection",
            index_artifact=http2_index_desc,
            member_count=1,
            members_sha256=members_sha,
            members=[http2_member],
            parent_source_sha256=source_desc.sha256,
            revision=None,
        )

        ngap_record_path = ngap_dir / "messages.jsonl"
        ngap_record = {
            "schema_version": "2.0",
            "record_id": str(uuid4()),
            "protocol": "NGAP",
            "frame": 20,
            "time_epoch": "2.000001",
            "transport": {
                "src_ip": "192.0.2.1",
                "dst_ip": "192.0.2.2",
                "src_port": 38412,
                "dst_port": 38412,
            },
            "ngap": {
                "initiatingMessage": {
                    "procedureCode": "14",
                    "AMF-UE-NGAP-ID": "100",
                    "RAN-UE-NGAP-ID": "200",
                    "PDU-Session-ID": "7",
                }
            },
            "nas": {
                "message_type": "65",
                "suci": "suci-001",
                "pdu_session_id": "7",
            },
        }
        ngap_record_path.write_text(json.dumps(ngap_record) + "\n", encoding="utf-8")
        ngap_desc = ArtifactDescriptor(
            artifact_id=str(uuid4()),
            relative_path="decoder/full/ngap/messages.jsonl",
            artifact_type="ngap_messages",
            protocol="ngap",
            media_type="application/x-ndjson",
            format_schema_version="2.0",
            sha256=sha256_file(ngap_record_path),
            byte_size=ngap_record_path.stat().st_size,
            record_count=1,
            creation_stage="T01",
            parent_source_sha256=source_desc.sha256,
            revision=None,
        )

        pfcp_record_path = pfcp_dir / "messages.jsonl"
        pfcp_record = {
            "schema_version": "2.0",
            "record_id": str(uuid4()),
            "protocol": "PFCP",
            "frame": 30,
            "time_epoch": "3.000001",
            "transport": {
                "src_ip": "198.51.100.1",
                "dst_ip": "198.51.100.2",
                "src_port": 8805,
                "dst_port": 8805,
            },
            "is_heartbeat": False,
            "msg_type": "50",
            "seq_num": "9",
            "pfcp": {
                "cpseid": "cp-seid-1",
                "ueip": "198.51.100.10",
                "pdu_session_id": "7",
            },
        }
        pfcp_record_path.write_text(json.dumps(pfcp_record) + "\n", encoding="utf-8")
        pfcp_desc = ArtifactDescriptor(
            artifact_id=str(uuid4()),
            relative_path="decoder/full/pfcp/messages.jsonl",
            artifact_type="pfcp_messages",
            protocol="pfcp",
            media_type="application/x-ndjson",
            format_schema_version="2.0",
            sha256=sha256_file(pfcp_record_path),
            byte_size=pfcp_record_path.stat().st_size,
            record_count=1,
            creation_stage="T01",
            parent_source_sha256=source_desc.sha256,
            revision=None,
        )

        analysis_id = uuid4()
        manifest = DecoderManifest(
            schema_version="2.0",
            analysis_id=str(analysis_id),
            status="success",
            revision="sha256:test-t01",
            enabled_capabilities=[],
            policy_versions={},
            decoder=DecoderInfo(
                name="5g_call",
                version="test",
                go_version="go1.test",
                tshark_version="4.4.test",
            ),
            source=source_desc,
            protocols={
                "http2": ProtocolDecodeResult(status="success", input_packets=2, records_written=1, elapsed_ms=1, warnings=[]),
                "ngap": ProtocolDecodeResult(status="success", input_packets=1, records_written=1, elapsed_ms=1, warnings=[]),
                "pfcp": ProtocolDecodeResult(status="success", input_packets=1, records_written=1, elapsed_ms=1, warnings=[]),
            },
            artifacts=[ngap_desc, pfcp_desc],
            collections=[http2_collection],
            warnings=[],
            started_at="2026-06-10T00:00:00Z",
            completed_at="2026-06-10T00:00:01Z",
            elapsed_ms=1,
        )
        manifest_path = decoder_dir / "decoder_manifest.json"
        manifest_path.write_text(json.dumps(manifest.model_dump(mode="json", exclude_none=True), indent=2), encoding="utf-8")

        manifest_desc = ArtifactDescriptor(
            artifact_id=str(uuid4()),
            relative_path="decoder/decoder_manifest.json",
            artifact_type="decoder_manifest",
            protocol=None,
            media_type="application/json",
            format_schema_version="2.0",
            sha256=sha256_file(manifest_path),
            byte_size=manifest_path.stat().st_size,
            record_count=1,
            creation_stage="T01",
            parent_source_sha256=source_desc.sha256,
            revision=manifest.revision,
        )

        return DecodeCaptureResult(
            analysis_id=analysis_id,
            status="success",
            revision=manifest.revision,
            source=source_desc,
            manifest=manifest_desc,
            protocols=manifest.protocols,
            artifacts=manifest.artifacts,
            collections=manifest.collections,
            decoder_version="test",
            tshark_version="4.4.test",
            started_at=datetime.now(tz=timezone.utc),
            completed_at=datetime.now(tz=timezone.utc),
            elapsed_ms=1,
            warnings=[],
            manifest_path=manifest_path,
        )

    def _members_digest(self, digests: list[str]) -> str:
        import hashlib

        hasher = hashlib.sha256()
        for digest in digests:
            hasher.update(digest.encode("utf-8"))
            hasher.update(b"\n")
        return hasher.hexdigest()


if __name__ == "__main__":
    unittest.main()
