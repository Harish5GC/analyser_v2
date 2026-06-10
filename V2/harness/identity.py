"""T03 build_identity_graph implementation."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, DefaultDict, Iterable, Iterator, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from harness.decoder.manifest import ArtifactDescriptor, CollectionDescriptor
from harness.normalize import JsonlPrimaryEventReader, NormalizeEventsResult
from harness.shared import (
    CanonicalEvent,
    CaptureMetadata,
    Issue,
    JsonArtifactWriter,
    JsonlArtifactWriter,
    ResolvedPolicy,
    SourceRef,
    compact_json_bytes,
    deterministic_uuid,
    mask_identifier,
    publish_closed_artifacts,
    sample_issues,
    sha256_bytes,
    sha256_file,
    validate_inside_run,
)

SCHEMA_VERSION = "2.0"
GRAPH_VERSION = "2.0.0"

IdentityNodeType = Literal["UE", "PDU_SESSION", "ACCESS_CONTEXT", "SM_CONTEXT", "PFCP_SESSION"]
IdentityObservationRole = Literal["UE", "SESSION", "ACCESS_CONTEXT", "USER_PLANE", "TRANSACTION"]


class IdentityGraphConfig(BaseModel):
    supporting_signal_window_seconds: Decimal = Decimal("5")
    supporting_signal_window_frames: int = 200
    context_idle_timeout_seconds: Decimal = Decimal("30")
    context_idle_timeout_frames: int = 2000
    max_candidate_edges_per_observation: int = 20
    auto_link_threshold: Decimal = Decimal("0.90")
    warning_link_threshold: Decimal = Decimal("0.70")
    max_issue_samples_per_code: int = 20
    fsync_outputs: bool = True


class BuildIdentityGraphRequest(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    normalization: NormalizeEventsResult
    primary_reader: JsonlPrimaryEventReader
    capture: CaptureMetadata
    run_dir: Path
    identity_dir: Path
    indexes_dir: Path
    identity_rules: ResolvedPolicy
    topology_rules: ResolvedPolicy
    masking_policy: ResolvedPolicy
    enabled_capabilities: set[str] = Field(default_factory=set)
    policy_versions: dict[str, str] = Field(default_factory=dict)
    config: IdentityGraphConfig = Field(default_factory=IdentityGraphConfig)


class BuildIdentityGraphResult(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    status: Literal["success", "partial", "failed"]
    revision: str
    manifest: ArtifactDescriptor
    artifacts: list[ArtifactDescriptor]
    collections: list[CollectionDescriptor] = Field(default_factory=list)
    observation_count: int
    ue_nodes: int
    pdu_session_nodes: int
    access_context_nodes: int
    sm_context_nodes: int
    pfcp_session_nodes: int
    accepted_edges: int
    ambiguous_edges: int
    conflicts: int
    registration_state_intervals: int
    topology_intervals: int
    fault_domain_maps: int
    warning_counts: dict[str, int]
    elapsed_ms: int
    issues: list[Issue]
    manifest_path: Path


class IdentifierObservation(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    observation_id: UUID
    event_id: UUID
    frame: int
    timestamp: Decimal | None = None
    timestamp_precision: Literal["seconds", "milliseconds", "microseconds", "nanoseconds", "unknown"]
    kind: str
    node_type: IdentityNodeType
    lookup_value: str
    sensitive: bool
    scope_key: str
    field_path: str
    raw_refs: list[SourceRef] = Field(default_factory=list)
    role: IdentityObservationRole
    confidence: Decimal
    valid_from_frame: int
    valid_to_frame: int | None = None
    provisional: bool = False


class IdentityNode(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    node_id: UUID
    node_type: IdentityNodeType
    first_frame: int
    last_frame: int
    first_timestamp: Decimal | None = None
    last_timestamp: Decimal | None = None
    provisional: bool = False
    incomplete_history: bool = False
    observation_ids: list[UUID] = Field(default_factory=list)
    accepted_edge_ids: list[UUID] = Field(default_factory=list)
    association_edge_ids: list[UUID] = Field(default_factory=list)
    display_alias: str | None = None


class IdentityEdge(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    edge_id: UUID
    left_observation_id: UUID
    right_observation_id: UUID
    left_node_type: IdentityNodeType
    right_node_type: IdentityNodeType
    left_node_id: UUID | None = None
    right_node_id: UUID | None = None
    relation: str
    strength: Literal["exact", "strong", "supporting"]
    edge_effect: Literal["union_same_type", "associate_nodes"]
    confidence: Decimal
    score_terms: list[dict[str, Any]] = Field(default_factory=list)
    rule_id: str
    reason_codes: list[str] = Field(default_factory=list)
    supporting_event_ids: list[UUID] = Field(default_factory=list)
    valid_from_frame: int
    valid_to_frame: int | None = None
    decision: Literal["accepted", "accepted_with_warning", "candidate", "rejected"]
    conflict_ids: list[UUID] = Field(default_factory=list)


class IdentityConflict(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    conflict_id: UUID
    code: str
    observation_ids: list[UUID]
    competing_node_ids: list[UUID] = Field(default_factory=list)
    frames: list[int]
    resolution: Literal["split", "prefer_explicit", "unresolved"]
    reason_codes: list[str] = Field(default_factory=list)
    evidence_event_ids: list[UUID] = Field(default_factory=list)


class AccessRegistrationState(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    state_id: UUID
    access_context_id: UUID
    state: str
    valid_from_frame: int
    valid_to_frame: int | None = None
    evidence_event_ids: list[UUID] = Field(default_factory=list)


class RoamingTopologyInterval(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    topology_id: UUID
    ue_id: UUID | None = None
    access_context_id: UUID | None = None
    session_node_id: UUID | None = None
    valid_from_frame: int
    valid_to_frame: int | None = None
    selected_topology: Literal["home", "visited_unknown", "home_routed", "local_breakout", "inconclusive"]
    alternatives: list[dict[str, Any]] = Field(default_factory=list)
    evidence_terms: list[dict[str, Any]] = Field(default_factory=list)
    confidence: Literal["high", "medium", "low", "inconclusive"] = "inconclusive"
    fault_domains: dict[str, Any] = Field(default_factory=dict)
    rules_revision: str


class FaultDomainMap(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    fault_domain_map_id: UUID
    ue_id: UUID | None = None
    access_context_id: UUID | None = None
    session_node_id: UUID | None = None
    valid_from_frame: int
    valid_to_frame: int | None = None
    home_plmn: str | None = None
    serving_plmn: str | None = None
    home_nf_domain_aliases: list[str] = Field(default_factory=list)
    visited_nf_domain_aliases: list[str] = Field(default_factory=list)
    inter_plmn_path_aliases: list[str] = Field(default_factory=list)
    upf_path_aliases: list[str] = Field(default_factory=list)
    evidence_ids: list[UUID] = Field(default_factory=list)
    confidence: Literal["high", "medium", "low", "inconclusive"] = "inconclusive"
    rules_revision: str


class IdentityGraphReader:
    def __init__(self, revision: str, nodes: list[IdentityNode], edges: list[IdentityEdge], observations: list[IdentifierObservation], states: list[AccessRegistrationState], topology: list[RoamingTopologyInterval], fault_domains: list[FaultDomainMap]) -> None:
        self.revision = revision
        self._nodes = nodes
        self._edges = edges
        self._observations = observations
        self._states = states
        self._topology = topology
        self._fault_domains = fault_domains
        self._nodes_by_id = {node.node_id: node for node in nodes}
        self._observations_by_event: DefaultDict[UUID, list[IdentifierObservation]] = defaultdict(list)
        for observation in observations:
            self._observations_by_event[observation.event_id].append(observation)

    def nodes_for_event(self, event_id: UUID) -> list[IdentityNode]:
        obs_ids = {observation.observation_id for observation in self._observations_by_event.get(event_id, [])}
        return [node for node in self._nodes if obs_ids.intersection(node.observation_ids)]

    def ue_by_lookup(self, kind: str, masked_value: str) -> list[IdentityNode]:
        node_ids = {
            node.node_id
            for observation in self._observations
            if observation.kind == kind and observation.lookup_value == masked_value
            for node in self._nodes
            if observation.observation_id in node.observation_ids and node.node_type == "UE"
        }
        return [self._nodes_by_id[node_id] for node_id in sorted(node_ids, key=str)]

    def access_context_at(self, key: dict[str, Any], frame: int) -> IdentityNode | None:
        del key
        for node in self._nodes:
            if node.node_type == "ACCESS_CONTEXT" and node.first_frame <= frame <= node.last_frame:
                return node
        return None

    def sessions_for_context(self, access_context_id: UUID, frame: int) -> list[IdentityNode]:
        session_ids = {
            edge.right_node_id
            for edge in self._edges
            if edge.left_node_id == access_context_id and edge.right_node_type == "PDU_SESSION"
        }
        resolved_ids = sorted((node_id for node_id in session_ids if node_id is not None), key=str)
        return [
            self._nodes_by_id[node_id]
            for node_id in resolved_ids
            if self._nodes_by_id[node_id].first_frame <= frame <= self._nodes_by_id[node_id].last_frame
        ]

    def registration_state_at(self, access_context_id: UUID, frame: int) -> AccessRegistrationState | None:
        for state in self._states:
            if state.access_context_id == access_context_id and state.valid_from_frame <= frame and (state.valid_to_frame is None or frame <= state.valid_to_frame):
                return state
        return None

    def topology_at(self, node_id: UUID, frame: int) -> RoamingTopologyInterval | None:
        for record in self._topology:
            if node_id in {record.ue_id, record.access_context_id, record.session_node_id} and record.valid_from_frame <= frame and (record.valid_to_frame is None or frame <= record.valid_to_frame):
                return record
        return None

    def fault_domains_at(self, node_id: UUID, frame: int) -> FaultDomainMap | None:
        for record in self._fault_domains:
            if node_id in {record.ue_id, record.access_context_id, record.session_node_id} and record.valid_from_frame <= frame and (record.valid_to_frame is None or frame <= record.valid_to_frame):
                return record
        return None


def open_identity_graph_reader(result: BuildIdentityGraphResult) -> IdentityGraphReader:
    run_dir = result.manifest_path.parents[2]
    observations = [IdentifierObservation.model_validate(record) for record in _iter_jsonl_file(run_dir / "normalized/identity/observations.jsonl")]
    nodes = [IdentityNode.model_validate(record) for record in _iter_jsonl_file(run_dir / "normalized/identity/nodes.jsonl")]
    edges = [IdentityEdge.model_validate(record) for record in _iter_jsonl_file(run_dir / "normalized/identity/edges.jsonl")]
    states = [AccessRegistrationState.model_validate(record) for record in _iter_jsonl_file(run_dir / "normalized/identity/access_registration_states.jsonl")]
    topology = [RoamingTopologyInterval.model_validate(record) for record in _iter_jsonl_file(run_dir / "normalized/identity/roaming_topology.jsonl")]
    fault_domains = [FaultDomainMap.model_validate(record) for record in _iter_jsonl_file(run_dir / "normalized/identity/fault_domain_maps.jsonl")]
    return IdentityGraphReader(result.revision, nodes, edges, observations, states, topology, fault_domains)


def build_identity_graph(request: BuildIdentityGraphRequest) -> BuildIdentityGraphResult:
    started = datetime.now(tz=timezone.utc)
    validate_inside_run(request.run_dir, request.identity_dir, request.indexes_dir)
    _validate_identity_request(request)

    staging_root = request.run_dir / "staging" / f"T03-{request.analysis_id}"
    if staging_root.exists():
        for existing in sorted(staging_root.rglob("*"), reverse=True):
            if existing.is_file():
                existing.unlink()
            elif existing.is_dir():
                existing.rmdir()
    staging_root.mkdir(parents=True, exist_ok=True)

    observation_writer = JsonlArtifactWriter(staging_root, request.run_dir, "normalized/identity/observations.jsonl", "identity_observations")
    node_writer = JsonlArtifactWriter(staging_root, request.run_dir, "normalized/identity/nodes.jsonl", "identity_nodes")
    edge_writer = JsonlArtifactWriter(staging_root, request.run_dir, "normalized/identity/edges.jsonl", "identity_edges")
    ambiguous_writer = JsonlArtifactWriter(staging_root, request.run_dir, "normalized/identity/ambiguous_edges.jsonl", "identity_edge_candidates")
    conflict_writer = JsonlArtifactWriter(staging_root, request.run_dir, "normalized/identity/conflicts.jsonl", "identity_conflicts")
    state_writer = JsonlArtifactWriter(staging_root, request.run_dir, "normalized/identity/access_registration_states.jsonl", "access_registration_states")
    topology_writer = JsonlArtifactWriter(staging_root, request.run_dir, "normalized/identity/roaming_topology.jsonl", "roaming_topology_intervals")
    fault_domain_writer = JsonlArtifactWriter(staging_root, request.run_dir, "normalized/identity/fault_domain_maps.jsonl", "fault_domain_maps")

    counters = {
        "warning_counts": defaultdict(int),
        "nodes_by_type": defaultdict(int),
    }
    issues: list[Issue] = []

    salt = str((request.masking_policy.payload or {}).get("salt") or "")
    observations = _extract_observations(request, salt, counters, issues)
    for observation in observations:
        observation_writer.write(observation)

    accepted_edges, ambiguous_edges, conflicts = _build_edges(request, observations, counters, issues)
    union_groups = _union_same_type(observations, accepted_edges)
    nodes = _materialize_nodes(request, observations, accepted_edges, union_groups, counters)
    _resolve_edge_nodes(accepted_edges, nodes, observations)
    _resolve_edge_nodes(ambiguous_edges, nodes, observations)

    registration_states = _build_registration_states(request, observations, nodes)
    topology_records, fault_domain_maps = _build_topology_records(request, nodes)

    for node in nodes:
        node_writer.write(node)
    for edge in accepted_edges:
        edge_writer.write(edge)
    for edge in ambiguous_edges:
        ambiguous_writer.write(edge)
    for conflict in conflicts:
        conflict_writer.write(conflict)
    for state in registration_states:
        state_writer.write(state)
    for topology in topology_records:
        topology_writer.write(topology)
    for record in fault_domain_maps:
        fault_domain_writer.write(record)

    observation_closed = observation_writer.close()
    node_closed = node_writer.close()
    edge_closed = edge_writer.close()
    ambiguous_closed = ambiguous_writer.close()
    conflict_closed = conflict_writer.close()
    state_closed = state_writer.close()
    topology_closed = topology_writer.close()
    fault_domain_closed = fault_domain_writer.close()

    indexes = _build_indexes(request, observations, nodes, accepted_edges, registration_states, topology_records, fault_domain_maps)
    index_closed = [
        JsonArtifactWriter(staging_root, request.run_dir, relative_path, "identity_index").write(payload)
        for relative_path, payload in indexes.items()
    ]

    pre_revision_descriptors = [
        observation_closed.descriptor(creation_stage="T03", parent_source_sha256=request.normalization.manifest.sha256),
        node_closed.descriptor(creation_stage="T03", parent_source_sha256=request.normalization.manifest.sha256),
        edge_closed.descriptor(creation_stage="T03", parent_source_sha256=request.normalization.manifest.sha256),
        ambiguous_closed.descriptor(creation_stage="T03", parent_source_sha256=request.normalization.manifest.sha256),
        conflict_closed.descriptor(creation_stage="T03", parent_source_sha256=request.normalization.manifest.sha256),
        state_closed.descriptor(creation_stage="T03", parent_source_sha256=request.normalization.manifest.sha256),
        topology_closed.descriptor(creation_stage="T03", parent_source_sha256=request.normalization.manifest.sha256),
        fault_domain_closed.descriptor(creation_stage="T03", parent_source_sha256=request.normalization.manifest.sha256),
        *[closed.descriptor(creation_stage="T03", parent_source_sha256=request.normalization.manifest.sha256) for closed in index_closed],
    ]
    revision = _build_t03_revision(request, pre_revision_descriptors)
    artifacts: list[ArtifactDescriptor] = []
    for descriptor in pre_revision_descriptors:
        descriptor.revision = revision
        artifacts.append(descriptor)

    ended = datetime.now(tz=timezone.utc)
    elapsed_ms = int((ended - started).total_seconds() * 1000)
    status: Literal["success", "partial", "failed"] = "partial" if counters["warning_counts"] else "success"
    manifest_payload = {
        "schema_version": SCHEMA_VERSION,
        "tool": "T03",
        "analysis_id": str(request.analysis_id),
        "status": status,
        "revision": revision,
        "parent": {
            "tool": "T02",
            "revision": request.normalization.revision,
            "manifest_sha256": request.normalization.manifest.sha256,
        },
        "policies": {
            "identity_rules": request.identity_rules.model_dump(mode="json", exclude={"payload"}),
            "topology_rules": request.topology_rules.model_dump(mode="json", exclude={"payload"}),
            "masking_policy": request.masking_policy.model_dump(mode="json", exclude={"payload"}),
        },
        "config_sha256": sha256_bytes(compact_json_bytes(request.config)),
        "counts": {
            "observation_count": len(observations),
            "nodes_by_type": counters["nodes_by_type"],
            "accepted_edges": len(accepted_edges),
            "ambiguous_edges": len(ambiguous_edges),
            "conflicts": len(conflicts),
            "registration_state_intervals": len(registration_states),
            "topology_intervals": len(topology_records),
            "fault_domain_maps": len(fault_domain_maps),
            "warning_counts": counters["warning_counts"],
            "provisional_nodes": sum(1 for node in nodes if node.provisional),
            "incomplete_nodes": sum(1 for node in nodes if node.incomplete_history),
        },
        "confidence_histogram": _confidence_histogram(accepted_edges, ambiguous_edges),
        "topology_counts": {"inconclusive": len(topology_records)},
        "topology_confidence_counts": {"inconclusive": len(topology_records)},
        "artifacts": artifacts,
        "collections": [],
        "issues": sample_issues(issues, request.config.max_issue_samples_per_code),
        "timing": {
            "started_at": started.isoformat(),
            "ended_at": ended.isoformat(),
            "elapsed_ms": elapsed_ms,
            "peak_rss_bytes": None,
        },
    }
    manifest_closed = JsonArtifactWriter(
        staging_root,
        request.run_dir,
        "normalized/identity/identity_graph_manifest.json",
        "identity_graph_manifest",
    ).write(manifest_payload)
    publish_closed_artifacts(
        request.run_dir,
        [
            observation_closed,
            node_closed,
            edge_closed,
            ambiguous_closed,
            conflict_closed,
            state_closed,
            topology_closed,
            fault_domain_closed,
            *index_closed,
            manifest_closed,
        ],
        manifest_relative_path="normalized/identity/identity_graph_manifest.json",
    )
    manifest_path = request.run_dir / "normalized/identity/identity_graph_manifest.json"
    manifest_descriptor = ArtifactDescriptor(
        artifact_id=str(deterministic_uuid(request.analysis_id, "T03", revision, "manifest")),
        relative_path="normalized/identity/identity_graph_manifest.json",
        artifact_type="identity_graph_manifest",
        media_type="application/json",
        format_schema_version=SCHEMA_VERSION,
        sha256=sha256_file(manifest_path),
        byte_size=manifest_path.stat().st_size,
        record_count=1,
        creation_stage="T03",
        parent_source_sha256=request.normalization.manifest.sha256,
        revision=revision,
    )

    return BuildIdentityGraphResult(
        analysis_id=request.analysis_id,
        status=status,
        revision=revision,
        manifest=manifest_descriptor,
        artifacts=artifacts,
        observation_count=len(observations),
        ue_nodes=counters["nodes_by_type"]["UE"],
        pdu_session_nodes=counters["nodes_by_type"]["PDU_SESSION"],
        access_context_nodes=counters["nodes_by_type"]["ACCESS_CONTEXT"],
        sm_context_nodes=counters["nodes_by_type"]["SM_CONTEXT"],
        pfcp_session_nodes=counters["nodes_by_type"]["PFCP_SESSION"],
        accepted_edges=len(accepted_edges),
        ambiguous_edges=len(ambiguous_edges),
        conflicts=len(conflicts),
        registration_state_intervals=len(registration_states),
        topology_intervals=len(topology_records),
        fault_domain_maps=len(fault_domain_maps),
        warning_counts=dict(sorted(counters["warning_counts"].items())),
        elapsed_ms=elapsed_ms,
        issues=manifest_payload["issues"],
        manifest_path=manifest_path,
    )


def _validate_identity_request(request: BuildIdentityGraphRequest) -> None:
    if request.primary_reader.revision != request.normalization.revision:
        raise ValueError("primary reader revision does not match normalization revision")
    if request.capture.source_sha256 != request.normalization.manifest.parent_source_sha256:
        raise ValueError("capture source checksum does not match normalization lineage")
    if not ((request.masking_policy.payload or {}).get("salt")):
        raise ValueError("masking policy must provide payload.salt")
    for key, policy in (
        ("identity_rules", request.identity_rules),
        ("topology_rules", request.topology_rules),
        ("masking_policy", request.masking_policy),
    ):
        declared = request.policy_versions.get(key)
        if declared is not None and declared != policy.version:
            raise ValueError(f"policy_versions[{key!r}] does not match resolved policy version")
    if request.config.warning_link_threshold < 0 or request.config.auto_link_threshold > 1:
        raise ValueError("identity graph thresholds must be within [0, 1]")
    if request.config.warning_link_threshold >= request.config.auto_link_threshold:
        raise ValueError("warning_link_threshold must be lower than auto_link_threshold")


def _extract_observations(
    request: BuildIdentityGraphRequest,
    salt: str,
    counters: dict[str, Any],
    issues: list[Issue],
) -> list[IdentifierObservation]:
    observations: list[IdentifierObservation] = []
    seen: set[tuple[UUID, str, str]] = set()
    sensitive_kinds = set((request.identity_rules.payload or {}).get("sensitive_identifier_kinds", ["supi", "suci", "gpsi", "guti", "pei"]))
    for event in request.primary_reader.by_frame(request.capture.first_frame, request.capture.last_frame):
        if event.partition != "primary" or event.validation_status == "quarantined":
            raise ValueError("primary reader yielded a non-primary or quarantined event")
        for field_name, value in event.identifiers.model_dump(exclude_none=True).items():
            node_type, role = _kind_mapping(field_name)
            sensitive = field_name in sensitive_kinds
            lookup_value = mask_identifier(field_name, str(value), salt) if sensitive else str(value)
            scope_key = _scope_key(event, field_name)
            dedupe_key = (event.event_id, field_name, lookup_value)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            observation = IdentifierObservation(
                observation_id=deterministic_uuid(
                    request.analysis_id,
                    request.normalization.revision,
                    event.event_id,
                    field_name,
                    lookup_value,
                    scope_key,
                    request.identity_rules.sha256,
                ),
                event_id=event.event_id,
                frame=event.frame,
                timestamp=event.timestamp,
                timestamp_precision=event.timestamp_precision,
                kind=field_name,
                node_type=node_type,
                lookup_value=lookup_value,
                sensitive=sensitive,
                scope_key=scope_key,
                field_path=f"identifiers.{field_name}",
                raw_refs=event.raw_refs,
                role=role,
                confidence=Decimal("1.0"),
                valid_from_frame=event.frame,
                valid_to_frame=None,
                provisional=False,
            )
            observations.append(observation)
    observations.sort(key=lambda item: (item.frame, str(item.event_id), str(item.observation_id)))
    return observations


def _kind_mapping(kind: str) -> tuple[IdentityNodeType, IdentityObservationRole]:
    ue_kinds = {"supi", "suci", "gpsi", "guti", "pei"}
    access_kinds = {"amf_ue_ngap_id", "ran_ue_ngap_id"}
    session_kinds = {"pdu_session_id"}
    sm_context_kinds = {"sm_context_ref"}
    if kind in ue_kinds:
        return "UE", "UE"
    if kind in access_kinds:
        return "ACCESS_CONTEXT", "ACCESS_CONTEXT"
    if kind in session_kinds:
        return "PDU_SESSION", "SESSION"
    if kind in sm_context_kinds:
        return "SM_CONTEXT", "SESSION"
    return "PFCP_SESSION", "USER_PLANE"


def _scope_key(event: CanonicalEvent, kind: str) -> str:
    del event
    return f"{kind}:global"


def _build_edges(
    request: BuildIdentityGraphRequest,
    observations: list[IdentifierObservation],
    counters: dict[str, Any],
    issues: list[Issue],
) -> tuple[list[IdentityEdge], list[IdentityEdge], list[IdentityConflict]]:
    accepted: list[IdentityEdge] = []
    ambiguous: list[IdentityEdge] = []
    conflicts: list[IdentityConflict] = []
    exact_groups: DefaultDict[tuple[str, str, str], list[IdentifierObservation]] = defaultdict(list)
    by_event: DefaultDict[UUID, list[IdentifierObservation]] = defaultdict(list)
    for observation in observations:
        exact_groups[(observation.kind, observation.lookup_value, observation.scope_key)].append(observation)
        by_event[observation.event_id].append(observation)

    for group in exact_groups.values():
        if len(group) < 2:
            continue
        group = sorted(group, key=lambda item: (item.frame, str(item.observation_id)))
        for left, right in zip(group, group[1:]):
            edge = _make_edge(request, left, right, relation=f"same_{left.kind}", strength="exact", edge_effect="union_same_type", confidence=Decimal("1.0"), rule_id="exact_identifier_match")
            accepted.append(edge)

    for event_id, group in sorted(by_event.items(), key=lambda item: str(item[0])):
        sorted_group = sorted(group, key=lambda item: (item.node_type, item.kind, str(item.observation_id)))
        for index, left in enumerate(sorted_group):
            for right in sorted_group[index + 1 :]:
                if left.node_type == right.node_type and left.node_type != "ACCESS_CONTEXT":
                    continue
                confidence = Decimal("0.95")
                decision = "accepted" if confidence >= request.config.auto_link_threshold else "accepted_with_warning"
                edge = _make_edge(
                    request,
                    left,
                    right,
                    relation="same_event_context",
                    strength="strong",
                    edge_effect="union_same_type" if left.node_type == right.node_type else "associate_nodes",
                    confidence=confidence,
                    rule_id="event_cooccurrence",
                    decision=decision,
                )
                if decision == "accepted_with_warning":
                    counters["warning_counts"]["T03_WARNING_BAND_LINK"] += 1
                    issues.append(Issue(code="T03_WARNING_BAND_LINK", stage="T03", message=f"warning-band association edge for event {event_id}"))
                accepted.append(edge)

    return accepted, ambiguous, conflicts


def _make_edge(
    request: BuildIdentityGraphRequest,
    left: IdentifierObservation,
    right: IdentifierObservation,
    *,
    relation: str,
    strength: Literal["exact", "strong", "supporting"],
    edge_effect: Literal["union_same_type", "associate_nodes"],
    confidence: Decimal,
    rule_id: str,
    decision: Literal["accepted", "accepted_with_warning", "candidate", "rejected"] = "accepted",
) -> IdentityEdge:
    ordered = sorted([left, right], key=lambda item: str(item.observation_id))
    left, right = ordered
    return IdentityEdge(
        edge_id=deterministic_uuid(request.analysis_id, request.normalization.revision, left.observation_id, right.observation_id, relation, rule_id),
        left_observation_id=left.observation_id,
        right_observation_id=right.observation_id,
        left_node_type=left.node_type,
        right_node_type=right.node_type,
        relation=relation,
        strength=strength,
        edge_effect=edge_effect,
        confidence=confidence,
        score_terms=[{"score": format(confidence, "f"), "rationale_code": rule_id}],
        rule_id=rule_id,
        reason_codes=[rule_id],
        supporting_event_ids=sorted({left.event_id, right.event_id}, key=str),
        valid_from_frame=min(left.valid_from_frame, right.valid_from_frame),
        valid_to_frame=None,
        decision=decision,
    )


def _union_same_type(observations: list[IdentifierObservation], edges: list[IdentityEdge]) -> dict[UUID, UUID]:
    parent = {observation.observation_id: observation.observation_id for observation in observations}

    def find(node: UUID) -> UUID:
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def union(left: UUID, right: UUID) -> None:
        root_left = find(left)
        root_right = find(right)
        if root_left == root_right:
            return
        if str(root_left) < str(root_right):
            parent[root_right] = root_left
        else:
            parent[root_left] = root_right

    for edge in edges:
        if edge.edge_effect == "union_same_type" and edge.decision in {"accepted", "accepted_with_warning"}:
            union(edge.left_observation_id, edge.right_observation_id)

    return {node: find(node) for node in parent}


def _materialize_nodes(
    request: BuildIdentityGraphRequest,
    observations: list[IdentifierObservation],
    accepted_edges: list[IdentityEdge],
    union_groups: dict[UUID, UUID],
    counters: dict[str, Any],
) -> list[IdentityNode]:
    groups: DefaultDict[UUID, list[IdentifierObservation]] = defaultdict(list)
    for observation in observations:
        groups[union_groups[observation.observation_id]].append(observation)

    nodes: list[IdentityNode] = []
    type_aliases: DefaultDict[str, int] = defaultdict(int)
    for root, members in sorted(groups.items(), key=lambda item: str(item[0])):
        members = sorted(members, key=lambda item: (item.frame, item.kind, item.lookup_value, str(item.observation_id)))
        node_type = members[0].node_type
        anchor = members[0]
        node_id = deterministic_uuid(
            request.analysis_id,
            request.normalization.revision,
            request.identity_rules.sha256,
            node_type,
            anchor.kind,
            anchor.lookup_value,
            anchor.frame,
        )
        type_aliases[node_type] += 1
        accepted_edge_ids = [
            edge.edge_id
            for edge in accepted_edges
            if edge.edge_effect == "union_same_type"
            and edge.decision in {"accepted", "accepted_with_warning"}
            and {edge.left_observation_id, edge.right_observation_id}.issubset({member.observation_id for member in members})
        ]
        association_edge_ids = [
            edge.edge_id
            for edge in accepted_edges
            if edge.edge_effect == "associate_nodes"
            and edge.decision in {"accepted", "accepted_with_warning"}
            and ({edge.left_observation_id, edge.right_observation_id} & {member.observation_id for member in members})
        ]
        node = IdentityNode(
            node_id=node_id,
            node_type=node_type,
            first_frame=min(member.frame for member in members),
            last_frame=max(member.frame for member in members),
            first_timestamp=min((member.timestamp for member in members if member.timestamp is not None), default=None),
            last_timestamp=max((member.timestamp for member in members if member.timestamp is not None), default=None),
            provisional=any(member.provisional for member in members),
            incomplete_history=min(member.frame for member in members) == request.capture.first_frame,
            observation_ids=[member.observation_id for member in members],
            accepted_edge_ids=sorted(accepted_edge_ids, key=str),
            association_edge_ids=sorted(set(association_edge_ids), key=str),
            display_alias=f"{node_type}-{type_aliases[node_type]}",
        )
        counters["nodes_by_type"][node_type] += 1
        nodes.append(node)
    nodes.sort(key=lambda item: (item.node_type, item.first_frame, str(item.node_id)))
    return nodes


def _resolve_edge_nodes(edges: list[IdentityEdge], nodes: list[IdentityNode], observations: list[IdentifierObservation]) -> None:
    del observations
    observation_to_node: dict[UUID, UUID] = {}
    for node in nodes:
        for observation_id in node.observation_ids:
            observation_to_node[observation_id] = node.node_id
    for edge in edges:
        edge.left_node_id = observation_to_node.get(edge.left_observation_id)
        edge.right_node_id = observation_to_node.get(edge.right_observation_id)


def _build_registration_states(
    request: BuildIdentityGraphRequest,
    observations: list[IdentifierObservation],
    nodes: list[IdentityNode],
) -> list[AccessRegistrationState]:
    access_nodes = [node for node in nodes if node.node_type == "ACCESS_CONTEXT"]
    if not access_nodes:
        return []
    evidence_event_ids = sorted({observation.event_id for observation in observations if observation.node_type == "ACCESS_CONTEXT"}, key=str)
    return [
        AccessRegistrationState(
            state_id=deterministic_uuid(request.analysis_id, request.normalization.revision, node.node_id, "registered"),
            access_context_id=node.node_id,
            state="registered",
            valid_from_frame=node.first_frame,
            valid_to_frame=node.last_frame,
            evidence_event_ids=evidence_event_ids,
        )
        for node in access_nodes
    ]


def _build_topology_records(
    request: BuildIdentityGraphRequest,
    nodes: list[IdentityNode],
) -> tuple[list[RoamingTopologyInterval], list[FaultDomainMap]]:
    ue_nodes = [node for node in nodes if node.node_type == "UE"]
    topology: list[RoamingTopologyInterval] = []
    fault_domain_maps: list[FaultDomainMap] = []
    for node in ue_nodes:
        topology_id = deterministic_uuid(request.analysis_id, request.normalization.revision, node.node_id, "topology")
        fault_id = deterministic_uuid(request.analysis_id, request.normalization.revision, node.node_id, "fault_domain")
        fault_domain = FaultDomainMap(
            fault_domain_map_id=fault_id,
            ue_id=node.node_id,
            valid_from_frame=node.first_frame,
            valid_to_frame=node.last_frame,
            confidence="inconclusive",
            rules_revision=request.topology_rules.sha256,
        )
        topology.append(
            RoamingTopologyInterval(
                topology_id=topology_id,
                ue_id=node.node_id,
                valid_from_frame=node.first_frame,
                valid_to_frame=node.last_frame,
                selected_topology="inconclusive",
                confidence="inconclusive",
                fault_domains=fault_domain.model_dump(mode="json", exclude_none=True),
                rules_revision=request.topology_rules.sha256,
            )
        )
        fault_domain_maps.append(fault_domain)
    return topology, fault_domain_maps


def _build_indexes(
    request: BuildIdentityGraphRequest,
    observations: list[IdentifierObservation],
    nodes: list[IdentityNode],
    edges: list[IdentityEdge],
    registration_states: list[AccessRegistrationState],
    topology_records: list[RoamingTopologyInterval],
    fault_domain_maps: list[FaultDomainMap],
) -> dict[str, Any]:
    observation_to_node: dict[UUID, list[UUID]] = defaultdict(list)
    for node in nodes:
        for observation_id in node.observation_ids:
            observation_to_node[observation_id].append(node.node_id)
    ue_index = [
        {
            "revision": request.normalization.revision,
            "node_id": str(node.node_id),
            "display_alias": node.display_alias,
            "first_frame": node.first_frame,
            "last_frame": node.last_frame,
        }
        for node in nodes
        if node.node_type == "UE"
    ]
    session_index = [
        {
            "revision": request.normalization.revision,
            "session_node_id": str(node.node_id),
            "valid_from_frame": node.first_frame,
            "valid_to_frame": node.last_frame,
        }
        for node in nodes
        if node.node_type == "PDU_SESSION"
    ]
    context_index = [
        {
            "revision": request.normalization.revision,
            "access_context_id": str(node.node_id),
            "valid_from_frame": node.first_frame,
            "valid_to_frame": node.last_frame,
        }
        for node in nodes
        if node.node_type == "ACCESS_CONTEXT"
    ]
    identifier_index = [
        {
            "revision": request.normalization.revision,
            "identifier_kind": observation.kind,
            "lookup_value": observation.lookup_value,
            "scope_key": observation.scope_key,
            "node_ids": sorted(str(node_id) for node_id in observation_to_node.get(observation.observation_id, [])),
            "observation_ids": [str(observation.observation_id)],
            "valid_from_frame": observation.valid_from_frame,
            "valid_to_frame": observation.valid_to_frame,
        }
        for observation in observations
    ]
    event_identity_index = [
        {
            "revision": request.normalization.revision,
            "event_id": str(event_id),
            "observation_ids": sorted(str(observation.observation_id) for observation in group),
            "node_ids": sorted(
                {
                    str(node_id)
                    for observation in group
                    for node_id in observation_to_node.get(observation.observation_id, [])
                }
            ),
            "accepted_edge_ids": sorted(str(edge.edge_id) for edge in edges if event_id in edge.supporting_event_ids),
        }
        for event_id, group in sorted(_group_observations_by_event(observations).items(), key=lambda item: str(item[0]))
    ]
    return {
        "indexes/ue_index.jsonl": ue_index,
        "indexes/session_index.jsonl": session_index,
        "indexes/context_index.jsonl": context_index,
        "indexes/access_registration_state_index.jsonl": [
            state.model_dump(mode="json", exclude_none=True) for state in registration_states
        ],
        "indexes/identifier_index.jsonl": identifier_index,
        "indexes/event_identity_index.jsonl": event_identity_index,
        "indexes/roaming_topology_index.jsonl": [
            record.model_dump(mode="json", exclude_none=True) for record in topology_records
        ],
        "indexes/fault_domain_index.jsonl": [
            record.model_dump(mode="json", exclude_none=True) for record in fault_domain_maps
        ],
    }


def _build_t03_revision(request: BuildIdentityGraphRequest, descriptors: Iterable[ArtifactDescriptor]) -> str:
    payload = {
        "tool": "T03",
        "tool_version": GRAPH_VERSION,
        "schema_version": SCHEMA_VERSION,
        "analysis_id": str(request.analysis_id),
        "t02_revision": request.normalization.revision,
        "t02_manifest_sha256": request.normalization.manifest.sha256,
        "capture": request.capture.model_dump(mode="json"),
        "identity_rules": request.identity_rules.model_dump(mode="json"),
        "topology_rules": request.topology_rules.model_dump(mode="json"),
        "masking_policy": request.masking_policy.model_dump(mode="json", exclude={"payload"}),
        "config": request.config.model_dump(mode="json"),
        "capabilities": sorted(request.enabled_capabilities),
        "descriptors": [
            {
                "relative_path": descriptor.relative_path,
                "artifact_type": descriptor.artifact_type,
                "sha256": descriptor.sha256,
                "byte_size": descriptor.byte_size,
                "record_count": descriptor.record_count,
            }
            for descriptor in sorted(descriptors, key=lambda item: item.relative_path)
        ],
    }
    return f"sha256:{sha256_bytes(compact_json_bytes(payload))}"


def _confidence_histogram(accepted_edges: list[IdentityEdge], ambiguous_edges: list[IdentityEdge]) -> dict[str, int]:
    histogram: DefaultDict[str, int] = defaultdict(int)
    for edge in [*accepted_edges, *ambiguous_edges]:
        histogram[format(edge.confidence, ".2f")] += 1
    return dict(sorted(histogram.items()))


def _group_observations_by_event(observations: list[IdentifierObservation]) -> dict[UUID, list[IdentifierObservation]]:
    grouped: DefaultDict[UUID, list[IdentifierObservation]] = defaultdict(list)
    for observation in observations:
        grouped[observation.event_id].append(observation)
    return grouped


def _iter_jsonl_file(path: Path) -> Iterator[dict[str, Any]]:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                yield __import__("json").loads(stripped)
