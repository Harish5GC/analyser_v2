"""T04 segment_attempts implementation."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
import json
from pathlib import Path
from typing import Any, DefaultDict, Iterable, Iterator, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from harness.decoder.manifest import ArtifactDescriptor, CollectionDescriptor
from harness.identity import (
    BuildIdentityGraphResult,
    FaultDomainMap,
    IdentityGraphReader,
    IdentityNode,
    RoamingTopologyInterval,
)
from harness.normalize import JsonlPrimaryEventReader, NormalizeEventsResult
from harness.shared import (
    CanonicalEvent,
    CaptureMetadata,
    Endpoint,
    EventIdentifiers,
    Issue,
    JsonArtifactWriter,
    JsonlArtifactWriter,
    ResolvedPolicy,
    artifact_by_relative_path,
    compact_json_bytes,
    deterministic_uuid,
    iter_jsonl,
    parse_decimal,
    publish_closed_artifacts,
    sample_issues,
    sha256_bytes,
    sha256_file,
    validate_inside_run,
)

SCHEMA_VERSION = "2.0"
ATTEMPTS_VERSION = "2.0.0"

AccessFamily = Literal["3gpp", "non_3gpp_untrusted", "non_3gpp_trusted", "unknown"]
AccessAnchorType = Literal["GNB", "N3IWF", "TNGF", "UNKNOWN"]
AttemptOutcome = Literal["succeeded", "failed", "aborted", "timed_out", "incomplete_capture"]
AssignmentConfidence = Literal["high", "medium", "low"]
StageApplicability = Literal["mandatory", "conditional", "optional", "repeatable"]


class EventMatcher(BaseModel):
    protocol: Literal["NAS", "NGAP", "HTTP2", "PFCP"] | None = None
    message_types: list[str] = Field(default_factory=list)
    outcomes: list[str] = Field(default_factory=list)
    attribute_equals: dict[str, Any] = Field(default_factory=dict)
    identifier_present: list[str] = Field(default_factory=list)


class VisibilityRequirement(BaseModel):
    domain: Literal["reference_point", "sbi_service", "sbi_api"]
    key: str
    required_for_missing_stage_failure: bool = False
    minimum_state: Literal["visible", "partial"] = "visible"


class StageDefinition(BaseModel):
    stage_id: str
    name: str
    order: int
    applicability: StageApplicability = "mandatory"
    event_matchers: list[EventMatcher] = Field(default_factory=list)
    terminal_success: bool = False
    terminal_failure: bool = False
    timeout_seconds: Decimal | None = None
    predecessor_ids: list[str] = Field(default_factory=list)
    visibility_requirements: list[VisibilityRequirement] = Field(default_factory=list)
    applicability_condition: dict[str, Any] | None = None


class ResolvedProcedureProfile(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    profile_id: str
    version: str
    release: str
    deployment_profile: str
    procedure_type: str
    trigger_matchers: list[EventMatcher] = Field(default_factory=list)
    correlation_keys: list[str] = Field(default_factory=list)
    stages: list[StageDefinition] = Field(default_factory=list)
    success_terminals: list[EventMatcher] = Field(default_factory=list)
    failure_terminals: list[EventMatcher] = Field(default_factory=list)
    abort_terminals: list[EventMatcher] = Field(default_factory=list)
    parent_profile_ids: list[str] = Field(default_factory=list)
    transfer_from_profile_ids: list[str] = Field(default_factory=list)
    closes_profile_ids: list[str] = Field(default_factory=list)
    retry_window_seconds: Decimal | None = None
    source_checksum: str
    resolved_revision: str


class ResolvedProfileRegistry(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    registry_version: str
    sha256: str
    release: str
    deployment_profile: str
    profiles: list[ResolvedProcedureProfile]


def load_resolved_profile_registry(
    registry_path: Path,
    *,
    expected_release: str | None = None,
    expected_deployment_profile: str | None = None,
) -> ResolvedProfileRegistry:
    registry_path = registry_path.resolve()
    root = registry_path.parent
    document = _load_profile_json(registry_path)
    profile_documents = document.get("profiles")
    profile_files = document.get("profile_files")
    if bool(profile_documents) == bool(profile_files):
        raise ValueError("resolved profile registry must declare exactly one of profiles or profile_files")

    profiles: list[ResolvedProcedureProfile] = []
    if profile_files:
        if not isinstance(profile_files, list):
            raise ValueError("profile_files must be an array")
        for entry in profile_files:
            if not isinstance(entry, dict) or not isinstance(entry.get("relative_path"), str):
                raise ValueError("profile_files entries require relative_path")
            relative_path = Path(entry["relative_path"])
            if relative_path.is_absolute() or ".." in relative_path.parts:
                raise ValueError("profile file path must remain inside the registry root")
            profile_path = root / relative_path
            if profile_path.is_symlink() or root not in profile_path.resolve().parents:
                raise ValueError("profile file path escapes the registry root")
            expected_sha256 = entry.get("sha256")
            actual_sha256 = sha256_file(profile_path)
            if expected_sha256 != actual_sha256:
                raise ValueError(f"profile checksum mismatch for {relative_path}")
            profiles.append(ResolvedProcedureProfile.model_validate(_load_profile_json(profile_path)))
    else:
        if not isinstance(profile_documents, list):
            raise ValueError("profiles must be an array")
        profiles = [ResolvedProcedureProfile.model_validate(item) for item in profile_documents]

    release = str(document.get("release", ""))
    deployment_profile = str(document.get("deployment_profile", ""))
    if expected_release is not None and release != expected_release:
        raise ValueError("profile registry release does not match expected release")
    if expected_deployment_profile is not None and deployment_profile != expected_deployment_profile:
        raise ValueError("profile registry deployment profile does not match expected deployment")
    for profile in profiles:
        if profile.release != release or profile.deployment_profile != deployment_profile:
            raise ValueError(f"profile {profile.profile_id} dimensions do not match the registry")

    canonical = {
        "schema_version": document.get("schema_version", SCHEMA_VERSION),
        "registry_version": document.get("registry_version"),
        "release": release,
        "deployment_profile": deployment_profile,
        "profiles": [profile.model_dump(mode="json") for profile in sorted(profiles, key=lambda item: item.profile_id)],
    }
    digest = sha256_bytes(compact_json_bytes(canonical))
    declared_sha256 = document.get("sha256")
    if declared_sha256 is not None and declared_sha256 not in {digest, f"sha256:{digest}"}:
        raise ValueError("profile registry checksum does not match canonical resolved content")
    return ResolvedProfileRegistry(
        schema_version=canonical["schema_version"],
        registry_version=str(canonical["registry_version"]),
        sha256=f"sha256:{digest}",
        release=release,
        deployment_profile=deployment_profile,
        profiles=profiles,
    )


def _load_profile_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid profile JSON {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"profile JSON {path.name} must be an object")
    return value


class ProfileSelectionAlternative(BaseModel):
    profile_id: str
    score: Decimal
    reason_codes: list[str] = Field(default_factory=list)


class InterfaceVisibility(BaseModel):
    reference_points: dict[str, Literal["visible", "partial", "not_observed", "unknown"]] = Field(default_factory=dict)
    services: dict[str, Literal["visible", "partial", "not_observed", "unknown"]] = Field(default_factory=dict)
    apis: dict[str, Literal["visible", "partial", "not_observed", "unknown"]] = Field(default_factory=dict)


class StateTransition(BaseModel):
    transition_id: UUID
    stage_id: str
    stage_name: str
    event_id: UUID
    frame: int
    timestamp: Decimal | None = None
    transition_type: Literal["entered", "completed", "failed", "aborted", "timed_out"] = "completed"


class RetryRecord(BaseModel):
    retry_id: UUID
    prior_attempt_id: UUID
    next_attempt_id: UUID
    trigger_event_id: UUID
    frame_gap: int
    time_gap_seconds: Decimal | None = None
    reason_codes: list[str] = Field(default_factory=list)


class StageTimingObservation(BaseModel):
    stage_timing_id: UUID
    stage_id: str
    stage_name: str
    first_event_id: UUID
    first_frame: int
    first_timestamp: Decimal | None = None
    last_event_id: UUID
    last_frame: int
    last_timestamp: Decimal | None = None
    status: Literal["observed", "missing", "skipped", "inconclusive"] = "observed"


class ProcedureAttempt(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    attempt_id: UUID
    analysis_id: UUID
    ue_id: UUID | None = None
    session_node_id: UUID | None = None
    access_context_id: UUID | None = None
    access_family: AccessFamily = "unknown"
    access_anchor_type: AccessAnchorType = "UNKNOWN"
    profile_id: str
    profile_alternatives: list[ProfileSelectionAlternative] = Field(default_factory=list)
    profile_selection_status: Literal["selected", "ambiguous"] = "selected"
    procedure_type: str
    subtype: str | None = None
    sequence_number: int
    initiator: Literal["UE", "NETWORK", "UNKNOWN"] = "UNKNOWN"
    parent_attempt_id: UUID | None = None
    child_attempt_ids: list[UUID] = Field(default_factory=list)
    start_frame: int
    end_frame: int
    start_timestamp: Decimal | None = None
    end_timestamp: Decimal | None = None
    incomplete_history: bool = False
    trigger_event_ids: list[UUID] = Field(default_factory=list)
    event_ids: list[UUID] = Field(default_factory=list)
    correlation_identifiers: EventIdentifiers = Field(default_factory=EventIdentifiers)
    request_signature: dict[str, Any] = Field(default_factory=dict)
    transitions: list[StateTransition] = Field(default_factory=list)
    retries: list[RetryRecord] = Field(default_factory=list)
    stage_timings: list[StageTimingObservation] = Field(default_factory=list)
    outcome: AttemptOutcome
    completion_reason: str
    assignment_confidence: AssignmentConfidence = "medium"
    visibility: InterfaceVisibility = Field(default_factory=InterfaceVisibility)
    roaming_topology: RoamingTopologyInterval | None = None
    issue_codes: list[str] = Field(default_factory=list)


class AttemptEventAssignment(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    assignment_id: UUID
    event_id: UUID
    attempt_id: UUID
    confidence: Decimal
    strength: Literal["exact", "strong", "supporting"]
    reason_codes: list[str]
    profile_stage_ids: list[str] = Field(default_factory=list)
    shared_by_nesting_rule: bool = False


class AttemptRelationship(BaseModel):
    relationship_id: UUID
    left_attempt_id: UUID
    right_attempt_id: UUID
    relation: Literal["parent_child", "retry_of", "supersedes", "access_transfer"]
    evidence_event_ids: list[UUID] = Field(default_factory=list)
    profile_rule_id: str


class UnassignedEventRecord(BaseModel):
    event_id: UUID
    frame: int
    protocol: str
    message_type: str
    reason_codes: list[str] = Field(default_factory=list)


class AttemptAmbiguityRecord(BaseModel):
    event_id: UUID
    frame: int
    candidate_attempt_ids: list[UUID]
    scores: dict[str, str]
    reason_codes: list[str] = Field(default_factory=list)


class AttemptSegmentationConfig(BaseModel):
    default_idle_timeout_seconds: Decimal = Decimal("30")
    default_response_timeout_seconds: Decimal = Decimal("10")
    default_idle_timeout_frames: int = 2000
    default_response_timeout_frames: int = 1000
    max_open_attempts_per_ue: int = 100
    minimum_assignment_confidence: Decimal = Decimal("0.70")
    profile_alternative_margin: Decimal = Decimal("0.10")
    max_profile_candidates_per_trigger: int = 20
    max_assignment_candidates_per_event: int = 20
    max_issue_samples_per_code: int = 20
    persist_unassigned_events: bool = True
    fsync_outputs: bool = True


class SegmentAttemptsRequest(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    normalization: NormalizeEventsResult
    identity_result: BuildIdentityGraphResult
    primary_reader: JsonlPrimaryEventReader
    identity_graph: IdentityGraphReader
    capture: CaptureMetadata
    profile_registry: ResolvedProfileRegistry
    run_dir: Path
    attempts_dir: Path
    indexes_dir: Path
    enabled_capabilities: set[str] = Field(default_factory=set)
    policy_versions: dict[str, str] = Field(default_factory=dict)
    config: AttemptSegmentationConfig = Field(default_factory=AttemptSegmentationConfig)


class SegmentAttemptsResult(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    status: Literal["success", "partial", "failed"]
    revision: str
    manifest: ArtifactDescriptor
    artifacts: list[ArtifactDescriptor]
    collections: list[CollectionDescriptor] = Field(default_factory=list)
    attempt_count: int
    outcome_counts: dict[str, int]
    profile_counts: dict[str, int]
    ambiguous_assignment_count: int
    unassigned_event_count: int
    transition_count: int
    retry_count: int
    profile_alternative_count: int
    stage_timing_count: int
    warning_counts: dict[str, int]
    elapsed_ms: int
    issues: list[Issue]
    manifest_path: Path


class AttemptsReader:
    def __init__(
        self,
        revision: str,
        attempts: list[ProcedureAttempt],
        assignments: list[AttemptEventAssignment],
        relationships: list[AttemptRelationship],
    ) -> None:
        self.revision = revision
        self.attempts = attempts
        self.assignments = assignments
        self.relationships = relationships
        self._attempts_by_id = {attempt.attempt_id: attempt for attempt in attempts}
        self._assignments_by_attempt: DefaultDict[UUID, list[AttemptEventAssignment]] = defaultdict(list)
        self._attempt_ids_by_event: DefaultDict[UUID, list[UUID]] = defaultdict(list)
        for assignment in assignments:
            self._assignments_by_attempt[assignment.attempt_id].append(assignment)
            self._attempt_ids_by_event[assignment.event_id].append(assignment.attempt_id)

    def for_attempt(self, attempt_id: UUID) -> ProcedureAttempt:
        return self._attempts_by_id[attempt_id]

    def assignments_for_attempt(self, attempt_id: UUID) -> list[AttemptEventAssignment]:
        return list(self._assignments_by_attempt.get(attempt_id, []))

    def attempts_for_event(self, event_id: UUID) -> list[ProcedureAttempt]:
        ids = self._attempt_ids_by_event.get(event_id, [])
        return [self._attempts_by_id[attempt_id] for attempt_id in ids]


@dataclass
class _OpenAttempt:
    attempt_id: UUID
    profile: ResolvedProcedureProfile
    ue_id: UUID | None
    session_node_id: UUID | None
    access_context_id: UUID | None
    access_family: AccessFamily
    access_anchor_type: AccessAnchorType
    initiator: Literal["UE", "NETWORK", "UNKNOWN"]
    start_event: CanonicalEvent
    start_nodes: list[IdentityNode]
    profile_alternatives: list[ProfileSelectionAlternative]
    incomplete_history: bool
    request_signature: dict[str, Any]
    correlation_identifiers: EventIdentifiers
    visibility: InterfaceVisibility
    roaming_topology: RoamingTopologyInterval | None
    parent_attempt_id: UUID | None = None
    child_attempt_ids: list[UUID] = field(default_factory=list)
    events: list[CanonicalEvent] = field(default_factory=list)
    assignments: list[AttemptEventAssignment] = field(default_factory=list)
    transitions: list[StateTransition] = field(default_factory=list)
    stage_timings: list[StageTimingObservation] = field(default_factory=list)
    matched_stage_ids: set[str] = field(default_factory=set)
    outcome: AttemptOutcome | None = None
    completion_reason: str | None = None
    issue_codes: list[str] = field(default_factory=list)


def open_attempts_reader(result: SegmentAttemptsResult) -> AttemptsReader:
    run_dir = result.manifest_path.parents[2]
    attempts = [
        ProcedureAttempt.model_validate(record)
        for record in iter_jsonl(run_dir / "normalized/attempts/attempts.jsonl")
    ]
    assignments = [
        AttemptEventAssignment.model_validate(record)
        for record in iter_jsonl(run_dir / "normalized/attempts/event_assignments.jsonl")
    ]
    relationships_path = run_dir / "normalized/attempts/relationships.jsonl"
    relationships = []
    if relationships_path.exists():
        relationships = [
            AttemptRelationship.model_validate(record)
            for record in iter_jsonl(relationships_path)
        ]
    return AttemptsReader(result.revision, attempts, assignments, relationships)


def segment_attempts(request: SegmentAttemptsRequest) -> SegmentAttemptsResult:
    started = datetime.now(tz=timezone.utc)
    validate_inside_run(request.run_dir, request.attempts_dir, request.indexes_dir)
    _validate_request(request)

    staging_root = request.run_dir / "staging" / f"T04-{request.analysis_id}"
    if staging_root.exists():
        for existing in sorted(staging_root.rglob("*"), reverse=True):
            if existing.is_file():
                existing.unlink()
            elif existing.is_dir():
                existing.rmdir()
    staging_root.mkdir(parents=True, exist_ok=True)

    attempts_writer = JsonlArtifactWriter(staging_root, request.run_dir, "normalized/attempts/attempts.jsonl", "procedure_attempts")
    assignments_writer = JsonlArtifactWriter(staging_root, request.run_dir, "normalized/attempts/event_assignments.jsonl", "attempt_event_assignments")
    relationships_writer = JsonlArtifactWriter(staging_root, request.run_dir, "normalized/attempts/relationships.jsonl", "attempt_relationships")
    ambiguities_writer = JsonlArtifactWriter(staging_root, request.run_dir, "normalized/attempts/ambiguous_assignments.jsonl", "attempt_ambiguous_assignments")
    unassigned_writer = JsonlArtifactWriter(staging_root, request.run_dir, "normalized/attempts/unassigned_events.jsonl", "attempt_unassigned_events")

    counters: dict[str, Any] = {
        "outcomes": defaultdict(int),
        "profiles": defaultdict(int),
        "warnings": defaultdict(int),
        "ambiguous": 0,
        "unassigned": 0,
        "transitions": 0,
        "retries": 0,
        "profile_alternatives": 0,
        "stage_timings": 0,
    }
    issues: list[Issue] = []

    events = sorted(
        list(request.primary_reader.by_frame(request.capture.first_frame, request.capture.last_frame)),
        key=lambda item: (item.frame, str(item.event_id)),
    )
    open_attempts: list[_OpenAttempt] = []
    completed: list[ProcedureAttempt] = []
    completed_assignments: list[AttemptEventAssignment] = []
    relationships: list[AttemptRelationship] = []
    previous_attempt_by_key: dict[tuple[str, UUID | None, UUID | None], ProcedureAttempt] = {}

    for event in events:
        expired = [
            (attempt, reason)
            for attempt in open_attempts
            if (reason := _timeout_reason_at_event(request, attempt, event)) is not None
        ]
        for expired_attempt, reason in expired:
            expired_attempt.outcome = "timed_out"
            expired_attempt.completion_reason = reason
            attempt = _complete_open_attempt(request, expired_attempt, previous_attempt_by_key, relationships, counters)
            completed.append(attempt)
            completed_assignments.extend(expired_attempt.assignments)
        if expired:
            expired_ids = {attempt.attempt_id for attempt, _ in expired}
            open_attempts = [attempt for attempt in open_attempts if attempt.attempt_id not in expired_ids]

        nodes = request.identity_graph.nodes_for_event(event.event_id)
        trigger_profiles = _profile_candidates(request, event)
        selected_profile = trigger_profiles[0] if trigger_profiles else None

        created_attempt: _OpenAttempt | None = None
        if selected_profile is not None and _open_attempt_count_for_scope(open_attempts, nodes) < request.config.max_open_attempts_per_ue:
            matching_open = _matching_open_attempt(open_attempts, event, nodes, selected_profile.profile.profile_id)
            if matching_open is None and selected_profile.score >= request.config.minimum_assignment_confidence:
                created_attempt = _open_attempt(request, event, nodes, trigger_profiles)
                _attach_open_parent(created_attempt, open_attempts)
                open_attempts.append(created_attempt)

        if created_attempt is not None:
            candidate_scores = [(selected_profile.score, created_attempt)]
        else:
            candidate_scores = _candidate_assignment_scores(
                open_attempts,
                event,
                nodes,
                request.config.max_assignment_candidates_per_event,
            )

        if not candidate_scores:
            if request.config.persist_unassigned_events:
                unassigned_writer.write(
                    UnassignedEventRecord(
                        event_id=event.event_id,
                        frame=event.frame,
                        protocol=event.protocol,
                        message_type=event.message_type,
                        reason_codes=["no_open_attempt"],
                    )
                )
            counters["unassigned"] += 1
            continue

        top_score, top_attempt = candidate_scores[0]
        if len(candidate_scores) > 1 and candidate_scores[1][0] == top_score:
            ambiguity = AttemptAmbiguityRecord(
                event_id=event.event_id,
                frame=event.frame,
                candidate_attempt_ids=[item[1].attempt_id for item in candidate_scores if item[0] == top_score],
                scores={str(item[1].attempt_id): format(item[0], "f") for item in candidate_scores if item[0] == top_score},
                reason_codes=["equal_top_score"],
            )
            ambiguities_writer.write(ambiguity)
            counters["ambiguous"] += 1
            issues.append(Issue(code="T04_ASSIGNMENT_AMBIGUOUS", stage="T04", message=f"event {event.event_id} had ambiguous attempt assignment"))

        if top_score < request.config.minimum_assignment_confidence:
            if request.config.persist_unassigned_events:
                unassigned_writer.write(
                    UnassignedEventRecord(
                        event_id=event.event_id,
                        frame=event.frame,
                        protocol=event.protocol,
                        message_type=event.message_type,
                        reason_codes=["assignment_below_threshold"],
                    )
                )
            counters["unassigned"] += 1
            continue

        assignment = _assign_event(
            request,
            top_attempt,
            event,
            top_score,
            reason_codes=["profile_trigger"] if top_attempt is created_attempt else ["identity_and_sequence"],
        )
        top_attempt.assignments.append(assignment)
        top_attempt.events.append(event)
        _advance_attempt(top_attempt, event)

        if top_attempt.outcome is not None:
            attempt = _complete_open_attempt(request, top_attempt, previous_attempt_by_key, relationships, counters)
            completed.append(attempt)
            completed_assignments.extend(top_attempt.assignments)
            open_attempts = [item for item in open_attempts if item.attempt_id != top_attempt.attempt_id]

    for open_attempt in sorted(open_attempts, key=lambda item: (item.start_event.frame, str(item.attempt_id))):
        if open_attempt.outcome is None:
            if _response_timeout_reached(request, open_attempt):
                open_attempt.outcome = "timed_out"
                open_attempt.completion_reason = "response_timeout"
            else:
                open_attempt.outcome = "incomplete_capture"
                open_attempt.completion_reason = "capture_ended_before_terminal"
        attempt = _complete_open_attempt(request, open_attempt, previous_attempt_by_key, relationships, counters)
        completed.append(attempt)
        completed_assignments.extend(open_attempt.assignments)

    completed.sort(key=lambda item: (item.start_frame, item.procedure_type, str(item.attempt_id)))
    _apply_sequence_numbers(completed)
    _infer_profile_relationships(request, completed, relationships)
    _finalize_parent_child_links(request, completed, relationships)
    event_frames = {event.event_id: event.frame for event in events}

    for attempt in completed:
        attempts_writer.write(attempt)
    for assignment in sorted(
        completed_assignments,
        key=lambda item: (
            event_frames[item.event_id],
            str(item.event_id),
            str(item.attempt_id),
            str(item.assignment_id),
        ),
    ):
        assignments_writer.write(assignment)
    for relationship in sorted(
        relationships,
        key=lambda item: (item.relation, str(item.left_attempt_id), str(item.right_attempt_id), str(item.relationship_id)),
    ):
        relationships_writer.write(relationship)

    indexes = _build_attempt_indexes(completed)

    attempts_closed = attempts_writer.close()
    assignments_closed = assignments_writer.close()
    relationships_closed = relationships_writer.close()
    ambiguities_closed = ambiguities_writer.close()
    unassigned_closed = unassigned_writer.close()
    index_closed = [
        JsonArtifactWriter(staging_root, request.run_dir, relative_path, "attempt_index").write(payload)
        for relative_path, payload in indexes.items()
    ]

    pre_revision = [
        attempts_closed.descriptor(creation_stage="T04", parent_source_sha256=request.normalization.manifest.sha256),
        assignments_closed.descriptor(creation_stage="T04", parent_source_sha256=request.normalization.manifest.sha256),
        relationships_closed.descriptor(creation_stage="T04", parent_source_sha256=request.normalization.manifest.sha256),
        ambiguities_closed.descriptor(creation_stage="T04", parent_source_sha256=request.normalization.manifest.sha256),
        unassigned_closed.descriptor(creation_stage="T04", parent_source_sha256=request.normalization.manifest.sha256),
        *[closed.descriptor(creation_stage="T04", parent_source_sha256=request.normalization.manifest.sha256) for closed in index_closed],
    ]
    revision = _build_t04_revision(request, pre_revision)
    artifacts: list[ArtifactDescriptor] = []
    for descriptor in pre_revision:
        descriptor.revision = revision
        artifacts.append(descriptor)

    ended = datetime.now(tz=timezone.utc)
    elapsed_ms = int((ended - started).total_seconds() * 1000)
    status: Literal["success", "partial", "failed"] = "partial" if counters["warnings"] or counters["ambiguous"] or counters["unassigned"] else "success"
    manifest_payload = {
        "schema_version": SCHEMA_VERSION,
        "tool": "T04",
        "analysis_id": str(request.analysis_id),
        "status": status,
        "revision": revision,
        "parent": {
            "normalization_revision": request.normalization.revision,
            "identity_revision": request.identity_result.revision,
            "capture_sha256": request.capture.source_sha256,
        },
        "profile_registry": request.profile_registry.model_dump(mode="json", exclude={"profiles"}),
        "config_sha256": sha256_bytes(compact_json_bytes(request.config)),
        "counts": {
            "attempt_count": len(completed),
            "outcome_counts": dict(sorted(counters["outcomes"].items())),
            "profile_counts": dict(sorted(counters["profiles"].items())),
            "ambiguous_assignment_count": counters["ambiguous"],
            "unassigned_event_count": counters["unassigned"],
            "transition_count": counters["transitions"],
            "retry_count": counters["retries"],
            "profile_alternative_count": counters["profile_alternatives"],
            "stage_timing_count": counters["stage_timings"],
            "warning_counts": dict(sorted(counters["warnings"].items())),
        },
        "artifacts": artifacts,
        "issues": sample_issues(issues, request.config.max_issue_samples_per_code),
        "timing": {
            "started_at": started.isoformat(),
            "ended_at": ended.isoformat(),
            "elapsed_ms": elapsed_ms,
        },
    }
    manifest_closed = JsonArtifactWriter(
        staging_root,
        request.run_dir,
        "normalized/attempts/attempts_manifest.json",
        "attempts_manifest",
    ).write(manifest_payload)
    publish_closed_artifacts(
        request.run_dir,
        [attempts_closed, assignments_closed, relationships_closed, ambiguities_closed, unassigned_closed, *index_closed, manifest_closed],
        manifest_relative_path="normalized/attempts/attempts_manifest.json",
    )
    manifest_path = request.run_dir / "normalized/attempts/attempts_manifest.json"
    manifest_descriptor = ArtifactDescriptor(
        artifact_id=str(deterministic_uuid(request.analysis_id, "T04", revision, "manifest")),
        relative_path="normalized/attempts/attempts_manifest.json",
        artifact_type="attempts_manifest",
        media_type="application/json",
        format_schema_version=SCHEMA_VERSION,
        sha256=sha256_file(manifest_path),
        byte_size=manifest_path.stat().st_size,
        record_count=1,
        creation_stage="T04",
        parent_source_sha256=request.normalization.manifest.sha256,
        revision=revision,
    )
    return SegmentAttemptsResult(
        analysis_id=request.analysis_id,
        status=status,
        revision=revision,
        manifest=manifest_descriptor,
        artifacts=artifacts,
        attempt_count=len(completed),
        outcome_counts=dict(sorted(counters["outcomes"].items())),
        profile_counts=dict(sorted(counters["profiles"].items())),
        ambiguous_assignment_count=counters["ambiguous"],
        unassigned_event_count=counters["unassigned"],
        transition_count=counters["transitions"],
        retry_count=counters["retries"],
        profile_alternative_count=counters["profile_alternatives"],
        stage_timing_count=counters["stage_timings"],
        warning_counts=dict(sorted(counters["warnings"].items())),
        elapsed_ms=elapsed_ms,
        issues=manifest_payload["issues"],
        manifest_path=manifest_path,
    )


def _validate_request(request: SegmentAttemptsRequest) -> None:
    if request.primary_reader.revision != request.normalization.revision:
        raise ValueError("primary reader revision does not match normalization revision")
    if request.identity_graph.revision != request.identity_result.revision:
        raise ValueError("identity graph reader revision does not match identity result revision")
    if request.capture.source_sha256 != request.normalization.manifest.parent_source_sha256:
        raise ValueError("capture source checksum does not match normalization lineage")
    declared = request.policy_versions.get("profile_registry")
    if declared is not None and declared != request.profile_registry.registry_version:
        raise ValueError("profile registry version does not match policy_versions")
    if request.config.minimum_assignment_confidence < 0 or request.config.minimum_assignment_confidence > 1:
        raise ValueError("minimum_assignment_confidence must be within [0,1]")
    if request.config.max_open_attempts_per_ue <= 0:
        raise ValueError("max_open_attempts_per_ue must be positive")
    if request.config.default_idle_timeout_frames <= 0 or request.config.default_response_timeout_frames <= 0:
        raise ValueError("frame timeout fallbacks must be positive")
    profile_ids = [profile.profile_id for profile in request.profile_registry.profiles]
    if len(profile_ids) != len(set(profile_ids)):
        raise ValueError("profile registry contains duplicate profile IDs")
    for profile in request.profile_registry.profiles:
        stage_ids = [stage.stage_id for stage in profile.stages]
        if len(stage_ids) != len(set(stage_ids)):
            raise ValueError(f"profile {profile.profile_id} contains duplicate stage IDs")
        known = set(stage_ids)
        for stage in profile.stages:
            if any(predecessor not in known for predecessor in stage.predecessor_ids):
                raise ValueError(f"profile {profile.profile_id} references an unknown predecessor")
            if stage.applicability == "conditional":
                if stage.applicability_condition is None:
                    raise ValueError(f"conditional stage {profile.profile_id}:{stage.stage_id} lacks an applicability condition")
                _validate_condition_expression(stage.applicability_condition)
            elif stage.applicability_condition is not None:
                raise ValueError(f"non-conditional stage {profile.profile_id}:{stage.stage_id} has an applicability condition")


def _validate_condition_expression(expression: dict[str, Any], *, depth: int = 1, node_count: list[int] | None = None) -> None:
    if node_count is None:
        node_count = [0]
    node_count[0] += 1
    if depth > 8 or node_count[0] > 64:
        raise ValueError("stage applicability condition exceeds complexity limits")
    op = expression.get("op")
    fact = expression.get("fact")
    children = expression.get("children", [])
    allowed_facts = (
        "request.",
        "attempt.",
        "profile.",
    )
    if op in {"and", "or"}:
        if fact is not None or "value" in expression or not isinstance(children, list) or len(children) < 2:
            raise ValueError(f"invalid {op} applicability condition")
    elif op == "not":
        if fact is not None or "value" in expression or not isinstance(children, list) or len(children) != 1:
            raise ValueError("invalid not applicability condition")
    elif op in {"present", "absent", "eq", "ne", "in"}:
        if not isinstance(fact, str) or not fact.startswith(allowed_facts) or children:
            raise ValueError(f"invalid {op} applicability fact")
        if op in {"present", "absent"} and "value" in expression:
            raise ValueError(f"{op} applicability condition must not include value")
        if op in {"eq", "ne", "in"} and "value" not in expression:
            raise ValueError(f"{op} applicability condition requires value")
        if op == "in" and not isinstance(expression.get("value"), list):
            raise ValueError("in applicability condition requires an array value")
        return
    else:
        raise ValueError(f"unsupported applicability operator {op!r}")
    for child in children:
        if not isinstance(child, dict):
            raise ValueError("applicability condition children must be objects")
        _validate_condition_expression(child, depth=depth + 1, node_count=node_count)


def _evaluate_stage_condition(expression: dict[str, Any] | None, attempt: _OpenAttempt) -> bool | None:
    if expression is None:
        return None
    op = expression["op"]
    if op in {"and", "or", "not"}:
        values = [_evaluate_stage_condition(child, attempt) for child in expression.get("children", [])]
        if op == "not":
            return None if values[0] is None else not values[0]
        if op == "and":
            if False in values:
                return False
            return None if None in values else True
        if True in values:
            return True
        return None if None in values else False

    facts = _stage_condition_facts(attempt)
    fact = expression["fact"]
    if fact not in facts:
        return None
    actual = facts[fact]
    if op == "present":
        return actual is not None
    if op == "absent":
        return actual is None
    expected = expression.get("value")
    if op == "eq":
        return actual == expected
    if op == "ne":
        return actual != expected
    return actual in expected


def _stage_condition_facts(attempt: _OpenAttempt) -> dict[str, Any]:
    facts = {f"request.{key}": value for key, value in attempt.request_signature.items()}
    facts.update(
        {
            "request.access_type": attempt.access_family,
            "request.access_anchor_type": attempt.access_anchor_type,
            "attempt.incomplete_history": attempt.incomplete_history,
            "attempt.roaming_topology": attempt.roaming_topology.selected_topology if attempt.roaming_topology else None,
            "profile.release": attempt.profile.release,
            "profile.deployment_profile": attempt.profile.deployment_profile,
        }
    )
    return facts


@dataclass
class _SelectedProfile:
    profile: ResolvedProcedureProfile
    score: Decimal
    reason_codes: list[str]


def _complete_open_attempt(
    request: SegmentAttemptsRequest,
    open_attempt: _OpenAttempt,
    previous_attempt_by_key: dict[tuple[str, UUID | None, UUID | None], ProcedureAttempt],
    relationships: list[AttemptRelationship],
    counters: dict[str, Any],
) -> ProcedureAttempt:
    attempt = _finalize_attempt(request, open_attempt)
    if _attach_retry_relationship(request, attempt, previous_attempt_by_key, relationships):
        counters["retries"] += 1
    counters["outcomes"][attempt.outcome] += 1
    counters["profiles"][attempt.profile_id] += 1
    counters["transitions"] += len(attempt.transitions)
    counters["profile_alternatives"] += len(attempt.profile_alternatives)
    counters["stage_timings"] += len(attempt.stage_timings)
    return attempt


def _open_attempt_count_for_scope(open_attempts: list[_OpenAttempt], nodes: list[IdentityNode]) -> int:
    ue_id = _first_node(nodes, "UE")
    access_context_id = _first_node(nodes, "ACCESS_CONTEXT")
    if ue_id is not None:
        return sum(attempt.ue_id == ue_id for attempt in open_attempts)
    if access_context_id is not None:
        return sum(attempt.access_context_id == access_context_id for attempt in open_attempts)
    return sum(attempt.ue_id is None and attempt.access_context_id is None for attempt in open_attempts)


def _idle_timeout_reached(
    request: SegmentAttemptsRequest,
    attempt: _OpenAttempt,
    event: CanonicalEvent,
) -> bool:
    last_event = attempt.events[-1] if attempt.events else attempt.start_event
    if last_event.timestamp is not None and event.timestamp is not None:
        return event.timestamp - last_event.timestamp > request.config.default_idle_timeout_seconds
    return event.frame - last_event.frame > request.config.default_idle_timeout_frames


def _timeout_reason_at_event(
    request: SegmentAttemptsRequest,
    attempt: _OpenAttempt,
    event: CanonicalEvent,
) -> str | None:
    last_event = attempt.events[-1] if attempt.events else attempt.start_event
    response_timeout = (
        attempt.profile.stages[-1].timeout_seconds
        if attempt.profile.stages and attempt.profile.stages[-1].timeout_seconds is not None
        else request.config.default_response_timeout_seconds
    )
    if last_event.timestamp is not None and event.timestamp is not None:
        elapsed = event.timestamp - last_event.timestamp
        if elapsed > response_timeout:
            return "response_timeout"
        if elapsed > request.config.default_idle_timeout_seconds:
            return "idle_timeout"
        return None
    frame_gap = event.frame - last_event.frame
    if frame_gap > request.config.default_response_timeout_frames:
        return "response_timeout"
    if frame_gap > request.config.default_idle_timeout_frames:
        return "idle_timeout"
    return None


def _response_timeout_reached(request: SegmentAttemptsRequest, attempt: _OpenAttempt) -> bool:
    last_event = attempt.events[-1] if attempt.events else attempt.start_event
    timeout = attempt.profile.stages[-1].timeout_seconds if attempt.profile.stages and attempt.profile.stages[-1].timeout_seconds is not None else request.config.default_response_timeout_seconds
    if request.capture.last_timestamp is not None and last_event.timestamp is not None:
        return request.capture.last_timestamp - last_event.timestamp > timeout
    return request.capture.last_frame - last_event.frame > request.config.default_response_timeout_frames


def _profile_candidates(request: SegmentAttemptsRequest, event: CanonicalEvent) -> list[_SelectedProfile]:
    candidates: list[_SelectedProfile] = []
    for profile in request.profile_registry.profiles:
        matched = [matcher for matcher in profile.trigger_matchers if _event_matches(event, matcher)]
        if not matched:
            continue
        score = Decimal("0.80")
        reasons = ["trigger_match"]
        if profile.procedure_type.startswith("INITIAL_") and event.protocol == "NAS":
            score += Decimal("0.10")
            reasons.append("nas_primary_trigger")
        if event.identifiers.pdu_session_id is not None:
            score += Decimal("0.05")
            reasons.append("session_identifier_present")
        candidates.append(_SelectedProfile(profile=profile, score=min(score, Decimal("1.0")), reason_codes=reasons))
    candidates.sort(key=lambda item: (item.score, item.profile.profile_id), reverse=True)
    if not candidates:
        return []
    selected = [candidates[0]]
    margin = request.config.profile_alternative_margin
    for candidate in candidates[1 : request.config.max_profile_candidates_per_trigger]:
        if selected[0].score - candidate.score <= margin:
            selected.append(candidate)
    return selected


def _matching_open_attempt(
    open_attempts: list[_OpenAttempt],
    event: CanonicalEvent,
    nodes: list[IdentityNode],
    profile_id: str,
) -> _OpenAttempt | None:
    event_access_context = _first_node(nodes, "ACCESS_CONTEXT")
    best: tuple[Decimal, _OpenAttempt] | None = None
    for attempt in open_attempts:
        if attempt.profile.profile_id != profile_id:
            continue
        if attempt.access_context_id is not None and event_access_context is not None and attempt.access_context_id != event_access_context:
            continue
        score = _assignment_score(attempt, event, nodes)
        if best is None or score > best[0]:
            best = (score, attempt)
    if best is not None and best[0] >= Decimal("0.90"):
        return best[1]
    return None


def _open_attempt(
    request: SegmentAttemptsRequest,
    event: CanonicalEvent,
    nodes: list[IdentityNode],
    selected_profiles: list[_SelectedProfile],
) -> _OpenAttempt:
    primary = selected_profiles[0]
    ue_id = _first_node(nodes, "UE")
    access_context_id = _first_node(nodes, "ACCESS_CONTEXT")
    session_node_id = _first_node(nodes, "PDU_SESSION")
    visibility = _attempt_visibility(primary.profile)
    request_signature = _request_signature(primary.profile, event)
    correlation_identifiers = _event_correlation_identifiers(event)
    return _OpenAttempt(
        attempt_id=deterministic_uuid(
            request.analysis_id,
            request.normalization.revision,
            request.identity_result.revision,
            primary.profile.profile_id,
            event.event_id,
        ),
        profile=primary.profile,
        ue_id=ue_id,
        session_node_id=session_node_id,
        access_context_id=access_context_id,
        access_family=_access_family(primary.profile, event),
        access_anchor_type=_access_anchor(nodes),
        initiator=_initiator_for_event(event),
        start_event=event,
        start_nodes=nodes,
        profile_alternatives=[
            ProfileSelectionAlternative(profile_id=item.profile.profile_id, score=item.score, reason_codes=item.reason_codes)
            for item in selected_profiles[1:]
        ],
        incomplete_history=event.frame == request.capture.first_frame,
        request_signature=request_signature,
        correlation_identifiers=correlation_identifiers,
        visibility=visibility,
        roaming_topology=_topology_for_nodes(request.identity_graph, nodes, event.frame),
    )


def _candidate_assignment_scores(
    open_attempts: list[_OpenAttempt],
    event: CanonicalEvent,
    nodes: list[IdentityNode],
    limit: int,
) -> list[tuple[Decimal, _OpenAttempt]]:
    scored = [(_assignment_score(attempt, event, nodes), attempt) for attempt in open_attempts]
    scored = [item for item in scored if item[0] > 0]
    scored.sort(key=lambda item: (item[0], str(item[1].attempt_id)), reverse=True)
    return scored[:limit]


def _assignment_score(attempt: _OpenAttempt, event: CanonicalEvent, nodes: list[IdentityNode]) -> Decimal:
    event_access_context = _first_node(nodes, "ACCESS_CONTEXT")
    if attempt.access_context_id is not None and event_access_context is not None and attempt.access_context_id != event_access_context:
        return Decimal("0")
    score = Decimal("0.0")
    if attempt.ue_id is not None and attempt.ue_id == _first_node(nodes, "UE"):
        score += Decimal("0.35")
    if attempt.access_context_id is not None and attempt.access_context_id == _first_node(nodes, "ACCESS_CONTEXT"):
        score += Decimal("0.25")
    if attempt.session_node_id is not None and attempt.session_node_id == _first_node(nodes, "PDU_SESSION"):
        score += Decimal("0.20")
    if attempt.correlation_identifiers.pdu_session_id is not None and attempt.correlation_identifiers.pdu_session_id == event.identifiers.pdu_session_id:
        score += Decimal("0.15")
    if (
        attempt.correlation_identifiers.amf_ue_ngap_id is not None
        and attempt.correlation_identifiers.amf_ue_ngap_id == event.identifiers.amf_ue_ngap_id
    ):
        score += Decimal("0.10")
    if (
        attempt.correlation_identifiers.ran_ue_ngap_id is not None
        and attempt.correlation_identifiers.ran_ue_ngap_id == event.identifiers.ran_ue_ngap_id
    ):
        score += Decimal("0.10")
    if attempt.events and event.frame >= attempt.events[-1].frame:
        score += Decimal("0.05")
    return min(score, Decimal("1.0"))


def _assign_event(
    request: SegmentAttemptsRequest,
    attempt: _OpenAttempt,
    event: CanonicalEvent,
    score: Decimal,
    *,
    reason_codes: list[str],
) -> AttemptEventAssignment:
    return AttemptEventAssignment(
        assignment_id=deterministic_uuid(request.analysis_id, "T04", attempt.attempt_id, event.event_id),
        event_id=event.event_id,
        attempt_id=attempt.attempt_id,
        confidence=max(score, request.config.minimum_assignment_confidence),
        strength="exact" if score >= Decimal("0.90") else "strong" if score >= Decimal("0.75") else "supporting",
        reason_codes=reason_codes,
        profile_stage_ids=_matching_stage_ids(attempt.profile, event),
        shared_by_nesting_rule=False,
    )


def _advance_attempt(attempt: _OpenAttempt, event: CanonicalEvent) -> None:
    matched_stage_ids = _matching_stage_ids(attempt.profile, event)
    for stage_id in matched_stage_ids:
        if stage_id in attempt.matched_stage_ids and not _stage_is_repeatable(attempt.profile, stage_id):
            continue
        attempt.matched_stage_ids.add(stage_id)
        stage = _stage_by_id(attempt.profile, stage_id)
        attempt.transitions.append(
            StateTransition(
                transition_id=deterministic_uuid(attempt.attempt_id, "transition", stage.stage_id, event.event_id),
                stage_id=stage.stage_id,
                stage_name=stage.name,
                event_id=event.event_id,
                frame=event.frame,
                timestamp=event.timestamp,
                transition_type="completed",
            )
        )
        attempt.stage_timings.append(
            StageTimingObservation(
                stage_timing_id=deterministic_uuid(attempt.attempt_id, "stage_timing", stage.stage_id, event.event_id),
                stage_id=stage.stage_id,
                stage_name=stage.name,
                first_event_id=event.event_id,
                first_frame=event.frame,
                first_timestamp=event.timestamp,
                last_event_id=event.event_id,
                last_frame=event.frame,
                last_timestamp=event.timestamp,
                status="observed",
            )
        )
        if stage.terminal_success:
            attempt.outcome = "succeeded"
            attempt.completion_reason = f"stage:{stage.stage_id}"
        if stage.terminal_failure:
            attempt.outcome = "failed"
            attempt.completion_reason = f"stage:{stage.stage_id}"

    if attempt.outcome is None:
        if any(_event_matches(event, matcher) for matcher in attempt.profile.success_terminals):
            attempt.outcome = "succeeded"
            attempt.completion_reason = "success_terminal"
        elif any(_event_matches(event, matcher) for matcher in attempt.profile.failure_terminals):
            attempt.outcome = "failed"
            attempt.completion_reason = "failure_terminal"
        elif any(_event_matches(event, matcher) for matcher in attempt.profile.abort_terminals):
            attempt.outcome = "aborted"
            attempt.completion_reason = "abort_terminal"


def _finalize_attempt(
    request: SegmentAttemptsRequest,
    open_attempt: _OpenAttempt,
) -> ProcedureAttempt:
    events = sorted(open_attempt.events, key=lambda item: (item.frame, str(item.event_id)))
    if not events:
        events = [open_attempt.start_event]
    correlation = open_attempt.correlation_identifiers.model_copy(deep=True)
    for event in events:
        for field_name, value in event.identifiers.model_dump(exclude_none=True).items():
            if getattr(correlation, field_name) is None:
                setattr(correlation, field_name, value)
    stage_timings = list(open_attempt.stage_timings)
    observed_stage_ids = {item.stage_id for item in stage_timings}
    for stage in sorted(open_attempt.profile.stages, key=lambda item: (item.order, item.stage_id)):
        if stage.stage_id in observed_stage_ids or stage.applicability == "optional":
            continue
        status: Literal["missing", "skipped", "inconclusive"] = "missing"
        if stage.applicability == "conditional":
            applicability = _evaluate_stage_condition(stage.applicability_condition, open_attempt)
            status = "missing" if applicability is True else "skipped" if applicability is False else "inconclusive"
            if applicability is None:
                open_attempt.issue_codes.append("T04_STAGE_APPLICABILITY_UNKNOWN")
        stage_timings.append(
            StageTimingObservation(
                stage_timing_id=deterministic_uuid(open_attempt.attempt_id, "stage_timing", stage.stage_id, "unobserved"),
                stage_id=stage.stage_id,
                stage_name=stage.name,
                first_event_id=open_attempt.start_event.event_id,
                first_frame=open_attempt.start_event.frame,
                first_timestamp=open_attempt.start_event.timestamp,
                last_event_id=events[-1].event_id,
                last_frame=events[-1].frame,
                last_timestamp=events[-1].timestamp,
                status=status,
            )
        )
    return ProcedureAttempt(
        attempt_id=open_attempt.attempt_id,
        analysis_id=request.analysis_id,
        ue_id=open_attempt.ue_id,
        session_node_id=open_attempt.session_node_id,
        access_context_id=open_attempt.access_context_id,
        access_family=open_attempt.access_family,
        access_anchor_type=open_attempt.access_anchor_type,
        profile_id=open_attempt.profile.profile_id,
        profile_alternatives=open_attempt.profile_alternatives,
        profile_selection_status="ambiguous" if open_attempt.profile_alternatives else "selected",
        procedure_type=open_attempt.profile.procedure_type,
        subtype=None,
        sequence_number=0,
        initiator=open_attempt.initiator,
        parent_attempt_id=open_attempt.parent_attempt_id,
        child_attempt_ids=sorted(open_attempt.child_attempt_ids, key=str),
        start_frame=events[0].frame,
        end_frame=events[-1].frame,
        start_timestamp=events[0].timestamp,
        end_timestamp=events[-1].timestamp,
        incomplete_history=open_attempt.incomplete_history,
        trigger_event_ids=[open_attempt.start_event.event_id],
        event_ids=[event.event_id for event in events],
        correlation_identifiers=correlation,
        request_signature=open_attempt.request_signature,
        transitions=sorted(open_attempt.transitions, key=lambda item: (item.frame, item.stage_id, str(item.transition_id))),
        retries=[],
        stage_timings=sorted(stage_timings, key=lambda item: (item.first_frame, item.stage_id, str(item.stage_timing_id))),
        outcome=open_attempt.outcome or "incomplete_capture",
        completion_reason=open_attempt.completion_reason or "capture_ended_before_terminal",
        assignment_confidence=_assignment_confidence(open_attempt.assignments),
        visibility=open_attempt.visibility,
        roaming_topology=open_attempt.roaming_topology,
        issue_codes=sorted(set(open_attempt.issue_codes)),
    )


def _attach_retry_relationship(
    request: SegmentAttemptsRequest,
    attempt: ProcedureAttempt,
    previous_attempt_by_key: dict[tuple[str, UUID | None, UUID | None], ProcedureAttempt],
    relationships: list[AttemptRelationship],
) -> bool:
    retry_key = (attempt.profile_id, attempt.ue_id, attempt.session_node_id)
    prior = previous_attempt_by_key.get(retry_key)
    previous_attempt_by_key[retry_key] = attempt
    if prior is None or prior.outcome == "succeeded":
        return False
    profile = next((item for item in request.profile_registry.profiles if item.profile_id == attempt.profile_id), None)
    gap_seconds = _gap_seconds(prior.end_timestamp, attempt.start_timestamp)
    if profile is not None and profile.retry_window_seconds is not None and gap_seconds is not None and gap_seconds > profile.retry_window_seconds:
        return False

    retry = RetryRecord(
        retry_id=deterministic_uuid(
            request.analysis_id,
            "T04",
            "retry",
            prior.attempt_id,
            attempt.attempt_id,
        ),
        prior_attempt_id=prior.attempt_id,
        next_attempt_id=attempt.attempt_id,
        trigger_event_id=attempt.trigger_event_ids[0],
        frame_gap=max(0, attempt.start_frame - prior.end_frame),
        time_gap_seconds=gap_seconds,
        reason_codes=["same_profile_retry"],
    )
    attempt.retries.append(retry)
    relationships.append(
        AttemptRelationship(
            relationship_id=deterministic_uuid(
                request.analysis_id,
                "T04",
                "relationship",
                "retry_of",
                prior.attempt_id,
                attempt.attempt_id,
            ),
            left_attempt_id=attempt.attempt_id,
            right_attempt_id=prior.attempt_id,
            relation="retry_of",
            evidence_event_ids=attempt.trigger_event_ids[:1],
            profile_rule_id="default_retry_window",
        )
    )
    return True


def _attach_open_parent(child: _OpenAttempt, open_attempts: list[_OpenAttempt]) -> None:
    if not child.profile.parent_profile_ids:
        return
    candidates = [
        attempt
        for attempt in open_attempts
        if attempt.profile.profile_id in child.profile.parent_profile_ids
        and _same_identity_scope(child, attempt)
    ]
    if not candidates:
        return
    parent = max(candidates, key=lambda item: (item.start_event.frame, str(item.attempt_id)))
    child.parent_attempt_id = parent.attempt_id
    if child.attempt_id not in parent.child_attempt_ids:
        parent.child_attempt_ids.append(child.attempt_id)
        parent.child_attempt_ids.sort(key=str)


def _infer_profile_relationships(
    request: SegmentAttemptsRequest,
    attempts: list[ProcedureAttempt],
    relationships: list[AttemptRelationship],
) -> None:
    profiles = {profile.profile_id: profile for profile in request.profile_registry.profiles}
    relationship_keys = {
        (relationship.relation, relationship.left_attempt_id, relationship.right_attempt_id)
        for relationship in relationships
    }
    ordered = sorted(attempts, key=lambda item: (item.start_frame, item.end_frame, str(item.attempt_id)))
    for attempt in ordered:
        profile = profiles.get(attempt.profile_id)
        if profile is None:
            continue
        if attempt.parent_attempt_id is None and profile.parent_profile_ids:
            parent = _nearest_prior_attempt(
                ordered,
                attempt,
                profile_ids=set(profile.parent_profile_ids),
                require_overlap=True,
                require_different_access=False,
            )
            if parent is not None:
                attempt.parent_attempt_id = parent.attempt_id
        if profile.transfer_from_profile_ids:
            prior = _nearest_prior_attempt(
                ordered,
                attempt,
                profile_ids=set(profile.transfer_from_profile_ids),
                require_overlap=False,
                require_different_access=True,
            )
            if prior is not None:
                _append_relationship(
                    request,
                    relationships,
                    relationship_keys,
                    relation="access_transfer",
                    left_attempt_id=attempt.attempt_id,
                    right_attempt_id=prior.attempt_id,
                    evidence_event_ids=attempt.trigger_event_ids[:1],
                    profile_rule_id="profile_access_transfer",
                )
        for prior in _nearest_prior_attempts_by_profile(
            ordered,
            attempt,
            profile_ids=set(profile.closes_profile_ids),
        ):
            _append_relationship(
                request,
                relationships,
                relationship_keys,
                relation="supersedes",
                left_attempt_id=attempt.attempt_id,
                right_attempt_id=prior.attempt_id,
                evidence_event_ids=attempt.trigger_event_ids[:1],
                profile_rule_id="profile_closes_prior_attempt",
            )


def _nearest_prior_attempt(
    attempts: list[ProcedureAttempt],
    current: ProcedureAttempt,
    *,
    profile_ids: set[str],
    require_overlap: bool,
    require_different_access: bool,
) -> ProcedureAttempt | None:
    candidates = []
    for prior in attempts:
        if prior.attempt_id == current.attempt_id or prior.profile_id not in profile_ids:
            continue
        if prior.start_frame > current.start_frame:
            continue
        if require_overlap and prior.end_frame < current.start_frame:
            continue
        if not _same_attempt_identity(current, prior):
            continue
        if require_different_access:
            if current.access_context_id is None or prior.access_context_id is None:
                continue
            if current.access_context_id == prior.access_context_id:
                continue
        candidates.append(prior)
    if not candidates:
        return None
    return max(candidates, key=lambda item: (item.end_frame, item.start_frame, str(item.attempt_id)))


def _nearest_prior_attempts_by_profile(
    attempts: list[ProcedureAttempt],
    current: ProcedureAttempt,
    *,
    profile_ids: set[str],
) -> list[ProcedureAttempt]:
    selected: dict[str, ProcedureAttempt] = {}
    for prior in attempts:
        if prior.attempt_id == current.attempt_id or prior.profile_id not in profile_ids:
            continue
        if prior.start_frame > current.start_frame or not _same_attempt_identity(current, prior):
            continue
        if current.access_context_id is not None and prior.access_context_id is not None and current.access_context_id != prior.access_context_id:
            continue
        existing = selected.get(prior.profile_id)
        if existing is None or (prior.end_frame, prior.start_frame, str(prior.attempt_id)) > (existing.end_frame, existing.start_frame, str(existing.attempt_id)):
            selected[prior.profile_id] = prior
    return [selected[profile_id] for profile_id in sorted(selected)]


def _same_identity_scope(left: _OpenAttempt, right: _OpenAttempt) -> bool:
    if left.ue_id is not None and right.ue_id is not None and left.ue_id != right.ue_id:
        return False
    if left.session_node_id is not None and right.session_node_id is not None and left.session_node_id != right.session_node_id:
        return False
    if left.access_context_id is not None and right.access_context_id is not None and left.access_context_id != right.access_context_id:
        return False
    return True


def _same_attempt_identity(left: ProcedureAttempt, right: ProcedureAttempt) -> bool:
    if left.ue_id is not None and right.ue_id is not None and left.ue_id != right.ue_id:
        return False
    if left.session_node_id is not None and right.session_node_id is not None and left.session_node_id != right.session_node_id:
        return False
    return True


def _append_relationship(
    request: SegmentAttemptsRequest,
    relationships: list[AttemptRelationship],
    relationship_keys: set[tuple[str, UUID, UUID]],
    *,
    relation: Literal["parent_child", "retry_of", "supersedes", "access_transfer"],
    left_attempt_id: UUID,
    right_attempt_id: UUID,
    evidence_event_ids: list[UUID],
    profile_rule_id: str,
) -> None:
    key = (relation, left_attempt_id, right_attempt_id)
    if key in relationship_keys:
        return
    relationships.append(
        AttemptRelationship(
            relationship_id=deterministic_uuid(
                request.analysis_id,
                "T04",
                "relationship",
                relation,
                left_attempt_id,
                right_attempt_id,
            ),
            left_attempt_id=left_attempt_id,
            right_attempt_id=right_attempt_id,
            relation=relation,
            evidence_event_ids=evidence_event_ids,
            profile_rule_id=profile_rule_id,
        )
    )
    relationship_keys.add(key)


def _finalize_parent_child_links(
    request: SegmentAttemptsRequest,
    attempts: list[ProcedureAttempt],
    relationships: list[AttemptRelationship],
) -> None:
    attempts_by_id = {attempt.attempt_id: attempt for attempt in attempts}
    relationship_keys = {
        (relationship.relation, relationship.left_attempt_id, relationship.right_attempt_id)
        for relationship in relationships
    }
    for child in attempts:
        if child.parent_attempt_id is None:
            continue
        parent = attempts_by_id.get(child.parent_attempt_id)
        if parent is None:
            child.issue_codes = sorted(set([*child.issue_codes, "T04_PARENT_ATTEMPT_MISSING"]))
            continue
        if child.attempt_id not in parent.child_attempt_ids:
            parent.child_attempt_ids.append(child.attempt_id)
            parent.child_attempt_ids.sort(key=str)
        key = ("parent_child", parent.attempt_id, child.attempt_id)
        if key in relationship_keys:
            continue
        _append_relationship(
            request,
            relationships,
            relationship_keys,
            relation="parent_child",
            left_attempt_id=parent.attempt_id,
            right_attempt_id=child.attempt_id,
            evidence_event_ids=child.trigger_event_ids[:1],
            profile_rule_id="explicit_parent_attempt",
        )


def _apply_sequence_numbers(attempts: list[ProcedureAttempt]) -> None:
    counters: DefaultDict[tuple[UUID | None, str], int] = defaultdict(int)
    for attempt in attempts:
        key = (attempt.ue_id, attempt.procedure_type)
        counters[key] += 1
        attempt.sequence_number = counters[key]


def _build_attempt_indexes(attempts: list[ProcedureAttempt]) -> dict[str, Any]:
    by_ue: DefaultDict[str, list[str]] = defaultdict(list)
    by_profile: DefaultDict[str, list[str]] = defaultdict(list)
    by_session: DefaultDict[str, list[str]] = defaultdict(list)
    for attempt in attempts:
        if attempt.ue_id is not None:
            by_ue[str(attempt.ue_id)].append(str(attempt.attempt_id))
        by_profile[attempt.profile_id].append(str(attempt.attempt_id))
        if attempt.session_node_id is not None:
            by_session[str(attempt.session_node_id)].append(str(attempt.attempt_id))
    return {
        "indexes/attempts_by_ue.json": dict(sorted(by_ue.items())),
        "indexes/attempts_by_profile.json": dict(sorted(by_profile.items())),
        "indexes/attempts_by_session.json": dict(sorted(by_session.items())),
    }


def _build_t04_revision(request: SegmentAttemptsRequest, descriptors: Iterable[ArtifactDescriptor]) -> str:
    payload = {
        "tool": "T04",
        "version": ATTEMPTS_VERSION,
        "analysis_id": str(request.analysis_id),
        "normalization_revision": request.normalization.revision,
        "identity_revision": request.identity_result.revision,
        "profile_registry_sha256": request.profile_registry.sha256,
        "config_sha256": sha256_bytes(compact_json_bytes(request.config)),
        "artifact_sha256s": [descriptor.sha256 for descriptor in sorted(descriptors, key=lambda item: item.relative_path)],
    }
    return "sha256:" + sha256_bytes(compact_json_bytes(payload))


def _event_matches(event: CanonicalEvent, matcher: EventMatcher) -> bool:
    if matcher.protocol is not None and event.protocol != matcher.protocol:
        return False
    if matcher.message_types and event.message_type not in matcher.message_types:
        return False
    if matcher.outcomes and event.outcome not in matcher.outcomes:
        return False
    for key, value in matcher.attribute_equals.items():
        if event.attributes.get(key) != value:
            return False
    for key in matcher.identifier_present:
        if getattr(event.identifiers, key, None) in {None, ""}:
            return False
    return True


def _matching_stage_ids(profile: ResolvedProcedureProfile, event: CanonicalEvent) -> list[str]:
    stage_ids = []
    for stage in sorted(profile.stages, key=lambda item: (item.order, item.stage_id)):
        if any(_event_matches(event, matcher) for matcher in stage.event_matchers):
            stage_ids.append(stage.stage_id)
    return stage_ids


def _stage_is_repeatable(profile: ResolvedProcedureProfile, stage_id: str) -> bool:
    stage = _stage_by_id(profile, stage_id)
    return stage.applicability == "repeatable"


def _stage_by_id(profile: ResolvedProcedureProfile, stage_id: str) -> StageDefinition:
    for stage in profile.stages:
        if stage.stage_id == stage_id:
            return stage
    raise KeyError(stage_id)


def _first_node(nodes: list[IdentityNode], node_type: str) -> UUID | None:
    for node in nodes:
        if node.node_type == node_type:
            return node.node_id
    return None


def _access_family(profile: ResolvedProcedureProfile, event: CanonicalEvent) -> AccessFamily:
    del profile
    if event.protocol in {"NAS", "NGAP"}:
        return "3gpp"
    return "unknown"


def _access_anchor(nodes: list[IdentityNode]) -> AccessAnchorType:
    del nodes
    return "GNB"


def _initiator_for_event(event: CanonicalEvent) -> Literal["UE", "NETWORK", "UNKNOWN"]:
    if event.protocol in {"NAS", "NGAP"} and "REQUEST" in event.message_type:
        return "UE"
    if "PAGING" in event.message_type or "DEREGISTRATION_REQUEST" in event.message_type:
        return "NETWORK"
    return "UNKNOWN"


def _attempt_visibility(profile: ResolvedProcedureProfile) -> InterfaceVisibility:
    visibility = InterfaceVisibility()
    for stage in profile.stages:
        for requirement in stage.visibility_requirements:
            state = "visible"
            if requirement.domain == "reference_point":
                visibility.reference_points[requirement.key] = state
            elif requirement.domain == "sbi_service":
                visibility.services[requirement.key] = state
            else:
                visibility.apis[requirement.key] = state
    return visibility


def _request_signature(profile: ResolvedProcedureProfile, event: CanonicalEvent) -> dict[str, Any]:
    signature: dict[str, Any] = {
        "procedure_type": profile.procedure_type,
        "message_type": event.message_type,
    }
    if "REGISTRATION" in profile.procedure_type:
        signature["registration_type"] = "initial"
    if event.identifiers.pdu_session_id is not None:
        signature["pdu_session_id"] = event.identifiers.pdu_session_id
    if event.identifiers.procedure_transaction_id is not None:
        signature["procedure_transaction_id"] = event.identifiers.procedure_transaction_id
    return signature


def _event_correlation_identifiers(event: CanonicalEvent) -> EventIdentifiers:
    return event.identifiers.model_copy(deep=True)


def _topology_for_nodes(graph: IdentityGraphReader, nodes: list[IdentityNode], frame: int) -> RoamingTopologyInterval | None:
    for node in nodes:
        topology = graph.topology_at(node.node_id, frame)
        if topology is not None:
            return topology
    return None


def _assignment_confidence(assignments: list[AttemptEventAssignment]) -> AssignmentConfidence:
    if not assignments:
        return "low"
    minimum = min(assignment.confidence for assignment in assignments)
    if minimum >= Decimal("0.90"):
        return "high"
    if minimum >= Decimal("0.75"):
        return "medium"
    return "low"


def _gap_seconds(start: Decimal | None, end: Decimal | None) -> Decimal | None:
    if start is None or end is None:
        return None
    return max(Decimal("0"), end - start)
