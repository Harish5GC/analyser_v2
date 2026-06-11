"""Baseline T11-T25 implementation layer."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import signal
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, DefaultDict, Iterable, Literal
from urllib import error as urllib_error
from urllib import request as urllib_request
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from harness.attempts import ProcedureAttempt, SegmentAttemptsResult
from harness.decoder.manifest import ArtifactDescriptor
from harness.diagnostics import (
    AttemptTimelineResult,
    FailureCandidate,
    FindHTTPFailuresResult,
    FindNASNGAPFailuresResult,
    FindPFCPFailuresResult,
    MaskedUEIdentity,
    ScoreTerm,
    TerminalEffect,
    UERequestResult,
)
from harness.normalize import JsonlPrimaryEventReader, NormalizeEventsResult
from harness.shared import (
    CanonicalEvent,
    Endpoint,
    Issue,
    JsonArtifactWriter,
    JsonlArtifactWriter,
    SourceRef,
    artifact_by_relative_path,
    compact_json_bytes,
    deterministic_uuid,
    iter_jsonl,
    publish_closed_artifacts,
    reset_staging_directory,
    sha256_bytes,
    sha256_file,
    validate_inside_run,
)

SCHEMA_VERSION = "2.0"
POST_VERSION = "2.0.0"
EvidenceStage = Literal["primary", "dependency_expanded"]
ModelPass = Literal["initial", "final"]


class FieldDifference(BaseModel):
    field_name: str
    failed_value: Any | None
    baseline_value: Any | None
    category: str


class StageAlignment(BaseModel):
    stage_id: str
    occurrence: int = 1
    failed_status: str
    baseline_status: str
    relation: Literal["matched", "changed", "missing_in_failed", "extra_in_failed", "not_comparable"]
    failed_evidence_ids: list[UUID] = Field(default_factory=list)
    baseline_evidence_ids: list[UUID] = Field(default_factory=list)


class AttemptDivergence(BaseModel):
    divergence_id: UUID
    stage_id: str
    category: str
    failed_value: Any | None
    baseline_value: Any | None
    failed_evidence_ids: list[UUID] = Field(default_factory=list)
    baseline_evidence_ids: list[UUID] = Field(default_factory=list)
    causal_relevance: Literal["strong", "supporting", "unknown"]
    rationale: str


class AttemptComparison(BaseModel):
    comparison_id: UUID
    failed_attempt_id: UUID
    baseline_attempt_id: UUID
    baseline_score: Decimal
    baseline_reasons: list[str] = Field(default_factory=list)
    request_differences: list[FieldDifference] = Field(default_factory=list)
    stage_alignment: list[StageAlignment] = Field(default_factory=list)
    first_divergence: AttemptDivergence | None = None
    later_divergences: list[AttemptDivergence] = Field(default_factory=list)
    visibility_limitations: list[str] = Field(default_factory=list)
    evidence_ids: list[UUID] = Field(default_factory=list)


class CompareAttemptsRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    failed_attempt: ProcedureAttempt
    candidate_baselines: list[ProcedureAttempt] = Field(default_factory=list)
    failed_request: UERequestResult
    baseline_requests: list[UERequestResult] = Field(default_factory=list)
    max_baselines: int = 2


class CompareAttemptsResult(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    failed_attempt_id: UUID
    selected_baseline_id: UUID | None
    comparisons: list[AttemptComparison]
    no_baseline_reason: str | None = None
    warnings: list[str] = Field(default_factory=list)


class RankedCandidate(BaseModel):
    candidate_id: UUID
    eligible: bool
    final_score: Decimal | None
    score_terms: list[ScoreTerm] = Field(default_factory=list)
    rank: int | None = None
    classification: Literal["primary", "alternative", "downstream", "excluded"]
    exclusion_reasons: list[str] = Field(default_factory=list)


class RootCauseResult(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    attempt_id: UUID
    pass_stage: EvidenceStage
    primary_candidate_id: UUID | None
    alternative_candidate_ids: list[UUID] = Field(default_factory=list)
    downstream_candidate_ids: list[UUID] = Field(default_factory=list)
    excluded_candidate_ids: list[UUID] = Field(default_factory=list)
    ranked_candidates: list[RankedCandidate] = Field(default_factory=list)
    candidate_records: list[FailureCandidate] = Field(default_factory=list)
    confidence: Literal["high", "medium", "low", "inconclusive"]
    rationale_codes: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    parent_ranking_revision: str | None = None
    dependency_result_revisions: list[str] = Field(default_factory=list)
    ranking_revision: str


class RootCauseRankingPolicy(BaseModel):
    policy_id: str = "canonical-v2"
    minimum_primary_score: Decimal = Decimal("0.45")
    alternative_margin: Decimal = Decimal("0.15")
    explicit_failure_bonus: Decimal = Decimal("0.08")
    exact_attempt_link_bonus: Decimal = Decimal("0.08")
    cross_protocol_explanatory_bonus: Decimal = Decimal("0.05")
    first_divergence_bonus: Decimal = Decimal("0.10")
    terminal_explanation_bonus: Decimal = Decimal("0.08")
    inspected_dependency_causal_bonus: Decimal = Decimal("0.10")
    inspected_dependency_contributing_bonus: Decimal = Decimal("0.05")
    downstream_penalty: Decimal = Decimal("0.20")
    cleanup_penalty: Decimal = Decimal("0.30")
    recovered_retry_penalty: Decimal = Decimal("0.15")
    assignment_ambiguity_penalty: Decimal = Decimal("0.12")
    incomplete_capture_penalty: Decimal = Decimal("0.15")
    contradiction_penalty: Decimal = Decimal("0.25")
    high_confidence_threshold: Decimal = Decimal("0.85")
    medium_confidence_threshold: Decimal = Decimal("0.70")


class RankRootCausesRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt: ProcedureAttempt
    candidates: list[FailureCandidate]
    terminal_effects: list[TerminalEffect] = Field(default_factory=list)
    comparison: AttemptComparison | None = None
    dependency_results: list[Any] = Field(default_factory=list)
    pass_stage: EvidenceStage
    primary_ranking_revision: str | None = None
    ranking_policy: RootCauseRankingPolicy = Field(default_factory=RootCauseRankingPolicy)


class ScenarioSelectors(BaseModel):
    ue_id: UUID | None = None
    attempt_id: UUID | None = None
    masked_subscriber_alias: str | None = None
    amf_ue_ngap_id: str | None = None
    ran_ue_ngap_id: str | None = None
    pdu_session_id: int | None = None
    frame_start: int | None = None
    frame_end: int | None = None
    time_start: Decimal | None = None
    time_end: Decimal | None = None


class ExpectedRequest(BaseModel):
    dnn: str | None = None
    snssai: str | None = None
    pdu_type: str | None = None
    ssc_mode: str | None = None
    registration_type: str | None = None
    service_type: str | None = None
    access_type: str | None = None
    emergency: bool | None = None
    roaming_topology: str | None = None


class ScenarioTextSpan(BaseModel):
    start_offset: int
    end_offset: int
    quoted_text: str
    rule_id: str


class ScenarioConflict(BaseModel):
    field_name: str
    values: list[Any]
    spans: list[ScenarioTextSpan]
    resolution: Literal["deterministic_wins", "later_phrase", "unresolved"]
    reason: str


class ScenarioMatcher(BaseModel):
    protocol: str | None = None
    message_type: str | None = None
    stage_id: str | None = None
    field: str | None = None
    operator: Literal["eq", "ne", "present", "absent", "in"] = "eq"
    value: Any | None = None


class ScenarioCondition(BaseModel):
    fact: str
    operator: Literal["eq", "ne", "present", "absent", "in"]
    value: Any | None = None


class ScenarioCheckpoint(BaseModel):
    checkpoint_id: str
    description: str
    protocol: str | None
    stage_id: str | None
    matcher: ScenarioMatcher
    expected_value: Any | None = None
    required: bool = True
    applicability_condition: ScenarioCondition | None = None


class CheckpointOrdering(BaseModel):
    first_checkpoint_id: str
    second_checkpoint_id: str
    constraint: Literal["before", "immediately_before", "at_least_n_between", "no_forbidden_between"]
    count: int | None = None


class ScenarioTimeScope(BaseModel):
    frame_start: int | None = None
    frame_end: int | None = None
    time_start: Decimal | None = None
    time_end: Decimal | None = None
    description_span: ScenarioTextSpan | None = None


class ScenarioSpec(BaseModel):
    scenario_id: UUID
    original_text_hash: str
    procedure: str | None = None
    procedure_subtype: str | None = None
    initiator: Literal["UE", "NETWORK"] | None = None
    selectors: ScenarioSelectors = Field(default_factory=ScenarioSelectors)
    expected_request: ExpectedRequest = Field(default_factory=ExpectedRequest)
    expected_outcome: Literal["success", "failure"] | None = None
    expected_failure_stage: str | None = None
    checkpoints: list[ScenarioCheckpoint] = Field(default_factory=list)
    forbidden_events: list[ScenarioCheckpoint] = Field(default_factory=list)
    ordering_constraints: list[CheckpointOrdering] = Field(default_factory=list)
    time_scope: ScenarioTimeScope | None = None
    notes: list[str] = Field(default_factory=list)


class ParseScenarioRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    scenario_text: str | None = None
    explicit_selectors: ScenarioSelectors | None = None
    provider_mode: Literal["none", "local", "openrouter"] = "none"


class ParseScenarioResult(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    status: Literal["parsed", "partial", "empty", "failed"]
    original_text: str | None
    normalized_text_hash: str | None
    spec: ScenarioSpec | None
    parser: Literal["model", "deterministic", "merged", "none"]
    confidence: Literal["high", "medium", "low", "inconclusive"]
    extracted_spans: list[ScenarioTextSpan] = Field(default_factory=list)
    conflicts: list[ScenarioConflict] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ScenarioAttemptCandidate(BaseModel):
    attempt_id: UUID
    score: Decimal
    matched_selectors: list[str] = Field(default_factory=list)
    mismatched_selectors: list[str] = Field(default_factory=list)
    ambiguous: bool = False
    selected: bool = False


class StageVisibilityResult(BaseModel):
    domain: Literal["reference_point", "sbi_service", "sbi_api"] = "reference_point"
    key: str
    state: Literal["visible", "partial", "not_observed", "unknown"] = "unknown"
    minimum_state: Literal["visible", "partial"] = "visible"
    satisfied: bool = False


class CheckpointResult(BaseModel):
    checkpoint_id: str
    status: Literal["verified", "failed", "inconclusive", "not_applicable"]
    expected: Any | None = None
    observed: Any | None = None
    attempt_id: UUID | None = None
    evidence_ids: list[UUID] = Field(default_factory=list)
    frames: list[int] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    visibility: str = "unknown"
    visibility_results: list[StageVisibilityResult] = Field(default_factory=list)
    conflict: bool = False


class ScenarioEvidenceConflict(BaseModel):
    checkpoint_id: str
    values: list[Any]
    evidence_ids: list[UUID] = Field(default_factory=list)
    resolution: Literal["prefer_request", "prefer_explicit_terminal", "unresolved"]
    reason: str


class ValidateScenarioRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    scenario: ScenarioSpec
    explicit_attempt_id: UUID | None = None
    attempts: list[ProcedureAttempt] = Field(default_factory=list)
    requests: list[UERequestResult] = Field(default_factory=list)
    root_causes: list[RootCauseResult] = Field(default_factory=list)
    pass_stage: EvidenceStage
    primary_validation_revision: str | None = None


class ValidateScenarioResult(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    scenario_id: UUID
    selected_attempt_ids: list[UUID] = Field(default_factory=list)
    selection_candidates: list[ScenarioAttemptCandidate] = Field(default_factory=list)
    checkpoints: list[CheckpointResult] = Field(default_factory=list)
    overall_status: Literal["verified", "failed", "inconclusive", "not_applicable"]
    conflicts: list[ScenarioEvidenceConflict] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    pass_stage: EvidenceStage
    parent_validation_revision: str | None = None
    dependency_result_revisions: list[str] = Field(default_factory=list)
    validation_revision: str


class TokenCounterSpec(BaseModel):
    method: Literal["pinned_tokenizer", "utf8_bytes_v1"] = "utf8_bytes_v1"
    tokenizer_id: str = "utf8_bytes_v1"
    tokenizer_version: str = "1"
    vocabulary_checksum: str | None = None
    canonical_serialization: Literal["canonical_json_v1"] = "canonical_json_v1"


class ResolvedTokenBudget(BaseModel):
    context_window_tokens: int = 32000
    configured_input_cap: int = 8000
    hard_input_cap: int = 12000
    reserved_system_tokens: int = 512
    reserved_output_tokens: int = 2000
    provider_framing_tokens: int = 128
    safety_margin_tokens: int = 256
    target_min_tokens: int = 2000
    target_max_tokens: int = 8000
    effective_input_tokens: int = 8000
    soft_target_tokens: int = 8000
    counter: TokenCounterSpec = Field(default_factory=TokenCounterSpec)


class EvidenceSchemaGuide(BaseModel):
    version: str = "1"
    rules: list[str] = Field(default_factory=list)


class PacketEvidenceRecord(BaseModel):
    evidence_id: UUID
    source_event_ids: list[UUID] = Field(default_factory=list)
    frames: list[int] = Field(default_factory=list)
    protocol: str
    record_type: str
    observed: dict[str, Any] = Field(default_factory=dict)
    source_refs: list[dict[str, Any]] = Field(default_factory=list)
    exact: bool = True
    masked: bool = True
    truncated: bool = False


class UERequestEvidence(BaseModel):
    procedure: str
    fields: dict[str, Any] = Field(default_factory=dict)


class AttemptEvidence(BaseModel):
    attempt_id: UUID
    profile_id: str
    outcome: str
    completion_reason: str
    request_signature: dict[str, Any] = Field(default_factory=dict)


class FailureEvidence(BaseModel):
    candidate_id: UUID
    summary: str
    protocol: str
    category: str
    frame: int
    evidence_ids: list[UUID] = Field(default_factory=list)


class TimelineEvidence(BaseModel):
    item_id: UUID
    frame: int
    label: str
    message: str
    evidence_ids: list[UUID] = Field(default_factory=list)


class AttemptComparisonEvidence(BaseModel):
    baseline_attempt_id: UUID
    first_divergence_stage_id: str | None = None
    summary: str


class CheckpointEvidence(BaseModel):
    checkpoint_id: str
    status: str
    expected: Any | None = None
    observed: Any | None = None
    evidence_ids: list[UUID] = Field(default_factory=list)


class DependencyToolDescriptor(BaseModel):
    tool: Literal["inspect_nrf_flow", "inspect_udr_flow"]
    available: bool = True


class DependencyInspectionEvidence(BaseModel):
    request_id: UUID
    tool: str
    status: str
    summary: str
    candidate_ids: list[UUID] = Field(default_factory=list)


class EvidencePacket(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    packet_id: UUID
    analysis_id: UUID
    pass_stage: EvidenceStage
    token_budget: ResolvedTokenBudget
    task: Literal["diagnose_failed_attempt"] = "diagnose_failed_attempt"
    schema_guide: EvidenceSchemaGuide
    ue: MaskedUEIdentity | None = None
    ue_request: UERequestEvidence
    attempt: AttemptEvidence
    primary_failure: FailureEvidence | None = None
    alternatives: list[FailureEvidence] = Field(default_factory=list)
    downstream_effects: list[FailureEvidence] = Field(default_factory=list)
    timeline: list[TimelineEvidence] = Field(default_factory=list)
    comparison: AttemptComparisonEvidence | None = None
    scenario_results: list[CheckpointEvidence] = Field(default_factory=list)
    evidence: list[PacketEvidenceRecord] = Field(default_factory=list)
    dependency_tools_available: list[DependencyToolDescriptor] = Field(default_factory=list)
    dependency_evidence: list[DependencyInspectionEvidence] = Field(default_factory=list)
    deterministic_limitations: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    parent_packet_id: UUID | None = None
    root_cause_revision: str
    scenario_validation_revision: str | None = None
    dependency_result_revisions: list[str] = Field(default_factory=list)


class EvidencePacketConfig(BaseModel):
    target_min_tokens: int = 2000
    target_max_tokens: int = 8000
    hard_input_cap: int = 12000
    safety_margin_tokens: int = 256
    max_alternatives: int = 5
    max_timeline_items: int = 20
    max_comparisons: int = 2


class EvidenceTruncation(BaseModel):
    section: str
    reason: str


class BuildInitialEvidenceRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt: ProcedureAttempt
    request_result: UERequestResult
    root_cause: RootCauseResult
    timeline: AttemptTimelineResult
    comparison: CompareAttemptsResult | None = None
    scenario_validation: ValidateScenarioResult | None = None
    provider_mode: Literal["local", "openrouter", "none"] = "none"
    token_budget: ResolvedTokenBudget = Field(default_factory=ResolvedTokenBudget)
    config: EvidencePacketConfig = Field(default_factory=EvidencePacketConfig)
    run_dir: Path
    evidence_dir: Path


class BuildExpandedEvidenceRequest(BaseModel):
    initial_packet: EvidencePacket
    dependency_results: list[Any] = Field(default_factory=list)
    expanded_root_cause: RootCauseResult
    scenario_validation: ValidateScenarioResult | None = None
    token_budget: ResolvedTokenBudget = Field(default_factory=ResolvedTokenBudget)
    run_dir: Path
    evidence_dir: Path


class BuildEvidencePacketResult(BaseModel):
    packet: EvidencePacket
    artifact: ArtifactDescriptor
    token_count: int
    token_counter: TokenCounterSpec
    truncations: list[EvidenceTruncation] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    manifest: ArtifactDescriptor
    manifest_path: Path


class ProviderConfig(BaseModel):
    mode: Literal["none", "local", "openrouter"] = "none"
    base_url: str | None = None
    model: str | None = None
    api_key_env: str | None = None
    timeout_seconds: int = 120
    temperature: Decimal = Decimal("0.1")
    context_window_tokens: int | None = None
    max_input_tokens: int = 12000
    max_output_tokens: int = 2000
    token_counter: TokenCounterSpec | None = None
    structured_output: Literal["prefer", "require", "json_prompt"] = "prefer"
    max_total_calls_per_pass: int = 3
    max_transport_retries_per_pass: int = 1
    max_content_recovery_calls_per_pass: int = 1


class DependencyEvidenceRequest(BaseModel):
    tool: Literal["inspect_nrf_flow", "inspect_udr_flow"]
    attempt_id: UUID
    reason_code: str
    rationale: str
    initial_evidence_ids: list[UUID] = Field(default_factory=list)
    frame_start: int
    frame_end: int
    nf_type: str | None = None
    service_name: str | None = None
    nf_instance_id: str | None = None
    fqdn: str | None = None
    consumer_nf: str | None = None
    resource_or_operation: str | None = None
    masked_correlation_key: str | None = None


class ReasoningStep(BaseModel):
    summary: str
    candidate_ids: list[UUID] = Field(default_factory=list)
    evidence_ids: list[UUID] = Field(default_factory=list)


class ModelDeterministicConflict(BaseModel):
    field_name: str
    model_value: Any | None = None
    deterministic_value: Any | None = None
    reason: str


class ModelDiagnosis(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    ue_request_summary: str
    outcome_summary: str
    root_cause_summary: str
    primary_candidate_id: UUID | None
    alternative_candidate_ids: list[UUID] = Field(default_factory=list)
    reasoning_steps: list[ReasoningStep] = Field(default_factory=list)
    evidence_ids: list[UUID] = Field(default_factory=list)
    confidence: Literal["high", "medium", "low", "inconclusive"]
    limitations: list[str] = Field(default_factory=list)
    deterministic_conflicts: list[ModelDeterministicConflict] = Field(default_factory=list)
    dependency_evidence_requests: list[DependencyEvidenceRequest] = Field(default_factory=list)


class ProviderMetadata(BaseModel):
    mode: str
    model: str | None = None
    request_id: str | None = None


class ModelValidationError(BaseModel):
    field_name: str
    reason: str


class GenerateDiagnosisRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt_id: UUID
    packet: EvidencePacket
    pass_stage: ModelPass
    provider_config: ProviderConfig


class GenerateDiagnosisResult(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    attempt_id: UUID
    packet_id: UUID
    pass_stage: ModelPass
    status: Literal["success", "failed", "disabled"]
    diagnosis: ModelDiagnosis | None = None
    provider: ProviderMetadata | None = None
    validation_errors: list[ModelValidationError] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class EvidenceCapability(BaseModel):
    holder: str
    purpose: str = "diagnostics"
    analysis_id: UUID
    partition_allowlist: list[str] = Field(default_factory=lambda: ["primary"])
    allowed_details: list[str] = Field(default_factory=lambda: ["metadata", "semantic_full", "summary", "full_protocol", "json_tree", "fields"])
    attempt_ids: list[UUID] = Field(default_factory=list)
    frame_start: int | None = None
    frame_end: int | None = None


class EvidenceSelectors(BaseModel):
    event_ids: list[UUID] = Field(default_factory=list)
    evidence_ids: list[UUID] = Field(default_factory=list)
    attempt_ids: list[UUID] = Field(default_factory=list)
    candidate_ids: list[UUID] = Field(default_factory=list)
    record_ids: list[UUID] = Field(default_factory=list)
    frame: int | None = None
    frame_start: int | None = None
    frame_end: int | None = None
    protocol: str | None = None


class FieldPathResult(BaseModel):
    field_path: str
    found: bool
    value: Any | None = None


class ArtifactLocation(BaseModel):
    relative_path: str
    artifact_sha256: str


class FullEvidenceRecord(BaseModel):
    record_id: UUID
    protocol: str
    partition: str
    frame_start: int
    frame_end: int
    timestamp_start: Decimal | None = None
    timestamp_end: Decimal | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    content: Any | None = None
    raw_content: Any | None = None
    source: ArtifactLocation
    checksum_verified: bool = True
    field_path_results: list[FieldPathResult] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class EvidenceRegistryEntry(BaseModel):
    evidence_id: UUID
    source_revision: str
    partition: str
    source_event_ids: list[UUID] = Field(default_factory=list)
    attempt_ids: list[UUID] = Field(default_factory=list)
    candidate_ids: list[UUID] = Field(default_factory=list)
    record_id: UUID | None = None
    source_refs: list[SourceRef] = Field(default_factory=list)
    checksum_sha256: str | None = None
    field_paths: list[str] = Field(default_factory=list)
    authorization_tags: list[str] = Field(default_factory=list)


class LookupFullEvidenceRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    caller_capability: EvidenceCapability
    selectors: EvidenceSelectors
    normalization: NormalizeEventsResult
    attempts: list[ProcedureAttempt] = Field(default_factory=list)
    candidates: list[FailureCandidate] = Field(default_factory=list)
    request_results: list[UERequestResult] = Field(default_factory=list)
    detail: Literal["metadata", "semantic_full", "raw_full"] = "semantic_full"
    field_paths: list[str] = Field(default_factory=list)
    page_size_bytes: int = 1_000_000
    max_records: int = 100
    cursor: str | None = None


class LookupFullEvidenceResult(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    query_id: UUID
    records: list[FullEvidenceRecord]
    total_matches: int
    returned_records: int
    returned_bytes: int
    truncated: bool
    next_cursor: str | None = None
    warnings: list[str] = Field(default_factory=list)


class ContextAnchor(BaseModel):
    frame: int | None = None
    timestamp: Decimal | None = None
    event_id: UUID | None = None
    evidence_id: UUID | None = None
    candidate_id: UUID | None = None


class ContextWindow(BaseModel):
    frames_before: int | None = 20
    frames_after: int | None = 20
    seconds_before: Decimal | None = None
    seconds_after: Decimal | None = None


class ValidatedProtocolFilter(BaseModel):
    protocols: set[str] = Field(default_factory=set)


class ContextPacket(BaseModel):
    frame: int
    timestamp: Decimal | None = None
    src: Endpoint | None = None
    dst: Endpoint | None = None
    protocols: list[str] = Field(default_factory=list)
    summary: str
    detail: Any | None = None
    event_ids: list[UUID] = Field(default_factory=list)
    attempt_ids: list[UUID] = Field(default_factory=list)
    correlation: Literal["selected_attempt", "other_attempt", "unassigned", "unknown"]
    partition: str | None = None
    evidence_ids: list[UUID] = Field(default_factory=list)
    source_ref: dict[str, Any] = Field(default_factory=dict)


class GetPacketContextRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    caller_capability: EvidenceCapability
    anchor: ContextAnchor
    window: ContextWindow
    normalization: NormalizeEventsResult
    attempts: list[ProcedureAttempt] = Field(default_factory=list)
    candidates: list[FailureCandidate] = Field(default_factory=list)
    protocol_filter: ValidatedProtocolFilter | None = None
    detail: Literal["summary", "full_protocol", "raw_packet"] = "summary"
    page_size_bytes: int = 1_000_000
    max_packets: int = 200
    cursor: str | None = None
    run_dir: Path
    context_dir: Path


class PacketContextResult(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    query_id: UUID
    effective_anchor: ContextAnchor
    effective_window: ContextWindow
    packets: list[ContextPacket]
    artifact: ArtifactDescriptor
    source_mode: Literal["retained", "targeted_redecode", "mixed"]
    total_matching: int
    truncated: bool
    next_cursor: str | None = None
    warnings: list[str] = Field(default_factory=list)
    manifest: ArtifactDescriptor
    manifest_path: Path


class RedecodeSelection(BaseModel):
    frame_start: int | None = None
    frame_end: int | None = None
    time_start: Decimal | None = None
    time_end: Decimal | None = None
    explicit_frames: list[int] = Field(default_factory=list)


class RedecodeAccessPlan(BaseModel):
    mode: Literal["indexed_extract", "scan_preslice", "full_scan_fallback"]
    target_selection: RedecodeSelection
    context_frame_ranges: list[dict[str, int]] = Field(default_factory=list)
    context_reason_codes: list[str] = Field(default_factory=list)
    source_index_revision: str | None = None
    context_planner_version: str = "baseline"
    source_bytes_scanned: int | None = None
    source_packets_scanned: int | None = None
    source_scan_accounting: Literal["measured", "conservative_upper_bound", "unknown"] = "unknown"
    slice_packets: int = 0
    slice_bytes: int = 0
    source_frame_map_checksum: str = ""


class TargetedRedecodeRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    caller_capability: EvidenceCapability
    selection: RedecodeSelection
    normalization: NormalizeEventsResult
    output_mode: Literal["json_tree", "fields", "raw_packet_json"] = "json_tree"
    timeout_seconds: int = 30
    run_dir: Path
    redecode_dir: Path


class TargetedRedecodeResult(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    query_id: UUID
    status: Literal["success", "empty", "failed"]
    artifact: ArtifactDescriptor | None
    manifest: ArtifactDescriptor | None
    tshark_version: str
    arguments_redacted: list[str] = Field(default_factory=list)
    access_plan: RedecodeAccessPlan
    record_count: int
    output_bytes: int
    elapsed_ms: int
    warnings: list[str] = Field(default_factory=list)


class PhaseRoll(BaseModel):
    pre_roll_frames: int = 0
    post_roll_frames: int = 0


class CapturePhaseInterval(BaseModel):
    interval_id: UUID
    phase: Literal["capture_preamble", "attempt_active", "between_attempts", "capture_postamble", "unknown"]
    start_frame: int
    end_frame: int
    start_timestamp: Decimal | None = None
    end_timestamp: Decimal | None = None
    attempt_ids: list[UUID] = Field(default_factory=list)
    core_start_frames: dict[str, int] = Field(default_factory=dict)
    core_end_frames: dict[str, int] = Field(default_factory=dict)
    roll_applied: dict[str, PhaseRoll] = Field(default_factory=dict)
    confidence: Literal["high", "medium", "low"] = "medium"
    reason_codes: list[str] = Field(default_factory=list)


class CapturePhaseLabel(BaseModel):
    event_id: UUID
    interval_id: UUID
    phase: str
    active_attempt_ids: list[UUID] = Field(default_factory=list)
    inside_core_attempt_ids: list[UUID] = Field(default_factory=list)
    inside_roll_only_attempt_ids: list[UUID] = Field(default_factory=list)


class CapturePhaseConfig(BaseModel):
    default_pre_roll_frames: int = 20
    default_post_roll_frames: int = 20
    max_roll_frames: int = 500


class ClassifyCapturePhasesRequest(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempts_revision: str
    attempts: list[ProcedureAttempt]
    primary_reader: JsonlPrimaryEventReader
    capture: Any
    config: CapturePhaseConfig = Field(default_factory=CapturePhaseConfig)
    run_dir: Path
    phases_dir: Path


class ClassifyCapturePhasesResult(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    status: Literal["success", "partial", "unknown"]
    intervals: list[CapturePhaseInterval]
    primary_event_labels_artifact: ArtifactDescriptor
    manifest: ArtifactDescriptor
    visibility: Literal["anchored", "partial", "unknown"]
    warnings: list[str] = Field(default_factory=list)
    manifest_path: Path


class NRFSelectors(BaseModel):
    nf_instance_id: str | None = None
    nf_type: str | None = None
    service_name: str | None = None
    fqdn: str | None = None
    endpoint: str | None = None
    consumer_nf: str | None = None


class NFEntityRef(BaseModel):
    entity_id: UUID
    nf_instance_id: str | None = None
    nf_type: str | None = None
    fqdn: str | None = None
    endpoints: list[str] = Field(default_factory=list)
    service_names: list[str] = Field(default_factory=list)
    identity_confidence: Literal["high", "medium", "low"] = "low"
    identity_evidence_ids: list[UUID] = Field(default_factory=list)


class NFServiceState(BaseModel):
    service_name: str
    api_versions: list[str] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)
    status: Literal["unknown", "available", "degraded", "suspended", "unavailable"]
    valid_from_frame: int
    valid_to_frame: int | None = None
    evidence_ids: list[UUID] = Field(default_factory=list)


class NFLifecycleEvent(BaseModel):
    lifecycle_event_id: UUID
    entity_id: UUID
    service_name: str | None = None
    frame: int
    timestamp: Decimal | None = None
    operation: str
    http_status: int | None = None
    state_before: str
    state_after: str
    service_state_before: str | None = None
    service_state_after: str | None = None
    classification: Literal["normal", "failure", "recovery", "benign_startup_cleanup", "discovery_observation", "ambiguous"]
    evidence_ids: list[UUID] = Field(default_factory=list)
    rationale_codes: list[str] = Field(default_factory=list)


class NFEntityReadiness(BaseModel):
    entity_id: UUID
    status: str
    service_states: list[NFServiceState] = Field(default_factory=list)


class NFReadinessSnapshot(BaseModel):
    attempt_id: UUID
    frame: int
    entities: list[NFEntityReadiness] = Field(default_factory=list)
    required_service: str | None = None
    available_candidates: list[UUID] = Field(default_factory=list)
    unresolved_failure_ids: list[UUID] = Field(default_factory=list)
    status: Literal["ready", "not_ready", "partially_ready", "unknown"] = "unknown"
    evidence_ids: list[UUID] = Field(default_factory=list)


class NFLifecycleFailure(BaseModel):
    failure_id: UUID
    event_id: UUID
    frame: int
    summary: str


class NFAmbiguousEvent(BaseModel):
    event_id: UUID
    frame: int
    summary: str


class BuildNFLifecycleRequest(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    approved_request_id: UUID
    attempt_id: UUID
    frame_start: int
    frame_end: int
    attempt_start_frame: int
    selectors: NRFSelectors
    dependency_events: list[CanonicalEvent] = Field(default_factory=list)


class BuildNFLifecycleResult(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    approved_request_id: UUID
    attempt_id: UUID
    selected_entities: list[NFEntityRef] = Field(default_factory=list)
    lifecycles: list[NFLifecycleEvent] = Field(default_factory=list)
    readiness_snapshot: NFReadinessSnapshot
    unresolved_failures: list[NFLifecycleFailure] = Field(default_factory=list)
    recovered_failures: list[NFLifecycleFailure] = Field(default_factory=list)
    ambiguous_events: list[NFAmbiguousEvent] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class DependencyBaselineComparison(BaseModel):
    baseline_ok: bool = False
    summary: str = ""


class DependencyEventSummary(BaseModel):
    event_id: UUID
    frame: int
    protocol: str
    summary: str
    evidence_ids: list[UUID] = Field(default_factory=list)


class CausalLink(BaseModel):
    from_evidence_id: UUID
    to_evidence_id: UUID
    relation: Literal["SAME_INSTANCE", "SAME_SERVICE", "SELECTED_ENDPOINT", "SAME_CONTEXT", "PROPAGATED_ERROR", "PRECEDES_STAGE_FAILURE", "BASELINE_DIVERGENCE", "RECOVERED_BEFORE", "ALTERNATE_SUCCEEDED"]
    strength: Literal["strong", "supporting", "contradictory"]
    rationale: str


class ImpactDecisionStep(BaseModel):
    order: int
    gate: str
    result: Literal["pass", "fail", "unknown", "not_applicable"]
    reason_codes: list[str] = Field(default_factory=list)
    evidence_ids: list[UUID] = Field(default_factory=list)
    terminal_impact: Literal["causal", "contributing", "unrelated", "inconclusive"] | None = None


class AssessBackgroundImpactRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    approved_request_id: UUID
    attempt: ProcedureAttempt
    initial_packet_id: UUID
    initial_symptom_evidence_ids: list[UUID] = Field(default_factory=list)
    dependency_type: Literal["NRF", "UDR"]
    dependency_events: list[DependencyEventSummary] = Field(default_factory=list)
    lifecycle: BuildNFLifecycleResult | None = None
    dependency_comparison: DependencyBaselineComparison | None = None


class AssessBackgroundImpactResult(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    impact_id: UUID
    approved_request_id: UUID
    attempt_id: UUID
    call_impact: Literal["causal", "contributing", "unrelated", "inconclusive"]
    primary_dependency_event_ids: list[UUID] = Field(default_factory=list)
    supporting_event_ids: list[UUID] = Field(default_factory=list)
    recovery_frame: int | None = None
    causal_path: list[CausalLink] = Field(default_factory=list)
    promotion_conditions: list[str] = Field(default_factory=list)
    demotion_conditions: list[str] = Field(default_factory=list)
    contradictions: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    counterfactual_supported: bool | None = None
    decision_trace: list[ImpactDecisionStep] = Field(default_factory=list)
    confidence: Literal["high", "medium", "low", "inconclusive"]


class ExpansionBudget(BaseModel):
    request_id: UUID
    maximum_expansions: Literal[1] = 1
    expansions_consumed: int = 0
    original_window: dict[str, int] = Field(default_factory=dict)
    maximum_window: dict[str, int] = Field(default_factory=dict)


class ExpansionDecision(BaseModel):
    requested_start: int
    effective_start: int
    reason: str
    approved: bool


class FrameWindow(BaseModel):
    frame_start: int
    frame_end: int


class NRFTransactionEvidence(BaseModel):
    transaction_id: UUID
    operation: str
    request_frame: int | None = None
    response_frame: int | None = None
    method: str | None = None
    uri_template: str | None = None
    status: int | None = None
    nf_instance_id: str | None = None
    nf_type: str | None = None
    service_names: list[str] = Field(default_factory=list)
    consumer_nf: str | None = None
    completion_state: str = "unknown"
    phase: str = "unknown"
    retry_group: UUID | None = None
    problem_cause: str | None = None
    evidence_ids: list[UUID] = Field(default_factory=list)


class DiscoverySelectionStep(BaseModel):
    step_id: UUID
    frame: int
    step_type: Literal["discovery_request", "discovery_response", "candidate_returned", "candidate_selected", "request_sent", "selection_failed"]
    consumer_nf: str | None = None
    requested_nf_type: str | None = None
    requested_service: str | None = None
    query_criteria: dict[str, Any] = Field(default_factory=dict)
    candidate_entity_ids: list[UUID] = Field(default_factory=list)
    selected_entity_id: UUID | None = None
    selected_endpoint: str | None = None
    outcome: str = "unknown"
    evidence_ids: list[UUID] = Field(default_factory=list)


class InspectNRFFlowRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    request_id: UUID
    analysis_id: UUID
    initial_packet_id: UUID
    attempt_id: UUID
    reason_code: str
    rationale: str
    initial_evidence_ids: list[UUID] = Field(default_factory=list)
    frame_start: int
    frame_end: int
    nf_type: str | None = None
    service_name: str | None = None
    nf_instance_id: str | None = None
    fqdn: str | None = None
    consumer_nf: str | None = None
    expansion_budget: ExpansionBudget = Field(default_factory=lambda: ExpansionBudget(request_id=UUID("00000000-0000-0000-0000-000000000000")))
    normalization: NormalizeEventsResult
    run_dir: Path
    diagnostics_dir: Path


class NRFInspectionResult(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    request_id: UUID
    analysis_id: UUID
    initial_packet_id: UUID
    attempt_id: UUID
    status: Literal["completed", "empty", "partial", "failed"]
    effective_window: FrameWindow
    expansion_decisions: list[ExpansionDecision] = Field(default_factory=list)
    selected_entities: list[NFEntityRef] = Field(default_factory=list)
    transactions: list[NRFTransactionEvidence] = Field(default_factory=list)
    lifecycle: BuildNFLifecycleResult | None = None
    discovery_chain: list[DiscoverySelectionStep] = Field(default_factory=list)
    impact: AssessBackgroundImpactResult | None = None
    failure_candidates: list[FailureCandidate] = Field(default_factory=list)
    full_evidence_refs: list[UUID] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    revision: str


class UDRResponseStructureSummary(BaseModel):
    top_level_keys: list[str] = Field(default_factory=list)


class UDRTransactionEvidence(BaseModel):
    transaction_id: UUID
    consumer_nf: str | None = None
    operation: str
    data_category: str
    request_frame: int | None = None
    response_frame: int | None = None
    method: str | None = None
    uri_template: str | None = None
    status: int | None = None
    completion_state: str = "unknown"
    problem_cause: str | None = None
    masked_correlation_key: str | None = None
    retry_group_id: UUID | None = None
    phase: str = "unknown"
    response_structure: UDRResponseStructureSummary | None = None
    evidence_ids: list[UUID] = Field(default_factory=list)


class UDRConsumerPropagationStep(BaseModel):
    step_id: UUID
    frame: int
    step_type: Literal["consumer_request_to_udr", "udr_failure", "consumer_retry", "consumer_error_to_upstream", "consumer_recovery"]
    consumer_nf: str | None = None
    operation: str | None = None
    status_or_cause: str | None = None
    evidence_ids: list[UUID] = Field(default_factory=list)
    correlation_confidence: Literal["high", "medium", "low"] = "low"


class UDRRetryGroup(BaseModel):
    group_id: UUID
    transaction_ids: list[UUID] = Field(default_factory=list)


class UDRRetrySummary(BaseModel):
    groups: list[UDRRetryGroup] = Field(default_factory=list)
    recovered_before_attempt: bool = False
    recovered_before_failed_stage: bool = False
    terminal_exhaustion: bool = False


class UDRBaselineComparison(BaseModel):
    summary: str
    matched: bool


class InspectUDRFlowRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    request_id: UUID
    analysis_id: UUID
    initial_packet_id: UUID
    attempt_id: UUID
    reason_code: str
    rationale: str
    initial_evidence_ids: list[UUID] = Field(default_factory=list)
    frame_start: int
    frame_end: int
    consumer_nf: str | None = None
    resource_or_operation: str | None = None
    masked_correlation_key: str | None = None
    normalization: NormalizeEventsResult
    run_dir: Path
    diagnostics_dir: Path


class UDRInspectionResult(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    request_id: UUID
    analysis_id: UUID
    initial_packet_id: UUID
    attempt_id: UUID
    status: Literal["completed", "empty", "partial", "failed"]
    effective_window: FrameWindow
    transactions: list[UDRTransactionEvidence] = Field(default_factory=list)
    retry_summary: UDRRetrySummary = Field(default_factory=UDRRetrySummary)
    consumer_chain: list[UDRConsumerPropagationStep] = Field(default_factory=list)
    baseline: UDRBaselineComparison | None = None
    impact: AssessBackgroundImpactResult | None = None
    failure_candidates: list[FailureCandidate] = Field(default_factory=list)
    full_evidence_refs: list[UUID] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    revision: str


class ReportWarning(BaseModel):
    code: str
    severity: str
    stage: str
    message: str


class ReportEvidenceRef(BaseModel):
    evidence_id: UUID
    event_ids: list[UUID] = Field(default_factory=list)
    frames: list[int] = Field(default_factory=list)
    protocol: str
    summary: str
    source_available: bool = True


class UEResult(BaseModel):
    attempt_id: UUID
    procedure: str
    outcome: str
    completion_reason: str
    profile_alternatives: list[dict[str, Any]] = Field(default_factory=list)
    ue_request: dict[str, Any] = Field(default_factory=dict)
    root_cause: dict[str, Any] = Field(default_factory=dict)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    comparison: dict[str, Any] | None = None
    scenario: list[dict[str, Any]] = Field(default_factory=list)
    dependency_inspections: list[dict[str, Any]] = Field(default_factory=list)
    model_diagnosis: dict[str, Any] | None = None
    model_narration: str | None = None
    evidence: list[ReportEvidenceRef] = Field(default_factory=list)


class CaptureReport(BaseModel):
    source_sha256: str
    packet_count: int | None = None


class PipelineReport(BaseModel):
    implemented_tools: list[str] = Field(default_factory=list)
    invoked_tools: list[str] = Field(default_factory=list)
    stage_statuses: dict[str, str] = Field(default_factory=dict)
    revisions: dict[str, str] = Field(default_factory=dict)


class ScenarioReport(BaseModel):
    overall_status: str
    selected_attempt_ids: list[UUID] = Field(default_factory=list)


class DependencyInspectionReport(BaseModel):
    tool: str
    request_id: UUID
    status: str
    summary: str


class ProviderReport(BaseModel):
    mode: str
    model: str | None = None
    status: str = "unknown"


class EvidenceIntegrityReport(BaseModel):
    status: str
    warnings: list[str] = Field(default_factory=list)


class AnalysisReport(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    status: Literal["success", "partial", "failed"]
    generated_at: datetime
    capture: CaptureReport
    pipeline: PipelineReport
    ue_results: list[UEResult] = Field(default_factory=list)
    scenario: ScenarioReport | None = None
    dependency_inspections: list[DependencyInspectionReport] = Field(default_factory=list)
    provider: ProviderReport | None = None
    warnings: list[ReportWarning] = Field(default_factory=list)
    timings: dict[str, int] = Field(default_factory=dict)
    evidence_integrity: EvidenceIntegrityReport


class AnalysisState(BaseModel):
    analysis_id: UUID
    attempts: list[ProcedureAttempt] = Field(default_factory=list)
    request_results: list[UERequestResult] = Field(default_factory=list)
    root_cause_results: list[RootCauseResult] = Field(default_factory=list)
    timelines: list[AttemptTimelineResult] = Field(default_factory=list)
    comparisons: list[CompareAttemptsResult] = Field(default_factory=list)
    scenario_validation: ValidateScenarioResult | None = None
    diagnoses: list[GenerateDiagnosisResult] = Field(default_factory=list)
    dependency_results: list[Any] = Field(default_factory=list)
    capture: dict[str, Any] = Field(default_factory=dict)
    stage_statuses: dict[str, str] = Field(default_factory=dict)
    stage_revisions: dict[str, str] = Field(default_factory=dict)
    timings_ms: dict[str, int] = Field(default_factory=dict)
    evidence_integrity_warnings: list[str] = Field(default_factory=list)
    publication_warnings: list[str] = Field(default_factory=list)
    generated_at: datetime | None = None
    run_dir: Path
    report_dir: Path


class RenderReportRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    analysis_state: AnalysisState


class RenderReportResult(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    status: Literal["success", "partial", "failed"]
    report_json: ArtifactDescriptor
    report_markdown: ArtifactDescriptor
    report_manifest: ArtifactDescriptor
    warnings: list[str] = Field(default_factory=list)
    manifest_path: Path


def compare_attempts(request: CompareAttemptsRequest) -> CompareAttemptsResult:
    eligible = [
        attempt
        for attempt in request.candidate_baselines
        if attempt.outcome == "succeeded"
        and attempt.profile_id == request.failed_attempt.profile_id
        and attempt.start_frame < request.failed_attempt.start_frame
    ]
    baseline_requests = {item.attempt_id: item for item in request.baseline_requests}
    comparisons: list[AttemptComparison] = []
    warnings: list[str] = []
    if not eligible:
        return CompareAttemptsResult(
            failed_attempt_id=request.failed_attempt.attempt_id,
            selected_baseline_id=None,
            comparisons=[],
            no_baseline_reason="no_eligible_successful_baseline",
            warnings=warnings,
        )
    scored: list[tuple[tuple[int, int, str], ProcedureAttempt, Decimal, list[str]]] = []
    for candidate in eligible:
        reasons: list[str] = []
        score = Decimal("0")
        band = 0
        baseline_request = baseline_requests.get(candidate.attempt_id)
        if baseline_request is not None:
            similarity = _request_similarity(request.failed_request, baseline_request)
            score += similarity
            if similarity == Decimal("1.0"):
                band = 3
                reasons.append("exact_request_signature")
            elif similarity >= Decimal("0.75"):
                band = 2
                reasons.append("high_request_similarity")
            else:
                band = 1
                reasons.append("partial_request_similarity")
        if candidate.access_context_id == request.failed_attempt.access_context_id:
            score += Decimal("0.20")
            reasons.append("same_access_context")
        if candidate.access_family == request.failed_attempt.access_family:
            score += Decimal("0.10")
            reasons.append("same_access_type")
        score += Decimal(max(0, 1000 - abs(request.failed_attempt.start_frame - candidate.start_frame))) / Decimal("10000")
        scored.append(((-band, abs(request.failed_attempt.start_frame - candidate.start_frame), str(candidate.attempt_id)), candidate, score, reasons))
    scored.sort(key=lambda item: item[0])
    selected = scored[: request.max_baselines]
    for _, baseline, baseline_score, reasons in selected:
        req_diffs = _request_differences(request.failed_request, baseline_requests.get(baseline.attempt_id))
        stage_alignment, first_divergence = _align_stages(request.failed_attempt, baseline)
        divergences = [
            _alignment_divergence(request.failed_attempt, baseline, item)
            for item in stage_alignment
            if item.relation != "matched"
        ]
        comparison = AttemptComparison(
            comparison_id=deterministic_uuid(request.analysis_id, "T11", request.failed_attempt.attempt_id, baseline.attempt_id),
            failed_attempt_id=request.failed_attempt.attempt_id,
            baseline_attempt_id=baseline.attempt_id,
            baseline_score=baseline_score,
            baseline_reasons=reasons,
            request_differences=req_diffs,
            stage_alignment=stage_alignment,
            first_divergence=first_divergence,
            later_divergences=divergences[1:] if divergences else [],
            visibility_limitations=[],
            evidence_ids=[deterministic_uuid(request.analysis_id, "T11", "comparison_evidence", request.failed_attempt.attempt_id, baseline.attempt_id)],
        )
        comparisons.append(comparison)
    return CompareAttemptsResult(
        failed_attempt_id=request.failed_attempt.attempt_id,
        selected_baseline_id=comparisons[0].baseline_attempt_id if comparisons else None,
        comparisons=comparisons,
        warnings=warnings,
    )


def rank_root_causes(request: RankRootCausesRequest) -> RootCauseResult:
    policy = request.ranking_policy
    ranked: list[tuple[Decimal, FailureCandidate, RankedCandidate, tuple[Any, ...]]] = []
    for candidate in request.candidates:
        detector_base = sum((term.value for term in candidate.score_terms), Decimal("0")) if candidate.score_terms else candidate.detector_score
        detector_base = max(Decimal("0"), min(Decimal("1"), detector_base))
        terms = [ScoreTerm(kind="base", rationale_code="detector_base", value=detector_base)]
        score = detector_base
        eligible = True
        exclusion_reasons: list[str] = []
        if candidate.explicit:
            score += policy.explicit_failure_bonus
            terms.append(ScoreTerm(kind="bonus", rationale_code="explicit_failure_bonus", value=policy.explicit_failure_bonus))
        exact_attempt_link = bool(candidate.source_event_ids) and candidate.relevance == "attempt_related"
        if exact_attempt_link:
            score += policy.exact_attempt_link_bonus
            terms.append(ScoreTerm(kind="bonus", rationale_code="exact_attempt_link_bonus", value=policy.exact_attempt_link_bonus))
        terminal_explanation = _candidate_explains_terminal(candidate, request.terminal_effects)
        if terminal_explanation:
            score += policy.terminal_explanation_bonus
            terms.append(ScoreTerm(kind="bonus", rationale_code="terminal_explanation_bonus", value=policy.terminal_explanation_bonus))
            if candidate.protocol not in {"NAS", "NGAP"}:
                score += policy.cross_protocol_explanatory_bonus
                terms.append(ScoreTerm(kind="bonus", rationale_code="cross_protocol_explanatory_bonus", value=policy.cross_protocol_explanatory_bonus))
        if candidate.call_impact == "causal":
            score += policy.inspected_dependency_causal_bonus
            terms.append(ScoreTerm(kind="bonus", rationale_code="inspected_dependency_impact_bonus", value=policy.inspected_dependency_causal_bonus))
        elif candidate.call_impact == "contributing":
            score += policy.inspected_dependency_contributing_bonus
            terms.append(ScoreTerm(kind="bonus", rationale_code="inspected_dependency_impact_bonus", value=policy.inspected_dependency_contributing_bonus))
        if candidate.cleanup:
            score -= policy.cleanup_penalty
            terms.append(ScoreTerm(kind="penalty", rationale_code="cleanup_penalty", value=-policy.cleanup_penalty))
        if candidate.downstream:
            score -= policy.downstream_penalty
            terms.append(ScoreTerm(kind="penalty", rationale_code="downstream_penalty", value=-policy.downstream_penalty))
        if request.comparison and request.comparison.first_divergence:
            divergence = request.comparison.first_divergence
            if divergence.stage_id == candidate.component or divergence.stage_id == candidate.category:
                score += policy.first_divergence_bonus
                terms.append(ScoreTerm(kind="bonus", rationale_code="first_divergence_bonus", value=policy.first_divergence_bonus))
        if candidate.observed.get("recovered_retry") is True:
            score -= policy.recovered_retry_penalty
            terms.append(ScoreTerm(kind="penalty", rationale_code="recovered_retry_penalty", value=-policy.recovered_retry_penalty))
        if request.attempt.assignment_confidence == "low":
            score -= policy.assignment_ambiguity_penalty
            terms.append(ScoreTerm(kind="penalty", rationale_code="assignment_ambiguity_penalty", value=-policy.assignment_ambiguity_penalty))
        if request.attempt.incomplete_history or request.attempt.outcome == "incomplete_capture":
            score -= policy.incomplete_capture_penalty
            terms.append(ScoreTerm(kind="penalty", rationale_code="incomplete_capture_penalty", value=-policy.incomplete_capture_penalty))
        if candidate.observed.get("contradicted") is True:
            score -= policy.contradiction_penalty
            terms.append(ScoreTerm(kind="penalty", rationale_code="contradiction_penalty", value=-policy.contradiction_penalty))
        if candidate.call_impact == "unrelated":
            eligible = False
            exclusion_reasons.append("dependency_unrelated")
        score = max(Decimal("0"), min(Decimal("1"), score)).quantize(Decimal("0.0001"))
        if eligible and score < policy.minimum_primary_score:
            eligible = False
            exclusion_reasons.append("below_minimum_primary_score")
        ranked_candidate = RankedCandidate(
            candidate_id=candidate.candidate_id,
            eligible=eligible,
            final_score=score if eligible else None,
            score_terms=terms,
            rank=None,
            classification="excluded" if not eligible else "alternative",
            exclusion_reasons=exclusion_reasons,
        )
        tie_key = (
            -int(candidate.explicit),
            -int(exact_attempt_link),
            -int(terminal_explanation),
            candidate.frame,
            _ranking_protocol_priority(candidate.protocol),
            str(candidate.candidate_id),
        )
        ranked.append((score, candidate, ranked_candidate, tie_key))
    ranked.sort(key=lambda item: (-item[0], *item[3]))
    primary_candidate_id: UUID | None = None
    alternative_ids: list[UUID] = []
    downstream_ids: list[UUID] = []
    excluded_ids: list[UUID] = []
    ranked_candidates: list[RankedCandidate] = []
    eligible_rank = 0
    primary_score: Decimal | None = None
    for score, candidate, ranked_candidate, _ in ranked:
        if not ranked_candidate.eligible:
            excluded_ids.append(candidate.candidate_id)
            ranked_candidates.append(ranked_candidate)
            continue
        if primary_candidate_id is None:
            eligible_rank += 1
            ranked_candidate.rank = eligible_rank
            primary_candidate_id = candidate.candidate_id
            primary_score = score
            ranked_candidate.classification = "primary"
        elif candidate.downstream or candidate.cleanup:
            eligible_rank += 1
            ranked_candidate.rank = eligible_rank
            ranked_candidate.classification = "downstream"
            downstream_ids.append(candidate.candidate_id)
        else:
            if primary_score is not None and primary_score - score <= policy.alternative_margin:
                eligible_rank += 1
                ranked_candidate.rank = eligible_rank
                ranked_candidate.classification = "alternative"
                alternative_ids.append(candidate.candidate_id)
            else:
                ranked_candidate.eligible = False
                ranked_candidate.rank = None
                ranked_candidate.final_score = None
                ranked_candidate.classification = "excluded"
                ranked_candidate.exclusion_reasons.append("outside_alternative_margin")
                excluded_ids.append(candidate.candidate_id)
        ranked_candidates.append(ranked_candidate)
    confidence: Literal["high", "medium", "low", "inconclusive"] = "inconclusive"
    if primary_candidate_id is not None:
        primary_ranked = next(
            item for item in ranked_candidates if item.candidate_id == primary_candidate_id
        )
        top_score = primary_ranked.final_score or Decimal("0")
        if top_score >= policy.high_confidence_threshold:
            confidence = "high"
        elif top_score >= policy.medium_confidence_threshold:
            confidence = "medium"
        else:
            confidence = "low"
    ranking_revision = "sha256:" + sha256_bytes(
        compact_json_bytes(
            {
                "tool": "T12",
                "version": POST_VERSION,
                "analysis_id": str(request.analysis_id),
                "attempt_id": str(request.attempt.attempt_id),
                "pass_stage": request.pass_stage,
                "primary_candidate_id": str(primary_candidate_id) if primary_candidate_id else None,
                "candidate_ids": [str(candidate.candidate_id) for _, candidate, _, _ in ranked],
                "dependency_revisions": [getattr(result, "revision", "") for result in request.dependency_results],
                "ranking_policy": policy.model_dump(mode="json"),
            }
        )
    )
    return RootCauseResult(
        attempt_id=request.attempt.attempt_id,
        pass_stage=request.pass_stage,
        primary_candidate_id=primary_candidate_id,
        alternative_candidate_ids=alternative_ids,
        downstream_candidate_ids=downstream_ids,
        excluded_candidate_ids=excluded_ids,
        ranked_candidates=ranked_candidates,
        candidate_records=[candidate for _, candidate, _, _ in ranked],
        confidence=confidence,
        rationale_codes=[] if primary_candidate_id is None else ["ranked_candidates_available"],
        limitations=[],
        parent_ranking_revision=request.primary_ranking_revision,
        dependency_result_revisions=[getattr(result, "revision", "") for result in request.dependency_results if getattr(result, "revision", None)],
        ranking_revision=ranking_revision,
    )


def _candidate_explains_terminal(candidate: FailureCandidate, effects: list[TerminalEffect]) -> bool:
    candidate_evidence = set(candidate.evidence_ids)
    candidate_events = set(candidate.source_event_ids)
    for effect in effects:
        if effect.event_id in candidate_events or candidate_evidence.intersection(effect.evidence_ids):
            return True
        if candidate.component and candidate.component.lower() in effect.summary.lower():
            return True
    return False


def _ranking_protocol_priority(protocol: str) -> int:
    return {"NAS": 0, "NGAP": 1, "HTTP2": 2, "PFCP": 3}.get(protocol.upper(), 99)


def parse_scenario(request: ParseScenarioRequest) -> ParseScenarioResult:
    if request.scenario_text is None or not request.scenario_text.strip():
        return ParseScenarioResult(
            analysis_id=request.analysis_id,
            status="empty",
            original_text=request.scenario_text,
            normalized_text_hash=None,
            spec=None,
            parser="none",
            confidence="inconclusive",
        )
    text = " ".join(request.scenario_text.strip().split())
    lowered = text.lower()
    spans: list[ScenarioTextSpan] = []
    warnings: list[str] = []
    expected_request = ExpectedRequest()
    procedure = None
    initiator = None
    expected_outcome = None
    expected_failure_stage = None
    checkpoints: list[ScenarioCheckpoint] = []
    forbidden_events: list[ScenarioCheckpoint] = []
    ordering_constraints: list[CheckpointOrdering] = []
    selectors = (request.explicit_selectors or ScenarioSelectors()).model_copy(deep=True)
    time_scope: ScenarioTimeScope | None = None
    if "registration" in lowered:
        procedure = "INITIAL_REGISTRATION"
        offset = lowered.index("registration")
        spans.append(ScenarioTextSpan(start_offset=offset, end_offset=offset + len("registration"), quoted_text=text[offset:offset + len("registration")], rule_id="procedure.registration"))
    if "pdu session" in lowered or "pdu-session" in lowered:
        procedure = procedure or "PDU_SESSION_ESTABLISHMENT"
        for match in re.finditer(r"pdu[- ]session(?: id)?\s*(?:=|is|#)?\s*(\d+)", lowered):
            selectors.pdu_session_id = int(match.group(1))
            spans.append(ScenarioTextSpan(start_offset=match.start(), end_offset=match.end(), quoted_text=text[match.start():match.end()], rule_id="selector.pdu_session_id"))
            break
    for match in re.finditer(r"\bframes?\s+(\d+)\s*(?:-|to|through)\s*(\d+)\b", lowered):
        start_frame = int(match.group(1))
        end_frame = int(match.group(2))
        time_scope = ScenarioTimeScope(frame_start=start_frame, frame_end=end_frame)
        spans.append(ScenarioTextSpan(start_offset=match.start(), end_offset=match.end(), quoted_text=text[match.start():match.end()], rule_id="time_scope.frame_range"))
        break
    for match in re.finditer(r"\bframe\s*(?:=|#)?\s*(\d+)\b", lowered):
        if time_scope is None:
            frame = int(match.group(1))
            time_scope = ScenarioTimeScope(frame_start=frame, frame_end=frame)
            spans.append(ScenarioTextSpan(start_offset=match.start(), end_offset=match.end(), quoted_text=text[match.start():match.end()], rule_id="time_scope.frame"))
        break
    for match in re.finditer(r"\bdnn\s*(?:=|is|:)?\s*([a-z0-9_.-]+)", lowered):
        expected_request.dnn = match.group(1)
        spans.append(ScenarioTextSpan(start_offset=match.start(), end_offset=match.end(), quoted_text=text[match.start():match.end()], rule_id="request.dnn"))
        break
    for match in re.finditer(r"\b(?:snssai|s-nssai)\s*(?:=|is|:)?\s*([a-z0-9_.:-]+)", lowered):
        expected_request.snssai = match.group(1)
        spans.append(ScenarioTextSpan(start_offset=match.start(), end_offset=match.end(), quoted_text=text[match.start():match.end()], rule_id="request.snssai"))
        break
    if "succeed" in lowered or "success" in lowered or "work" in lowered:
        expected_outcome = "success"
    if "fail" in lowered or "failed" in lowered:
        expected_outcome = "failure"
    if "pdu" in lowered and "ipv4" in lowered:
        expected_request.pdu_type = "ipv4"
    if "3gpp" in lowered:
        expected_request.access_type = "non_3gpp" if "non-3gpp" in lowered or "non 3gpp" in lowered else "3gpp"
    if "ue initiated" in lowered or "ue-initiated" in lowered:
        initiator = "UE"
    if "network initiated" in lowered or "network-initiated" in lowered:
        initiator = "NETWORK"
    if "emergency" in lowered:
        expected_request.emergency = True
    if "at smf" in lowered or "smf" in lowered:
        expected_failure_stage = "smf"
    if "registration request" in lowered:
        checkpoints.append(
            ScenarioCheckpoint(
                checkpoint_id="registration_request",
                description="registration request observed",
                protocol="NAS",
                stage_id="registration.request",
                matcher=ScenarioMatcher(stage_id="registration.request"),
            )
        )
    if "smf" in lowered:
        checkpoints.append(
            ScenarioCheckpoint(
                checkpoint_id="smf_stage",
                description="SMF stage observed",
                protocol="HTTP2",
                stage_id="smf",
                matcher=ScenarioMatcher(stage_id="smf"),
                required=False if expected_failure_stage == "smf" else True,
            )
        )
    if "no registration reject" in lowered or "without registration reject" in lowered:
        forbidden_events.append(
            ScenarioCheckpoint(
                checkpoint_id="no_registration_reject",
                description="registration reject absent",
                protocol="NAS",
                stage_id=None,
                matcher=ScenarioMatcher(protocol="NAS", message_type="REGISTRATION_REJECT"),
            )
        )
    if "registration request before smf" in lowered and any(item.checkpoint_id == "registration_request" for item in checkpoints) and any(item.checkpoint_id == "smf_stage" for item in checkpoints):
        ordering_constraints.append(
            CheckpointOrdering(
                first_checkpoint_id="registration_request",
                second_checkpoint_id="smf_stage",
                constraint="before",
            )
        )
    if request.provider_mode != "none":
        warnings.append("provider_scenario_parser_not_configured; deterministic parser used")
    spec = ScenarioSpec(
        scenario_id=deterministic_uuid(request.analysis_id, "T13", text),
        original_text_hash=sha256_bytes(text.encode("utf-8")),
        procedure=procedure,
        initiator=initiator,
        selectors=selectors,
        expected_request=expected_request,
        expected_outcome=expected_outcome,
        expected_failure_stage=expected_failure_stage,
        checkpoints=checkpoints,
        forbidden_events=forbidden_events,
        ordering_constraints=ordering_constraints,
        time_scope=time_scope,
        notes=[],
    )
    extracted = sum(
        1
        for value in [
            procedure,
            initiator,
            expected_outcome,
            expected_failure_stage,
            *expected_request.model_dump(exclude_none=True).values(),
            selectors.pdu_session_id,
            time_scope,
            *checkpoints,
            *forbidden_events,
            *ordering_constraints,
        ]
        if value is not None
    )
    return ParseScenarioResult(
        analysis_id=request.analysis_id,
        status="parsed" if extracted else "partial",
        original_text=request.scenario_text,
        normalized_text_hash=spec.original_text_hash,
        spec=spec,
        parser="deterministic",
        confidence="high" if extracted >= 3 else "medium" if extracted else "low",
        extracted_spans=spans,
        conflicts=[],
        warnings=warnings,
    )


def validate_scenario(request: ValidateScenarioRequest) -> ValidateScenarioResult:
    _validate_scenario_contract(request.scenario)
    request_map = {item.attempt_id: item for item in request.requests}
    root_map = {item.attempt_id: item for item in request.root_causes}
    candidates, selected_attempts, selection_warnings, selection_conflicts = _select_scenario_attempts(
        request,
        request_map,
    )
    checkpoint_results: list[CheckpointResult] = []
    conflicts: list[ScenarioEvidenceConflict] = list(selection_conflicts)
    warnings: list[str] = list(selection_warnings)
    required_by_checkpoint: dict[str, bool] = {}

    for attempt in selected_attempts:
        request_result = request_map.get(attempt.attempt_id)
        root = root_map.get(attempt.attempt_id)
        if request.scenario.expected_outcome is not None:
            result = _validate_expected_outcome(request.analysis_id, attempt, request.scenario.expected_outcome)
            checkpoint_results.append(result)
            required_by_checkpoint[result.checkpoint_id] = True

        request_results, request_conflicts = _validate_expected_request(
            request.analysis_id,
            attempt,
            request_result,
            request.scenario.expected_request,
        )
        checkpoint_results.extend(request_results)
        conflicts.extend(request_conflicts)
        required_by_checkpoint.update({result.checkpoint_id: True for result in request_results})

        if request.scenario.expected_failure_stage is not None:
            result = _validate_expected_failure_stage(
                attempt,
                root,
                request.scenario.expected_failure_stage,
            )
            checkpoint_results.append(result)
            required_by_checkpoint[result.checkpoint_id] = True

        observations = _scenario_observations(attempt, request_result, root)
        scoped_observations = [
            observation
            for observation in observations
            if _observation_in_scope(observation, request.scenario, attempt)
        ]
        checkpoint_map: dict[str, CheckpointResult] = {}
        for checkpoint in request.scenario.checkpoints:
            result, checkpoint_conflicts = _evaluate_scenario_checkpoint(
                attempt,
                request_result,
                checkpoint,
                scoped_observations,
                forbidden=False,
            )
            checkpoint_results.append(result)
            checkpoint_map[checkpoint.checkpoint_id] = result
            conflicts.extend(checkpoint_conflicts)
            required_by_checkpoint[result.checkpoint_id] = checkpoint.required

        forbidden_matches: dict[str, list[_ScenarioObservation]] = {}
        for checkpoint in request.scenario.forbidden_events:
            result, checkpoint_conflicts = _evaluate_scenario_checkpoint(
                attempt,
                request_result,
                checkpoint,
                scoped_observations,
                forbidden=True,
            )
            checkpoint_results.append(result)
            checkpoint_map[checkpoint.checkpoint_id] = result
            conflicts.extend(checkpoint_conflicts)
            required_by_checkpoint[result.checkpoint_id] = checkpoint.required
            forbidden_matches[checkpoint.checkpoint_id] = [
                observation
                for observation in scoped_observations
                if _matcher_matches(checkpoint.matcher, observation)
            ]

        for ordering in request.scenario.ordering_constraints:
            result = _evaluate_checkpoint_ordering(
                attempt,
                ordering,
                checkpoint_map,
                forbidden_matches,
            )
            checkpoint_results.append(result)
            required_by_checkpoint[result.checkpoint_id] = True

    overall_status = _aggregate_scenario_status(
        checkpoint_results,
        required_by_checkpoint,
        selected_attempts,
    )
    revision = "sha256:" + sha256_bytes(
        compact_json_bytes(
            {
                "tool": "T14",
                "analysis_id": str(request.analysis_id),
                "scenario": request.scenario,
                "selected_attempt_ids": [str(item.attempt_id) for item in selected_attempts],
                "attempts": [item.model_dump(mode="json", exclude_none=True) for item in selected_attempts],
                "request_revisions": sorted(
                    item.revision for item in request.requests if item.attempt_id in {attempt.attempt_id for attempt in selected_attempts}
                ),
                "ranking_revisions": sorted(
                    item.ranking_revision for item in request.root_causes if item.attempt_id in {attempt.attempt_id for attempt in selected_attempts}
                ),
                "checkpoints": checkpoint_results,
                "conflicts": conflicts,
                "pass_stage": request.pass_stage,
                "parent": request.primary_validation_revision,
            }
        )
    )
    return ValidateScenarioResult(
        scenario_id=request.scenario.scenario_id,
        selected_attempt_ids=[attempt.attempt_id for attempt in selected_attempts],
        selection_candidates=candidates,
        checkpoints=checkpoint_results,
        overall_status=overall_status,
        conflicts=conflicts,
        warnings=warnings,
        pass_stage=request.pass_stage,
        parent_validation_revision=request.primary_validation_revision,
        dependency_result_revisions=[],
        validation_revision=revision,
    )


@dataclass(frozen=True)
class _ScenarioObservation:
    kind: str
    frame: int
    timestamp: Decimal | None
    evidence_ids: tuple[UUID, ...]
    protocol: str | None = None
    message_type: str | None = None
    stage_id: str | None = None
    fields: dict[str, Any] | None = None


_SCENARIO_MATCHER_FIELDS = {
    "access_family",
    "call_impact",
    "category",
    "cause",
    "component",
    "detector",
    "dnn",
    "emergency",
    "field_name",
    "field_status",
    "http.cause",
    "http.method",
    "http.path",
    "http.status",
    "initiator",
    "message_type",
    "operation",
    "outcome",
    "pdu_type",
    "pfcp.cause",
    "procedure_subtype",
    "procedure_type",
    "profile_id",
    "registration_type",
    "service_type",
    "severity",
    "snssai",
    "ssc_mode",
    "stage_id",
    "stage_name",
    "status",
    "transition_type",
}

_SCENARIO_CONDITION_FACTS = {
    "access_family",
    "initiator",
    "outcome",
    "procedure",
    "procedure_subtype",
    "procedure_type",
    "profile_id",
    "roaming_topology",
    *{f"request.{field_name}" for field_name in ExpectedRequest.model_fields},
}


def _validate_scenario_contract(scenario: ScenarioSpec) -> None:
    if len(scenario.checkpoints) > 64:
        raise ValueError("scenario checkpoints exceed limit 64")
    if len(scenario.forbidden_events) > 16:
        raise ValueError("scenario forbidden events exceed limit 16")
    if len(scenario.ordering_constraints) > 16:
        raise ValueError("scenario ordering constraints exceed limit 16")
    checkpoint_ids = [
        checkpoint.checkpoint_id
        for checkpoint in [*scenario.checkpoints, *scenario.forbidden_events]
    ]
    if len(checkpoint_ids) != len(set(checkpoint_ids)):
        raise ValueError("scenario checkpoint IDs must be unique")
    checkpoint_id_set = set(checkpoint_ids)
    for ordering in scenario.ordering_constraints:
        if ordering.first_checkpoint_id not in checkpoint_id_set:
            raise ValueError(f"unknown first ordering checkpoint {ordering.first_checkpoint_id}")
        if ordering.second_checkpoint_id not in checkpoint_id_set:
            raise ValueError(f"unknown second ordering checkpoint {ordering.second_checkpoint_id}")
        if ordering.constraint == "at_least_n_between" and (ordering.count is None or ordering.count < 0):
            raise ValueError("at_least_n_between requires a non-negative count")
    for checkpoint in [*scenario.checkpoints, *scenario.forbidden_events]:
        matcher = checkpoint.matcher
        if not any((matcher.protocol, matcher.message_type, matcher.stage_id, matcher.field)):
            raise ValueError(f"checkpoint {checkpoint.checkpoint_id} has an empty matcher")
        if matcher.field is not None and matcher.field not in _SCENARIO_MATCHER_FIELDS:
            raise ValueError(f"checkpoint field {matcher.field} is not allowlisted")
        condition = checkpoint.applicability_condition
        if condition is not None and condition.fact not in _SCENARIO_CONDITION_FACTS:
            raise ValueError(f"condition fact {condition.fact} is not allowlisted")
    for scope in (scenario.selectors, scenario.time_scope):
        if scope is None:
            continue
        if scope.frame_start is not None and scope.frame_end is not None and scope.frame_start > scope.frame_end:
            raise ValueError("scenario frame_start exceeds frame_end")
        if scope.time_start is not None and scope.time_end is not None and scope.time_start > scope.time_end:
            raise ValueError("scenario time_start exceeds time_end")


def _select_scenario_attempts(
    request: ValidateScenarioRequest,
    request_map: dict[UUID, UERequestResult],
) -> tuple[
    list[ScenarioAttemptCandidate],
    list[ProcedureAttempt],
    list[str],
    list[ScenarioEvidenceConflict],
]:
    selectors = request.scenario.selectors
    warnings: list[str] = []
    conflicts: list[ScenarioEvidenceConflict] = []
    if selectors.pdu_session_id is not None and not any(
        value is not None
        for value in (
            request.explicit_attempt_id,
            selectors.attempt_id,
            selectors.ue_id,
            selectors.frame_start,
            selectors.frame_end,
            selectors.time_start,
            selectors.time_end,
            request.scenario.procedure,
        )
    ):
        warnings.append("pdu_session_id_requires_additional_scope")
        return [], [], warnings, conflicts

    candidates: list[ScenarioAttemptCandidate] = []
    eligible_attempts: dict[UUID, ProcedureAttempt] = {}
    for attempt in request.attempts:
        request_result = request_map.get(attempt.attempt_id)
        score = Decimal("0")
        matched: list[str] = []
        mismatched: list[str] = []

        def compare(name: str, actual: Any, expected: Any, weight: str) -> None:
            nonlocal score
            if expected is None:
                return
            if actual == expected:
                matched.append(name)
                score += Decimal(weight)
            else:
                mismatched.append(name)

        compare("explicit_attempt_id", attempt.attempt_id, request.explicit_attempt_id, "100")
        compare("selector_attempt_id", attempt.attempt_id, selectors.attempt_id, "90")
        compare("ue_id", attempt.ue_id, selectors.ue_id, "20")
        compare("procedure", attempt.procedure_type, request.scenario.procedure, "15")
        compare("procedure_subtype", attempt.subtype, request.scenario.procedure_subtype, "8")
        compare("initiator", attempt.initiator, request.scenario.initiator, "8")
        compare("amf_ue_ngap_id", attempt.correlation_identifiers.amf_ue_ngap_id, selectors.amf_ue_ngap_id, "10")
        compare("ran_ue_ngap_id", attempt.correlation_identifiers.ran_ue_ngap_id, selectors.ran_ue_ngap_id, "10")
        compare("pdu_session_id", attempt.correlation_identifiers.pdu_session_id, selectors.pdu_session_id, "8")

        if selectors.masked_subscriber_alias is not None:
            aliases = set()
            if request_result is not None and request_result.ue is not None:
                aliases.add(request_result.ue.display)
                aliases.update(request_result.ue.kinds.values())
            compare(
                "masked_subscriber_alias",
                selectors.masked_subscriber_alias if selectors.masked_subscriber_alias in aliases else None,
                selectors.masked_subscriber_alias,
                "20",
            )

        if not _attempt_in_frame_scope(attempt, selectors.frame_start, selectors.frame_end):
            if selectors.frame_start is not None or selectors.frame_end is not None:
                mismatched.append("frame_scope")
        elif selectors.frame_start is not None or selectors.frame_end is not None:
            matched.append("frame_scope")
            score += Decimal("6")

        if not _attempt_in_time_scope(attempt, selectors.time_start, selectors.time_end):
            if selectors.time_start is not None or selectors.time_end is not None:
                mismatched.append("time_scope")
        elif selectors.time_start is not None or selectors.time_end is not None:
            matched.append("time_scope")
            score += Decimal("6")

        scenario_scope = request.scenario.time_scope
        if scenario_scope is not None:
            in_frames = _attempt_in_frame_scope(attempt, scenario_scope.frame_start, scenario_scope.frame_end)
            in_times = _attempt_in_time_scope(attempt, scenario_scope.time_start, scenario_scope.time_end)
            if in_frames and in_times:
                matched.append("scenario_time_scope")
                score += Decimal("4")
            else:
                mismatched.append("scenario_time_scope")

        for field_name, expected in request.scenario.expected_request.model_dump(exclude_none=True).items():
            if field_name == "roaming_topology":
                actual = None if attempt.roaming_topology is None else attempt.roaming_topology.selected_topology
            else:
                field = None if request_result is None else request_result.fields.get(field_name)
                actual = None if field is None else field.value
            if actual == expected:
                matched.append(f"request_signature:{field_name}")
                score += Decimal("1")

        explicit_selected = request.explicit_attempt_id is not None and attempt.attempt_id == request.explicit_attempt_id
        selector_selected = selectors.attempt_id is not None and attempt.attempt_id == selectors.attempt_id
        if request.explicit_attempt_id is not None:
            eligible = explicit_selected
        elif selectors.attempt_id is not None:
            eligible = selector_selected
        else:
            eligible = not mismatched
        candidate = ScenarioAttemptCandidate(
            attempt_id=attempt.attempt_id,
            score=score,
            matched_selectors=matched,
            mismatched_selectors=mismatched,
        )
        candidates.append(candidate)
        if eligible and score > 0:
            eligible_attempts[attempt.attempt_id] = attempt

    candidates.sort(key=lambda item: (-item.score, str(item.attempt_id)))
    if not eligible_attempts:
        warnings.append("no_attempt_selected")
        return candidates, [], warnings, conflicts

    eligible_candidates = [item for item in candidates if item.attempt_id in eligible_attempts]
    top_score = eligible_candidates[0].score
    tied = [item for item in eligible_candidates if item.score == top_score]
    if len(tied) > 1:
        for item in tied:
            item.ambiguous = True
        conflicts.append(
            ScenarioEvidenceConflict(
                checkpoint_id="attempt_selection",
                values=[str(item.attempt_id) for item in tied],
                evidence_ids=[],
                resolution="unresolved",
                reason="multiple_attempts_have_equal_selection_priority",
            )
        )
        warnings.append("ambiguous_attempt_selection")
        return candidates, [], warnings, conflicts

    selected_candidate = tied[0]
    selected_candidate.selected = True
    return candidates, [eligible_attempts[selected_candidate.attempt_id]], warnings, conflicts


def _attempt_in_frame_scope(
    attempt: ProcedureAttempt,
    frame_start: int | None,
    frame_end: int | None,
) -> bool:
    if frame_start is not None and attempt.end_frame < frame_start:
        return False
    if frame_end is not None and attempt.start_frame > frame_end:
        return False
    return True


def _attempt_in_time_scope(
    attempt: ProcedureAttempt,
    time_start: Decimal | None,
    time_end: Decimal | None,
) -> bool:
    if time_start is None and time_end is None:
        return True
    if attempt.start_timestamp is None or attempt.end_timestamp is None:
        return False
    if time_start is not None and attempt.end_timestamp < time_start:
        return False
    if time_end is not None and attempt.start_timestamp > time_end:
        return False
    return True


def _validate_expected_outcome(
    analysis_id: UUID,
    attempt: ProcedureAttempt,
    expected: Literal["success", "failure"],
) -> CheckpointResult:
    observed = "success" if attempt.outcome == "succeeded" else "failure"
    if attempt.outcome == "incomplete_capture":
        status: Literal["verified", "failed", "inconclusive", "not_applicable"] = "inconclusive"
        reason_codes = ["capture_incomplete"]
    elif observed == expected:
        status = "verified"
        reason_codes = ["explicit_attempt_terminal"]
    else:
        status = "failed"
        reason_codes = ["contradictory_attempt_terminal"]
    evidence_ids = list(attempt.event_ids[-1:]) or [
        deterministic_uuid(analysis_id, "T14", "expected_outcome", attempt.attempt_id)
    ]
    return CheckpointResult(
        checkpoint_id="expected_outcome",
        status=status,
        expected=expected,
        observed=attempt.outcome if status == "inconclusive" else observed,
        attempt_id=attempt.attempt_id,
        evidence_ids=evidence_ids,
        frames=[attempt.end_frame],
        reason_codes=reason_codes,
        visibility="partial" if status == "inconclusive" else "visible",
    )


def _validate_expected_request(
    analysis_id: UUID,
    attempt: ProcedureAttempt,
    request_result: UERequestResult | None,
    expected_request: ExpectedRequest,
) -> tuple[list[CheckpointResult], list[ScenarioEvidenceConflict]]:
    results: list[CheckpointResult] = []
    conflicts: list[ScenarioEvidenceConflict] = []
    for field_name, expected in expected_request.model_dump(exclude_none=True).items():
        checkpoint_id = f"expected_request.{field_name}"
        if field_name == "roaming_topology":
            topology = attempt.roaming_topology
            if topology is None or topology.selected_topology == "inconclusive":
                results.append(
                    CheckpointResult(
                        checkpoint_id=checkpoint_id,
                        status="inconclusive",
                        expected=expected,
                        observed=None if topology is None else topology.selected_topology,
                        attempt_id=attempt.attempt_id,
                        frames=[attempt.start_frame],
                        reason_codes=["roaming_topology_unresolved"],
                        visibility="unknown",
                    )
                )
                continue
            results.append(
                CheckpointResult(
                    checkpoint_id=checkpoint_id,
                    status="verified" if topology.selected_topology == expected else "failed",
                    expected=expected,
                    observed=topology.selected_topology,
                    attempt_id=attempt.attempt_id,
                    evidence_ids=[topology.topology_id],
                    frames=[attempt.start_frame],
                    reason_codes=["attempt_roaming_topology"],
                    visibility="visible",
                )
            )
            continue

        field = None if request_result is None else request_result.fields.get(field_name)
        field_conflict = None
        if request_result is not None:
            field_conflict = next(
                (item for item in request_result.conflicts if item.name == field_name),
                None,
            )
        if field is not None and (field.status == "conflicting" or field_conflict is not None):
            values = [] if field_conflict is None else list(field_conflict.values)
            if field.value is not None and field.value not in values:
                values.append(field.value)
            evidence_ids = list(field.evidence_ids)
            conflicts.append(
                ScenarioEvidenceConflict(
                    checkpoint_id=checkpoint_id,
                    values=values,
                    evidence_ids=evidence_ids,
                    resolution="unresolved",
                    reason="request_field_has_conflicting_values",
                )
            )
            results.append(
                CheckpointResult(
                    checkpoint_id=checkpoint_id,
                    status="inconclusive",
                    expected=expected,
                    observed=values,
                    attempt_id=attempt.attempt_id,
                    evidence_ids=evidence_ids,
                    frames=list(field.source_frames),
                    reason_codes=["request_field_conflict"],
                    visibility="visible",
                    conflict=True,
                )
            )
            continue
        if field is None or field.value is None or field.status == "unknown":
            results.append(
                CheckpointResult(
                    checkpoint_id=checkpoint_id,
                    status="inconclusive",
                    expected=expected,
                    observed=None,
                    attempt_id=attempt.attempt_id,
                    evidence_ids=[] if field is None else list(field.evidence_ids),
                    frames=[] if field is None else list(field.source_frames),
                    reason_codes=["request_field_unavailable"],
                    visibility="unknown",
                )
            )
            continue
        results.append(
            CheckpointResult(
                checkpoint_id=checkpoint_id,
                status="verified" if field.value == expected else "failed",
                expected=expected,
                observed=field.value,
                attempt_id=attempt.attempt_id,
                evidence_ids=list(field.evidence_ids),
                frames=list(field.source_frames),
                reason_codes=["explicit_ue_request_field"],
                visibility="visible",
            )
        )
    return results, conflicts


def _validate_expected_failure_stage(
    attempt: ProcedureAttempt,
    root: RootCauseResult | None,
    expected_stage: str,
) -> CheckpointResult:
    candidate = None if root is None else _candidate_by_id(root, root.primary_candidate_id)
    if candidate is None:
        return CheckpointResult(
            checkpoint_id="expected_failure_stage",
            status="inconclusive",
            expected=expected_stage,
            observed=None,
            attempt_id=attempt.attempt_id,
            frames=[attempt.end_frame],
            reason_codes=["primary_failure_candidate_unavailable"],
            visibility="unknown",
        )
    observed_stage = (
        candidate.component
        or candidate.observed.get("stage_id")
        or candidate.observed.get("component")
        or candidate.category
    )
    matched = _semantic_value_matches(observed_stage, expected_stage)
    return CheckpointResult(
        checkpoint_id="expected_failure_stage",
        status="verified" if matched else "failed",
        expected=expected_stage,
        observed=observed_stage,
        attempt_id=attempt.attempt_id,
        evidence_ids=list(candidate.evidence_ids),
        frames=[candidate.frame],
        reason_codes=["primary_candidate_stage_match" if matched else "primary_candidate_stage_mismatch"],
        visibility="visible",
    )


def _semantic_value_matches(observed: Any, expected: Any) -> bool:
    if observed == expected:
        return True
    if not isinstance(observed, str) or not isinstance(expected, str):
        return False
    observed_parts = {part for part in _semantic_parts(observed) if part}
    expected_parts = {part for part in _semantic_parts(expected) if part}
    return bool(expected_parts) and expected_parts.issubset(observed_parts)


def _semantic_parts(value: str) -> list[str]:
    normalized = "".join(character.lower() if character.isalnum() else " " for character in value)
    return normalized.split()


def _scenario_observations(
    attempt: ProcedureAttempt,
    request_result: UERequestResult | None,
    root: RootCauseResult | None,
) -> list[_ScenarioObservation]:
    observations: list[_ScenarioObservation] = []
    for transition in attempt.transitions:
        observations.append(
            _ScenarioObservation(
                kind="stage",
                frame=transition.frame,
                timestamp=transition.timestamp,
                evidence_ids=(transition.event_id,),
                message_type=transition.stage_name,
                stage_id=transition.stage_id,
                fields={
                    "transition_type": transition.transition_type,
                    "stage_id": transition.stage_id,
                    "stage_name": transition.stage_name,
                },
            )
        )
    if request_result is not None:
        for field_name, field in request_result.fields.items():
            frames = field.source_frames or request_result.trigger_frames or [attempt.start_frame]
            evidence_ids = tuple(field.evidence_ids or field.source_event_ids)
            for frame in frames[:1]:
                observations.append(
                    _ScenarioObservation(
                        kind="request_field",
                        frame=frame,
                        timestamp=None,
                        evidence_ids=evidence_ids,
                        protocol="REQUEST",
                        message_type=request_result.procedure,
                        fields={field_name: field.value, "field_name": field_name, "field_status": field.status},
                    )
                )
    if root is not None:
        for candidate in root.candidate_records:
            fields = dict(candidate.observed)
            fields.update(
                {
                    "category": candidate.category,
                    "component": candidate.component,
                    "severity": candidate.severity,
                    "detector": candidate.detector,
                    "call_impact": candidate.call_impact,
                }
            )
            observations.append(
                _ScenarioObservation(
                    kind="failure_candidate",
                    frame=candidate.frame,
                    timestamp=None,
                    evidence_ids=tuple(candidate.evidence_ids),
                    protocol=candidate.protocol,
                    message_type=str(candidate.observed.get("message_type") or candidate.category),
                    stage_id=candidate.component or candidate.observed.get("stage_id"),
                    fields=fields,
                )
            )
    observations.append(
        _ScenarioObservation(
            kind="attempt",
            frame=attempt.end_frame,
            timestamp=attempt.end_timestamp,
            evidence_ids=tuple(attempt.event_ids[-1:]),
            message_type=attempt.completion_reason,
            fields={
                "outcome": attempt.outcome,
                "profile_id": attempt.profile_id,
                "procedure_type": attempt.procedure_type,
                "procedure_subtype": attempt.subtype,
                "initiator": attempt.initiator,
                "access_family": attempt.access_family,
            },
        )
    )
    return sorted(observations, key=lambda item: (item.frame, item.kind, item.stage_id or "", item.message_type or ""))


def _observation_in_scope(
    observation: _ScenarioObservation,
    scenario: ScenarioSpec,
    attempt: ProcedureAttempt,
) -> bool:
    scopes = [scenario.selectors, scenario.time_scope]
    for scope in scopes:
        if scope is None:
            continue
        if scope.frame_start is not None and observation.frame < scope.frame_start:
            return False
        if scope.frame_end is not None and observation.frame > scope.frame_end:
            return False
        if scope.time_start is not None:
            if observation.timestamp is None or observation.timestamp < scope.time_start:
                return False
        if scope.time_end is not None:
            if observation.timestamp is None or observation.timestamp > scope.time_end:
                return False
    return attempt.start_frame <= observation.frame <= attempt.end_frame


def _evaluate_scenario_checkpoint(
    attempt: ProcedureAttempt,
    request_result: UERequestResult | None,
    checkpoint: ScenarioCheckpoint,
    observations: list[_ScenarioObservation],
    *,
    forbidden: bool,
) -> tuple[CheckpointResult, list[ScenarioEvidenceConflict]]:
    applicability = _condition_result(checkpoint.applicability_condition, attempt, request_result)
    if applicability is False:
        return (
            CheckpointResult(
                checkpoint_id=checkpoint.checkpoint_id,
                status="not_applicable",
                expected=checkpoint.expected_value,
                attempt_id=attempt.attempt_id,
                reason_codes=["applicability_condition_false"],
                visibility="not_applicable",
            ),
            [],
        )
    if applicability is None:
        return (
            CheckpointResult(
                checkpoint_id=checkpoint.checkpoint_id,
                status="inconclusive",
                expected=checkpoint.expected_value,
                attempt_id=attempt.attempt_id,
                reason_codes=["applicability_fact_unknown"],
                visibility="unknown",
            ),
            [],
        )

    matches = [observation for observation in observations if _matcher_matches(checkpoint.matcher, observation)]
    visibility, visibility_results = _checkpoint_visibility(checkpoint, attempt, request_result, bool(matches))
    conflicts: list[ScenarioEvidenceConflict] = []
    if checkpoint.matcher.field is not None:
        relevant_values = {
            _hashable_value((observation.fields or {}).get(checkpoint.matcher.field))
            for observation in observations
            if checkpoint.matcher.field in (observation.fields or {})
        }
        relevant_values.discard(None)
        if len(relevant_values) > 1:
            values = [value for value in sorted(relevant_values, key=str)]
            conflicts.append(
                ScenarioEvidenceConflict(
                    checkpoint_id=checkpoint.checkpoint_id,
                    values=values,
                    evidence_ids=[evidence_id for observation in matches for evidence_id in observation.evidence_ids],
                    resolution="unresolved",
                    reason="multiple_observed_values_for_checkpoint_field",
                )
            )
            return (
                CheckpointResult(
                    checkpoint_id=checkpoint.checkpoint_id,
                    status="inconclusive",
                    expected=checkpoint.expected_value if checkpoint.expected_value is not None else checkpoint.matcher.value,
                    observed=values,
                    attempt_id=attempt.attempt_id,
                    evidence_ids=[evidence_id for observation in matches for evidence_id in observation.evidence_ids],
                    frames=[observation.frame for observation in matches],
                    reason_codes=["evidence_conflict"],
                    visibility=visibility,
                    visibility_results=visibility_results,
                    conflict=True,
                ),
                conflicts,
            )

    if forbidden:
        if matches:
            status: Literal["verified", "failed", "inconclusive", "not_applicable"] = "failed"
            reason_codes = ["forbidden_event_observed"]
        elif visibility == "visible" and not attempt.incomplete_history and attempt.outcome != "incomplete_capture":
            status = "verified"
            reason_codes = ["forbidden_event_absent_in_visible_scope"]
        else:
            status = "inconclusive"
            reason_codes = ["forbidden_event_absence_not_provable"]
    elif matches:
        status = "verified"
        reason_codes = ["checkpoint_match_observed"]
    elif visibility == "visible" and not attempt.incomplete_history and attempt.outcome != "incomplete_capture":
        status = "failed"
        reason_codes = ["required_checkpoint_absent_in_visible_scope"]
    else:
        status = "inconclusive"
        reason_codes = ["checkpoint_evidence_or_visibility_insufficient"]

    return (
        CheckpointResult(
            checkpoint_id=checkpoint.checkpoint_id,
            status=status,
            expected=checkpoint.expected_value if checkpoint.expected_value is not None else checkpoint.matcher.value,
            observed=[_observation_value(checkpoint.matcher, observation) for observation in matches] or None,
            attempt_id=attempt.attempt_id,
            evidence_ids=[evidence_id for observation in matches for evidence_id in observation.evidence_ids],
            frames=[observation.frame for observation in matches],
            reason_codes=reason_codes,
            visibility=visibility,
            visibility_results=visibility_results,
        ),
        conflicts,
    )


def _matcher_matches(matcher: ScenarioMatcher, observation: _ScenarioObservation) -> bool:
    if matcher.protocol is not None and not _semantic_value_matches(observation.protocol, matcher.protocol):
        return False
    if matcher.message_type is not None and not _semantic_value_matches(observation.message_type, matcher.message_type):
        return False
    if matcher.stage_id is not None and not _semantic_value_matches(observation.stage_id, matcher.stage_id):
        return False
    if matcher.field is None:
        return any((matcher.protocol, matcher.message_type, matcher.stage_id))
    fields = observation.fields or {}
    present = matcher.field in fields and fields[matcher.field] is not None
    value = fields.get(matcher.field)
    if matcher.operator == "present":
        return present
    if matcher.operator == "absent":
        return not present
    if not present:
        return False
    if matcher.operator == "eq":
        return value == matcher.value
    if matcher.operator == "ne":
        return value != matcher.value
    if matcher.operator == "in":
        return isinstance(matcher.value, (list, tuple, set)) and value in matcher.value
    return False


def _observation_value(matcher: ScenarioMatcher, observation: _ScenarioObservation) -> Any:
    if matcher.field is not None:
        return (observation.fields or {}).get(matcher.field)
    if matcher.stage_id is not None:
        return observation.stage_id
    if matcher.message_type is not None:
        return observation.message_type
    return observation.protocol


def _condition_result(
    condition: ScenarioCondition | None,
    attempt: ProcedureAttempt,
    request_result: UERequestResult | None,
) -> bool | None:
    if condition is None:
        return True
    facts: dict[str, Any] = {
        "procedure": attempt.procedure_type,
        "procedure_type": attempt.procedure_type,
        "procedure_subtype": attempt.subtype,
        "profile_id": attempt.profile_id,
        "initiator": attempt.initiator,
        "access_family": attempt.access_family,
        "outcome": attempt.outcome,
        "roaming_topology": None if attempt.roaming_topology is None else attempt.roaming_topology.selected_topology,
    }
    if request_result is not None:
        facts.update({f"request.{name}": field.value for name, field in request_result.fields.items()})
    present = condition.fact in facts and facts[condition.fact] is not None
    value = facts.get(condition.fact)
    if condition.operator == "present":
        return present
    if condition.operator == "absent":
        return not present
    if not present:
        return None
    if condition.operator == "eq":
        return value == condition.value
    if condition.operator == "ne":
        return value != condition.value
    if condition.operator == "in":
        return isinstance(condition.value, (list, tuple, set)) and value in condition.value
    return None


def _checkpoint_visibility(
    checkpoint: ScenarioCheckpoint,
    attempt: ProcedureAttempt,
    request_result: UERequestResult | None,
    matched: bool,
) -> tuple[str, list[StageVisibilityResult]]:
    if matched:
        return "visible", []
    if checkpoint.matcher.field is not None and request_result is not None:
        if checkpoint.matcher.field in request_result.fields:
            return "visible", []
    protocol = (checkpoint.protocol or checkpoint.matcher.protocol or "").upper()
    reference_key = {"NAS": "N1", "NGAP": "N2", "PFCP": "N4"}.get(protocol)
    if reference_key is not None:
        state = attempt.visibility.reference_points.get(reference_key, "unknown")
        result = StageVisibilityResult(
            domain="reference_point",
            key=reference_key,
            state=state,
            minimum_state="visible",
            satisfied=state == "visible",
        )
        return state, [result]
    if protocol == "HTTP2":
        states = [*attempt.visibility.services.items(), *attempt.visibility.apis.items()]
        if states:
            key, state = sorted(states)[0]
            domain: Literal["reference_point", "sbi_service", "sbi_api"] = (
                "sbi_service" if key in attempt.visibility.services else "sbi_api"
            )
            result = StageVisibilityResult(
                domain=domain,
                key=key,
                state=state,
                minimum_state="visible",
                satisfied=state == "visible",
            )
            return state, [result]
    return "unknown", []


def _evaluate_checkpoint_ordering(
    attempt: ProcedureAttempt,
    ordering: CheckpointOrdering,
    checkpoint_map: dict[str, CheckpointResult],
    forbidden_matches: dict[str, list[_ScenarioObservation]],
) -> CheckpointResult:
    checkpoint_id = (
        f"ordering.{ordering.first_checkpoint_id}.{ordering.constraint}."
        f"{ordering.second_checkpoint_id}"
    )
    first = checkpoint_map.get(ordering.first_checkpoint_id)
    second = checkpoint_map.get(ordering.second_checkpoint_id)
    if first is None or second is None:
        return CheckpointResult(
            checkpoint_id=checkpoint_id,
            status="inconclusive",
            attempt_id=attempt.attempt_id,
            reason_codes=["ordering_checkpoint_missing"],
            visibility="unknown",
        )
    if first.status != "verified" or second.status != "verified" or not first.frames or not second.frames:
        return CheckpointResult(
            checkpoint_id=checkpoint_id,
            status="inconclusive",
            attempt_id=attempt.attempt_id,
            evidence_ids=[*first.evidence_ids, *second.evidence_ids],
            frames=[*first.frames, *second.frames],
            reason_codes=["ordering_endpoint_inconclusive"],
            visibility="unknown",
        )

    first_frame = min(first.frames)
    second_frame = min(second.frames)
    verified = first_frame < second_frame
    reason = "checkpoint_order_verified" if verified else "checkpoint_order_violated"
    if ordering.constraint == "immediately_before":
        ordered_frames = sorted(
            min(result.frames)
            for result in checkpoint_map.values()
            if result.status == "verified" and result.frames
        )
        verified = verified and ordered_frames.index(first_frame) + 1 == ordered_frames.index(second_frame)
        reason = "checkpoint_immediate_order_verified" if verified else "checkpoint_immediate_order_violated"
    elif ordering.constraint == "at_least_n_between":
        between = sum(
            first_frame < min(result.frames) < second_frame
            for result in checkpoint_map.values()
            if result.status == "verified" and result.frames
        )
        required = ordering.count or 0
        verified = verified and between >= required
        reason = "checkpoint_count_between_verified" if verified else "checkpoint_count_between_violated"
    elif ordering.constraint == "no_forbidden_between":
        forbidden_frames = [
            observation.frame
            for observations in forbidden_matches.values()
            for observation in observations
            if first_frame < observation.frame < second_frame
        ]
        verified = verified and not forbidden_frames
        reason = "no_forbidden_event_between" if verified else "forbidden_event_between_checkpoints"

    return CheckpointResult(
        checkpoint_id=checkpoint_id,
        status="verified" if verified else "failed",
        expected=ordering.constraint,
        observed={"first_frame": first_frame, "second_frame": second_frame},
        attempt_id=attempt.attempt_id,
        evidence_ids=[*first.evidence_ids, *second.evidence_ids],
        frames=[first_frame, second_frame],
        reason_codes=[reason],
        visibility="visible",
    )


def _aggregate_scenario_status(
    results: list[CheckpointResult],
    required_by_checkpoint: dict[str, bool],
    selected_attempts: list[ProcedureAttempt],
) -> Literal["verified", "failed", "inconclusive", "not_applicable"]:
    if not selected_attempts:
        return "inconclusive"
    required = [result for result in results if required_by_checkpoint.get(result.checkpoint_id, True)]
    if any(result.status == "failed" for result in required):
        return "failed"
    if any(result.status == "inconclusive" for result in required):
        return "inconclusive"
    applicable = [result for result in required if result.status != "not_applicable"]
    if applicable and all(result.status == "verified" for result in applicable):
        return "verified"
    return "not_applicable"


def _hashable_value(value: Any) -> Any:
    if isinstance(value, (dict, list, tuple, set)):
        return compact_json_bytes(value).decode("utf-8")
    return value


def build_initial_evidence_packet(request: BuildInitialEvidenceRequest) -> BuildEvidencePacketResult:
    validate_inside_run(request.run_dir, request.evidence_dir)
    primary_candidate = _candidate_by_id(request.root_cause, request.root_cause.primary_candidate_id)
    alternative_candidates = [
        candidate
        for candidate in request.root_cause.candidate_records
        if candidate.candidate_id in request.root_cause.alternative_candidate_ids
    ][: request.config.max_alternatives]
    downstream_candidates = [
        candidate
        for candidate in request.root_cause.candidate_records
        if candidate.candidate_id in request.root_cause.downstream_candidate_ids
    ]
    packet = EvidencePacket(
        packet_id=deterministic_uuid(request.analysis_id, "T15", request.attempt.attempt_id, request.root_cause.ranking_revision, request.provider_mode),
        analysis_id=request.analysis_id,
        pass_stage="primary",
        token_budget=request.token_budget,
        schema_guide=EvidenceSchemaGuide(rules=[
            "candidate_ids and evidence_ids are references",
            "deterministic root cause is authoritative",
            "dependency tools may be requested only in initial pass",
        ]),
        ue=request.request_result.ue,
        ue_request=UERequestEvidence(
            procedure=request.request_result.procedure,
            fields={name: field.value for name, field in request.request_result.fields.items() if field.value is not None},
        ),
        attempt=AttemptEvidence(
            attempt_id=request.attempt.attempt_id,
            profile_id=request.attempt.profile_id,
            outcome=request.attempt.outcome,
            completion_reason=request.attempt.completion_reason,
            request_signature=request.attempt.request_signature,
        ),
        primary_failure=None if primary_candidate is None else FailureEvidence(
            candidate_id=primary_candidate.candidate_id,
            summary=primary_candidate.summary,
            protocol=primary_candidate.protocol,
            category=primary_candidate.category,
            frame=primary_candidate.frame,
            evidence_ids=primary_candidate.evidence_ids,
        ),
        alternatives=[
            FailureEvidence(
                candidate_id=candidate.candidate_id,
                summary=candidate.summary,
                protocol=candidate.protocol,
                category=candidate.category,
                frame=candidate.frame,
                evidence_ids=candidate.evidence_ids,
            )
            for candidate in alternative_candidates
        ],
        downstream_effects=[
            FailureEvidence(
                candidate_id=candidate.candidate_id,
                summary=candidate.summary,
                protocol=candidate.protocol,
                category=candidate.category,
                frame=candidate.frame,
                evidence_ids=candidate.evidence_ids,
            )
            for candidate in downstream_candidates
        ],
        timeline=[
            TimelineEvidence(
                item_id=item.item_id,
                frame=item.frame,
                label=item.label,
                message=item.message,
                evidence_ids=item.evidence_ids,
            )
            for item in request.timeline.items[: request.config.max_timeline_items]
        ],
        comparison=_comparison_evidence(request.comparison),
        scenario_results=_scenario_evidence(request.scenario_validation),
        evidence=_packet_evidence_from_request(request.request_result),
        dependency_tools_available=[
            DependencyToolDescriptor(tool="inspect_nrf_flow"),
            DependencyToolDescriptor(tool="inspect_udr_flow"),
        ],
        deterministic_limitations=list(request.root_cause.limitations),
        warnings=[],
        parent_packet_id=None,
        root_cause_revision=request.root_cause.ranking_revision,
        scenario_validation_revision=None if request.scenario_validation is None else request.scenario_validation.validation_revision,
        dependency_result_revisions=[],
    )
    return _publish_evidence_packet(request.analysis_id, packet, request.run_dir, request.evidence_dir, request.token_budget.counter)


def build_expanded_evidence_packet(request: BuildExpandedEvidenceRequest) -> BuildEvidencePacketResult:
    validate_inside_run(request.run_dir, request.evidence_dir)
    packet = request.initial_packet.model_copy(deep=True)
    packet.packet_id = deterministic_uuid(packet.analysis_id, "T15", "expanded", packet.packet_id, request.expanded_root_cause.ranking_revision)
    packet.pass_stage = "dependency_expanded"
    packet.parent_packet_id = request.initial_packet.packet_id
    packet.root_cause_revision = request.expanded_root_cause.ranking_revision
    packet.scenario_validation_revision = None if request.scenario_validation is None else request.scenario_validation.validation_revision
    packet.dependency_result_revisions = [getattr(item, "revision", "") for item in request.dependency_results if getattr(item, "revision", None)]
    primary_candidate = _candidate_by_id(request.expanded_root_cause, request.expanded_root_cause.primary_candidate_id)
    packet.primary_failure = None if primary_candidate is None else FailureEvidence(
        candidate_id=primary_candidate.candidate_id,
        summary=primary_candidate.summary,
        protocol=primary_candidate.protocol,
        category=primary_candidate.category,
        frame=primary_candidate.frame,
        evidence_ids=primary_candidate.evidence_ids,
    )
    packet.alternatives = [
        FailureEvidence(
            candidate_id=candidate.candidate_id,
            summary=candidate.summary,
            protocol=candidate.protocol,
            category=candidate.category,
            frame=candidate.frame,
            evidence_ids=candidate.evidence_ids,
        )
        for candidate in request.expanded_root_cause.candidate_records
        if candidate.candidate_id in request.expanded_root_cause.alternative_candidate_ids
    ]
    packet.downstream_effects = [
        FailureEvidence(
            candidate_id=candidate.candidate_id,
            summary=candidate.summary,
            protocol=candidate.protocol,
            category=candidate.category,
            frame=candidate.frame,
            evidence_ids=candidate.evidence_ids,
        )
        for candidate in request.expanded_root_cause.candidate_records
        if candidate.candidate_id in request.expanded_root_cause.downstream_candidate_ids
    ]
    packet.dependency_evidence = [
        DependencyInspectionEvidence(
            request_id=getattr(item, "request_id"),
            tool="inspect_nrf_flow" if item.__class__.__name__.startswith("NRF") else "inspect_udr_flow",
            status=getattr(item, "status"),
            summary=f"{item.__class__.__name__}:{getattr(item, 'status')}",
            candidate_ids=[candidate.candidate_id for candidate in getattr(item, "failure_candidates", [])],
        )
        for item in request.dependency_results
    ]
    return _publish_evidence_packet(request.initial_packet.analysis_id, packet, request.run_dir, request.evidence_dir, request.token_budget.counter)


def generate_diagnosis(request: GenerateDiagnosisRequest) -> GenerateDiagnosisResult:
    if request.provider_config.mode == "none":
        return GenerateDiagnosisResult(
            attempt_id=request.attempt_id,
            packet_id=request.packet.packet_id,
            pass_stage=request.pass_stage,
            status="disabled",
            diagnosis=None,
            provider=None,
            validation_errors=[],
            warnings=["provider_disabled"],
        )
    try:
        payload, provider = _invoke_provider_transport(request)
        diagnosis, validation_errors, warnings = _validate_provider_diagnosis(request, payload)
    except (
        TimeoutError,
        urllib_error.URLError,
        urllib_error.HTTPError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        return GenerateDiagnosisResult(
            attempt_id=request.attempt_id,
            packet_id=request.packet.packet_id,
            pass_stage=request.pass_stage,
            status="failed",
            diagnosis=None,
            provider=ProviderMetadata(mode=request.provider_config.mode, model=request.provider_config.model, request_id=None),
            validation_errors=[],
            warnings=[f"provider_failed:{exc.__class__.__name__}"],
        )
    return GenerateDiagnosisResult(
        attempt_id=request.attempt_id,
        packet_id=request.packet.packet_id,
        pass_stage=request.pass_stage,
        status="success",
        diagnosis=diagnosis,
        provider=provider,
        validation_errors=validation_errors,
        warnings=warnings,
    )


def lookup_full_evidence(request: LookupFullEvidenceRequest) -> LookupFullEvidenceResult:
    _validate_capability(
        request.caller_capability,
        analysis_id=request.analysis_id,
        revision=request.normalization.revision,
        detail=request.detail,
    )
    events = _load_all_events(request.normalization)
    candidate_by_id = {candidate.candidate_id: candidate for candidate in request.candidates}
    event_by_id = {event.event_id: event for event in events}
    attempts_by_event_id: DefaultDict[UUID, list[UUID]] = defaultdict(list)
    for attempt in request.attempts:
        for event_id in attempt.event_ids:
            attempts_by_event_id[event_id].append(attempt.attempt_id)
    registry = _build_evidence_registry(
        request.analysis_id,
        request.normalization.revision,
        events,
        request.attempts,
        request.candidates,
        request.request_results,
    )
    registry_by_record_id = {
        entry.record_id: entry
        for entry in registry.values()
        if entry.record_id is not None
    }
    registry_ids_by_event: DefaultDict[UUID, list[UUID]] = defaultdict(list)
    for entry in registry.values():
        for event_id in entry.source_event_ids:
            registry_ids_by_event[event_id].append(entry.evidence_id)
    if not any(
        (
            request.selectors.event_ids,
            request.selectors.evidence_ids,
            request.selectors.attempt_ids,
            request.selectors.candidate_ids,
            request.selectors.record_ids,
            request.selectors.frame,
            request.selectors.frame_start,
            request.selectors.frame_end,
            request.selectors.protocol,
        )
    ):
        raise ValueError("at least one evidence selector is required")
    event_ids = set(request.selectors.event_ids)
    for event_id in request.selectors.event_ids:
        if event_id not in event_by_id:
            raise ValueError(f"unknown event_id {event_id}")
    if request.selectors.attempt_ids:
        for attempt in request.attempts:
            if attempt.attempt_id in request.selectors.attempt_ids:
                if not _attempt_authorized(request.caller_capability, attempt.attempt_id):
                    raise ValueError(f"attempt {attempt.attempt_id} is outside capability scope")
                event_ids.update(attempt.event_ids)
        if not event_ids:
            raise ValueError("attempt selectors resolved to no authorized events")
    if request.selectors.candidate_ids:
        for candidate_id in request.selectors.candidate_ids:
            candidate = candidate_by_id.get(candidate_id)
            if candidate is None:
                raise ValueError(f"unknown candidate_id {candidate_id}")
            if not _attempt_authorized(request.caller_capability, candidate.attempt_id):
                raise ValueError(f"candidate {candidate_id} is outside capability scope")
            for evidence_id in candidate.evidence_ids:
                entry = registry.get(evidence_id)
                if entry is not None:
                    _ensure_registry_entry_authorized(request.caller_capability, entry, event_by_id, attempts_by_event_id)
            event_ids.update(candidate.source_event_ids)
            if not candidate.source_event_ids:
                raise ValueError(f"candidate {candidate_id} does not resolve to source events")
    if request.selectors.evidence_ids:
        for evidence_id in request.selectors.evidence_ids:
            entry = registry.get(evidence_id)
            if entry is None:
                raise ValueError(f"unknown evidence_id {evidence_id}")
            _ensure_registry_entry_authorized(request.caller_capability, entry, event_by_id, attempts_by_event_id)
            if not entry.source_event_ids:
                raise ValueError(f"evidence_id {evidence_id} does not resolve to source events")
            event_ids.update(entry.source_event_ids)
    if request.selectors.record_ids:
        for record_id in request.selectors.record_ids:
            entry = registry_by_record_id.get(record_id)
            if entry is None:
                raise ValueError(f"unknown record_id {record_id}")
            _ensure_registry_entry_authorized(request.caller_capability, entry, event_by_id, attempts_by_event_id)
            event_ids.update(entry.source_event_ids)
    selected_events = []
    for event in events:
        if event_ids and event.event_id not in event_ids:
            continue
        if request.selectors.frame is not None and event.frame != request.selectors.frame:
            continue
        if request.selectors.frame_start is not None and event.frame < request.selectors.frame_start:
            continue
        if request.selectors.frame_end is not None and event.frame > request.selectors.frame_end:
            continue
        if request.selectors.protocol is not None and event.protocol != request.selectors.protocol:
            continue
        _ensure_authorized_event(
            request.caller_capability,
            event,
            attempt_ids=attempts_by_event_id.get(event.event_id, []),
        )
        selected_events.append(event)
    if not selected_events:
        raise ValueError("selectors resolved to no authorized evidence")
    selected_events = sorted(selected_events, key=lambda item: (item.frame, str(item.event_id)))
    query_payload = {
        "detail": request.detail,
        "field_paths": request.field_paths,
        "selectors": request.selectors.model_dump(mode="json", exclude_none=True),
        "revision": request.normalization.revision,
    }
    query_id = deterministic_uuid(request.analysis_id, "T18", request.detail, *(str(item.event_id) for item in selected_events))
    all_records = [
        FullEvidenceRecord(
            record_id=deterministic_uuid(request.analysis_id, "T18", event.event_id),
            protocol=event.protocol,
            partition=event.partition,
            frame_start=event.frame,
            frame_end=event.frame,
            timestamp_start=event.timestamp,
            timestamp_end=event.timestamp,
            metadata={
                "message_type": event.message_type,
                "outcome": event.outcome,
                "direction": event.direction,
                "evidence_registry_ids": [str(item) for item in sorted(registry_ids_by_event.get(event.event_id, []), key=str)],
            },
            content=None if request.detail == "metadata" else event.model_dump(mode="json", exclude_none=True),
            raw_content=None
            if request.detail != "raw_full"
            else _raw_content_from_source_refs(request.normalization, event.raw_refs),
            source=ArtifactLocation(
                relative_path=event.raw_refs[0].decoder_file if event.raw_refs else "unknown",
                artifact_sha256=event.raw_refs[0].artifact_sha256 if event.raw_refs else "unknown",
            ),
            checksum_verified=True,
            field_path_results=_field_path_results(event.model_dump(mode="json", exclude_none=True), request.field_paths),
            warnings=[],
        )
        for event in selected_events
    ]
    selected_payload, truncated, next_cursor = _paginate_items(
        tool="T18",
        analysis_id=request.analysis_id,
        revision=request.normalization.revision,
        query_payload=query_payload,
        cursor=request.cursor,
        items=[record.model_dump(mode="json", exclude_none=True) for record in all_records],
        page_size_bytes=request.page_size_bytes,
        max_records=request.max_records,
    )
    records = [FullEvidenceRecord.model_validate(item) for item in selected_payload]
    payload_bytes = len(compact_json_bytes(selected_payload))
    return LookupFullEvidenceResult(
        query_id=query_id,
        records=records,
        total_matches=len(selected_events),
        returned_records=len(records),
        returned_bytes=payload_bytes,
        truncated=truncated,
        next_cursor=next_cursor,
        warnings=[],
    )


def get_packet_context(request: GetPacketContextRequest) -> PacketContextResult:
    validate_inside_run(request.run_dir, request.context_dir)
    _validate_capability(
        request.caller_capability,
        analysis_id=request.analysis_id,
        revision=request.normalization.revision,
        detail=request.detail,
    )
    events = _load_all_events(request.normalization)
    attempt_map = {attempt.attempt_id: attempt for attempt in request.attempts}
    attempts_by_event_id: DefaultDict[UUID, list[UUID]] = defaultdict(list)
    for attempt in request.attempts:
        for event_id in attempt.event_ids:
            attempts_by_event_id[event_id].append(attempt.attempt_id)
    anchor_frame = _resolve_anchor_frame(request.anchor, events, request.candidates)
    start_frame = max(1, anchor_frame - (request.window.frames_before or 0))
    end_frame = anchor_frame + (request.window.frames_after or 0)
    if request.caller_capability.frame_start is not None:
        start_frame = max(start_frame, request.caller_capability.frame_start)
    if request.caller_capability.frame_end is not None:
        end_frame = min(end_frame, request.caller_capability.frame_end)
    if start_frame > end_frame:
        raise ValueError("context window is outside capability frame bounds")
    packets = []
    for event in events:
        if event.frame < start_frame or event.frame > end_frame:
            continue
        if request.protocol_filter is not None and request.protocol_filter.protocols and event.protocol not in request.protocol_filter.protocols:
            continue
        attempt_ids = attempts_by_event_id.get(event.event_id, [])
        _ensure_authorized_event(request.caller_capability, event, attempt_ids=attempt_ids)
        correlation = "selected_attempt" if request.caller_capability.attempt_ids and any(attempt_id in request.caller_capability.attempt_ids for attempt_id in attempt_ids) else "other_attempt" if attempt_ids else "unassigned"
        packets.append(
            ContextPacket(
                frame=event.frame,
                timestamp=event.timestamp,
                src=event.src,
                dst=event.dst,
                protocols=[event.protocol],
                summary=event.message_type,
                detail=None if request.detail == "summary" else event.model_dump(mode="json", exclude_none=True),
                event_ids=[event.event_id],
                attempt_ids=attempt_ids,
                correlation=correlation,
                partition=event.partition,
                evidence_ids=[deterministic_uuid(request.analysis_id, "T19", "context_evidence", event.event_id)],
                source_ref={} if not event.raw_refs else event.raw_refs[0].model_dump(mode="json", exclude_none=True),
            )
        )
    if request.anchor.event_id is not None and all(packet.event_ids[0] != request.anchor.event_id for packet in packets):
        raise ValueError(f"unknown or unauthorized anchor event_id {request.anchor.event_id}")
    if request.anchor.candidate_id is not None and not any(packet.frame == anchor_frame for packet in packets):
        raise ValueError(f"unknown or unauthorized anchor candidate_id {request.anchor.candidate_id}")
    query_id = deterministic_uuid(request.analysis_id, "T19", anchor_frame, start_frame, end_frame, request.detail)
    relative_dir = f"evidence/context/{query_id}"
    artifact_relative = f"{relative_dir}/packets.jsonl"
    manifest_relative = f"{relative_dir}/context_manifest.json"
    staging_root = request.run_dir / "staging" / f"T19-{query_id}"
    reset_staging_directory(request.run_dir, staging_root)
    writer = JsonlArtifactWriter(staging_root, request.run_dir, artifact_relative, "packet_context")
    query_payload = {
        "anchor": request.anchor.model_dump(mode="json", exclude_none=True),
        "window": request.window.model_dump(mode="json", exclude_none=True),
        "detail": request.detail,
        "protocol_filter": None if request.protocol_filter is None else sorted(request.protocol_filter.protocols),
        "revision": request.normalization.revision,
    }
    page_payload, truncated, next_cursor = _paginate_items(
        tool="T19",
        analysis_id=request.analysis_id,
        revision=request.normalization.revision,
        query_payload=query_payload,
        cursor=request.cursor,
        items=[packet.model_dump(mode="json", exclude_none=True) for packet in packets],
        page_size_bytes=request.page_size_bytes,
        max_records=request.max_packets,
    )
    page_packets = [ContextPacket.model_validate(item) for item in page_payload]
    for packet in page_packets:
        writer.write(packet)
    artifact_closed = writer.close()
    manifest_closed = JsonArtifactWriter(staging_root, request.run_dir, manifest_relative, "packet_context_manifest").write(
        {
            "schema_version": SCHEMA_VERSION,
            "tool": "T19",
            "query_id": str(query_id),
            "analysis_id": str(request.analysis_id),
            "effective_window": {"frame_start": start_frame, "frame_end": end_frame},
        }
    )
    publish_closed_artifacts(request.run_dir, [artifact_closed, manifest_closed], manifest_relative_path=manifest_relative)
    artifact_path = request.run_dir / artifact_relative
    manifest_path = request.run_dir / manifest_relative
    return PacketContextResult(
        query_id=query_id,
        effective_anchor=request.anchor.model_copy(update={"frame": anchor_frame}),
        effective_window=ContextWindow(frames_before=request.window.frames_before, frames_after=request.window.frames_after),
        packets=page_packets,
        artifact=ArtifactDescriptor(
            artifact_id=str(deterministic_uuid(request.analysis_id, "T19", query_id, "artifact")),
            relative_path=artifact_relative,
            artifact_type="packet_context",
            media_type="application/x-ndjson",
            format_schema_version=SCHEMA_VERSION,
            sha256=sha256_file(artifact_path),
            byte_size=artifact_path.stat().st_size,
            record_count=len(page_packets),
            creation_stage="T19",
            parent_source_sha256=request.normalization.manifest.sha256,
            revision=f"sha256:{sha256_file(artifact_path)}",
        ),
        source_mode="retained",
        total_matching=len(packets),
        truncated=truncated,
        next_cursor=next_cursor,
        manifest=ArtifactDescriptor(
            artifact_id=str(deterministic_uuid(request.analysis_id, "T19", query_id, "manifest")),
            relative_path=manifest_relative,
            artifact_type="packet_context_manifest",
            media_type="application/json",
            format_schema_version=SCHEMA_VERSION,
            sha256=sha256_file(manifest_path),
            byte_size=manifest_path.stat().st_size,
            record_count=1,
            creation_stage="T19",
            parent_source_sha256=request.normalization.manifest.sha256,
            revision=f"sha256:{sha256_file(manifest_path)}",
        ),
        manifest_path=manifest_path,
        warnings=[],
    )


def targeted_redecode(request: TargetedRedecodeRequest) -> TargetedRedecodeResult:
    validate_inside_run(request.run_dir, request.redecode_dir)
    _validate_capability(
        request.caller_capability,
        analysis_id=request.analysis_id,
        revision=request.normalization.revision,
        detail=request.output_mode,
    )
    started = datetime.now(tz=timezone.utc)
    events = _load_all_events(request.normalization)
    frame_start = request.selection.frame_start
    frame_end = request.selection.frame_end
    if request.selection.time_start is not None or request.selection.time_end is not None:
        time_selected = [
            event.frame
            for event in events
            if (request.selection.time_start is None or (event.timestamp is not None and event.timestamp >= request.selection.time_start))
            and (request.selection.time_end is None or (event.timestamp is not None and event.timestamp <= request.selection.time_end))
        ]
        if time_selected:
            frame_start = min(time_selected) if frame_start is None else max(frame_start, min(time_selected))
            frame_end = max(time_selected) if frame_end is None else min(frame_end, max(time_selected))
    if request.caller_capability.frame_start is not None:
        frame_start = request.caller_capability.frame_start if frame_start is None else max(frame_start, request.caller_capability.frame_start)
    if request.caller_capability.frame_end is not None:
        frame_end = request.caller_capability.frame_end if frame_end is None else min(frame_end, request.caller_capability.frame_end)
    explicit_frames = sorted(
        {
            frame
            for frame in request.selection.explicit_frames
            if (request.caller_capability.frame_start is None or frame >= request.caller_capability.frame_start)
            and (request.caller_capability.frame_end is None or frame <= request.caller_capability.frame_end)
        }
    )
    selected = [
        event
        for event in events
        if (
            (frame_start is not None and frame_end is not None and frame_start <= event.frame <= frame_end)
            or event.frame in explicit_frames
        )
    ]
    if not selected:
        elapsed_ms = int((datetime.now(tz=timezone.utc) - started).total_seconds() * 1000)
        return TargetedRedecodeResult(
            query_id=deterministic_uuid(request.analysis_id, "T20", "empty"),
            status="empty",
            artifact=None,
            manifest=None,
            tshark_version="retained-baseline",
            access_plan=RedecodeAccessPlan(
                mode="full_scan_fallback",
                target_selection=request.selection,
                slice_packets=0,
                slice_bytes=0,
                source_frame_map_checksum="",
            ),
            record_count=0,
            output_bytes=0,
            elapsed_ms=elapsed_ms,
            warnings=[],
        )
    query_id = deterministic_uuid(request.analysis_id, "T20", request.output_mode, *(str(item.event_id) for item in selected))
    relative_dir = f"evidence/redecode/{query_id}"
    artifact_relative = f"{relative_dir}/result.jsonl"
    manifest_relative = f"{relative_dir}/manifest.json"
    staging_root = request.run_dir / "staging" / f"T20-{query_id}"
    reset_staging_directory(request.run_dir, staging_root)
    pcap_path = request.run_dir / "source" / "capture.pcap"
    tshark_bin = os.environ.get("ANALYSER_TSHARK_BIN") or shutil.which("tshark")
    if not pcap_path.exists():
        raise FileNotFoundError("retained source PCAP not found")
    if not tshark_bin:
        raise FileNotFoundError("tshark is not available")
    requested_selection = request.selection.model_copy(deep=True, update={"frame_start": frame_start, "frame_end": frame_end, "explicit_frames": explicit_frames})
    filter_parts: list[str] = []
    if frame_start is not None and frame_end is not None:
        filter_parts.append(f"(frame.number>={frame_start} && frame.number<={frame_end})")
    elif frame_start is not None:
        filter_parts.append(f"(frame.number>={frame_start})")
    elif frame_end is not None:
        filter_parts.append(f"(frame.number<={frame_end})")
    if explicit_frames:
        filter_parts.append("(" + " || ".join(f"frame.number=={frame}" for frame in explicit_frames) + ")")
    display_filter = " || ".join(filter_parts) if filter_parts else "frame"
    argv = [tshark_bin, "-r", str(pcap_path), "-Y", display_filter, "-T", "json"]
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        stdout, stderr = proc.communicate(timeout=request.timeout_seconds)
    except subprocess.TimeoutExpired:
        _terminate_process_group(proc)
        elapsed_ms = int((datetime.now(tz=timezone.utc) - started).total_seconds() * 1000)
        return TargetedRedecodeResult(
            query_id=query_id,
            status="failed",
            artifact=None,
            manifest=None,
            tshark_version="unknown",
            arguments_redacted=["tshark", "-r", "source/capture.pcap", "-Y", "<frame-filter>", "-T", "json"],
            access_plan=RedecodeAccessPlan(
                mode="full_scan_fallback",
                target_selection=requested_selection,
                context_reason_codes=["tshark_timeout"],
                source_index_revision=request.normalization.revision,
                source_scan_accounting="unknown",
            ),
            record_count=0,
            output_bytes=0,
            elapsed_ms=elapsed_ms,
            warnings=["tshark_timeout"],
        )
    if proc.returncode != 0:
        raise RuntimeError(f"tshark failed with exit code {proc.returncode}: {stderr.decode('utf-8', errors='replace')}")
    payload = json.loads(stdout.decode("utf-8"))
    writer = JsonlArtifactWriter(staging_root, request.run_dir, artifact_relative, "targeted_redecode")
    if not isinstance(payload, list):
        raise ValueError("tshark output must be a JSON array")
    selected_frames = [event.frame for event in selected]
    for item in payload:
        if not isinstance(item, dict):
            continue
        layers = item.get("_source", {}).get("layers", {})
        frame_number = int(str((layers.get("frame") or {}).get("frame.number") or 0))
        if frame_number and frame_number not in selected_frames:
            continue
        if request.output_mode == "fields":
            writer.write({"frame": frame_number, "layers": layers})
        elif request.output_mode == "raw_packet_json":
            writer.write({"frame": frame_number, "raw_packet": item})
        else:
            writer.write({"frame": frame_number, "json_tree": item})
    artifact_closed = writer.close()
    elapsed_ms = int((datetime.now(tz=timezone.utc) - started).total_seconds() * 1000)
    access_plan = RedecodeAccessPlan(
        mode="scan_preslice",
        target_selection=requested_selection,
        context_frame_ranges=[{"frame_start": selected[0].frame, "frame_end": selected[-1].frame}],
        context_reason_codes=["tshark_redecode"],
        source_index_revision=request.normalization.revision,
        source_bytes_scanned=pcap_path.stat().st_size,
        source_packets_scanned=len(payload),
        source_scan_accounting="measured",
        slice_packets=len(payload),
        slice_bytes=artifact_closed.byte_size,
        source_frame_map_checksum=sha256_bytes(compact_json_bytes(selected_frames)),
    )
    manifest_closed = JsonArtifactWriter(staging_root, request.run_dir, manifest_relative, "targeted_redecode_manifest").write(
        {
            "schema_version": SCHEMA_VERSION,
            "tool": "T20",
            "query_id": str(query_id),
            "analysis_id": str(request.analysis_id),
            "source_pcap_sha256": sha256_file(pcap_path),
            "access_plan": access_plan.model_dump(mode="json"),
        }
    )
    publish_closed_artifacts(request.run_dir, [artifact_closed, manifest_closed], manifest_relative_path=manifest_relative)
    artifact_path = request.run_dir / artifact_relative
    manifest_path = request.run_dir / manifest_relative
    return TargetedRedecodeResult(
        query_id=query_id,
        status="success",
        artifact=ArtifactDescriptor(
            artifact_id=str(deterministic_uuid(request.analysis_id, "T20", query_id, "artifact")),
            relative_path=artifact_relative,
            artifact_type="targeted_redecode",
            media_type="application/x-ndjson",
            format_schema_version=SCHEMA_VERSION,
            sha256=sha256_file(artifact_path),
            byte_size=artifact_path.stat().st_size,
            record_count=len(selected),
            creation_stage="T20",
            parent_source_sha256=request.normalization.manifest.sha256,
            revision=f"sha256:{sha256_file(artifact_path)}",
        ),
        manifest=ArtifactDescriptor(
            artifact_id=str(deterministic_uuid(request.analysis_id, "T20", query_id, "manifest")),
            relative_path=manifest_relative,
            artifact_type="targeted_redecode_manifest",
            media_type="application/json",
            format_schema_version=SCHEMA_VERSION,
            sha256=sha256_file(manifest_path),
            byte_size=manifest_path.stat().st_size,
            record_count=1,
            creation_stage="T20",
            parent_source_sha256=request.normalization.manifest.sha256,
            revision=f"sha256:{sha256_file(manifest_path)}",
        ),
        tshark_version="resolved-via-env-or-path",
        arguments_redacted=["tshark", "-r", "source/capture.pcap", "-Y", "<frame-filter>", "-T", "json"],
        access_plan=access_plan,
        record_count=artifact_closed.record_count or 0,
        output_bytes=artifact_path.stat().st_size,
        elapsed_ms=elapsed_ms,
        warnings=[],
    )


def classify_capture_phases(request: ClassifyCapturePhasesRequest) -> ClassifyCapturePhasesResult:
    validate_inside_run(request.run_dir, request.phases_dir)
    attempts = sorted(request.attempts, key=lambda item: (item.start_frame, item.end_frame, str(item.attempt_id)))
    if not attempts:
        relative_dir = "normalized/phases"
        intervals_relative = f"{relative_dir}/capture_phase_intervals.jsonl"
        labels_relative = f"{relative_dir}/primary_event_phase_labels.jsonl"
        manifest_relative = f"{relative_dir}/capture_phase_manifest.json"
        staging_root = request.run_dir / "staging" / f"T21-{request.analysis_id}"
        reset_staging_directory(request.run_dir, staging_root)
        intervals_closed = JsonlArtifactWriter(staging_root, request.run_dir, intervals_relative, "capture_phase_intervals").close()
        labels_closed = JsonlArtifactWriter(staging_root, request.run_dir, labels_relative, "capture_phase_labels").close()
        manifest_closed = JsonArtifactWriter(staging_root, request.run_dir, manifest_relative, "capture_phase_manifest").write(
            {
                "schema_version": SCHEMA_VERSION,
                "tool": "T21",
                "analysis_id": str(request.analysis_id),
                "attempts_revision": request.attempts_revision,
                "interval_count": 0,
                "label_count": 0,
                "status": "unknown",
                "warnings": ["no_attempts"],
            }
        )
        publish_closed_artifacts(
            request.run_dir,
            [intervals_closed, labels_closed, manifest_closed],
            manifest_relative_path=manifest_relative,
        )
        labels_path = request.run_dir / labels_relative
        manifest_path = request.run_dir / manifest_relative
        return ClassifyCapturePhasesResult(
            status="unknown",
            intervals=[],
            primary_event_labels_artifact=ArtifactDescriptor(
                artifact_id=str(deterministic_uuid(request.analysis_id, "T21", "empty")),
                relative_path=labels_relative,
                artifact_type="capture_phase_labels",
                media_type="application/x-ndjson",
                format_schema_version=SCHEMA_VERSION,
                sha256=sha256_file(labels_path),
                byte_size=labels_path.stat().st_size,
                record_count=0,
                creation_stage="T21",
                parent_source_sha256=request.attempts_revision,
                revision=f"sha256:{sha256_file(labels_path)}",
            ),
            manifest=ArtifactDescriptor(
                artifact_id=str(deterministic_uuid(request.analysis_id, "T21", "manifest-empty")),
                relative_path=manifest_relative,
                artifact_type="capture_phase_manifest",
                media_type="application/json",
                format_schema_version=SCHEMA_VERSION,
                sha256=sha256_file(manifest_path),
                byte_size=manifest_path.stat().st_size,
                record_count=1,
                creation_stage="T21",
                parent_source_sha256=request.attempts_revision,
                revision=f"sha256:{sha256_file(manifest_path)}",
            ),
            visibility="unknown",
            warnings=["no_attempts"],
            manifest_path=manifest_path,
        )
    edges = []
    for attempt in attempts:
        start = max(request.capture.first_frame, attempt.start_frame - request.config.default_pre_roll_frames)
        end = min(request.capture.last_frame, attempt.end_frame + request.config.default_post_roll_frames)
        edges.append((start, "start", attempt))
        edges.append((end + 1, "end", attempt))
    edges.sort(key=lambda item: (item[0], 0 if item[1] == "start" else 1, str(item[2].attempt_id)))
    active: dict[UUID, ProcedureAttempt] = {}
    intervals: list[CapturePhaseInterval] = []
    current_frame = request.capture.first_frame
    for frame, edge_type, attempt in edges:
        if current_frame < frame:
            phase = "attempt_active" if active else ("capture_preamble" if not intervals else "between_attempts")
            intervals.append(
                CapturePhaseInterval(
                    interval_id=deterministic_uuid(request.analysis_id, "T21", phase, current_frame, frame - 1, *(str(item) for item in sorted(active))),
                    phase=phase,
                    start_frame=current_frame,
                    end_frame=frame - 1,
                    attempt_ids=sorted(active.keys(), key=str),
                    core_start_frames={str(item.attempt_id): item.start_frame for item in active.values()},
                    core_end_frames={str(item.attempt_id): item.end_frame for item in active.values()},
                    roll_applied={str(item.attempt_id): PhaseRoll(pre_roll_frames=request.config.default_pre_roll_frames, post_roll_frames=request.config.default_post_roll_frames) for item in active.values()},
                    confidence="high" if active else "medium",
                    reason_codes=["phase_sweep"],
                )
            )
        if edge_type == "start":
            active[attempt.attempt_id] = attempt
        else:
            active.pop(attempt.attempt_id, None)
        current_frame = frame
    if current_frame <= request.capture.last_frame:
        phase = "capture_postamble" if intervals else "unknown"
        intervals.append(
            CapturePhaseInterval(
                interval_id=deterministic_uuid(request.analysis_id, "T21", phase, current_frame, request.capture.last_frame),
                phase=phase,
                start_frame=current_frame,
                end_frame=request.capture.last_frame,
                attempt_ids=[],
                confidence="medium",
                reason_codes=["tail_interval"],
            )
        )
    event_labels = []
    for event in request.primary_reader.by_frame(request.capture.first_frame, request.capture.last_frame):
        interval = next(item for item in intervals if item.start_frame <= event.frame <= item.end_frame)
        inside_core = [attempt_id for attempt_id in interval.attempt_ids if any(attempt.attempt_id == attempt_id and attempt.start_frame <= event.frame <= attempt.end_frame for attempt in attempts)]
        event_labels.append(
            CapturePhaseLabel(
                event_id=event.event_id,
                interval_id=interval.interval_id,
                phase=interval.phase,
                active_attempt_ids=interval.attempt_ids,
                inside_core_attempt_ids=inside_core,
                inside_roll_only_attempt_ids=[attempt_id for attempt_id in interval.attempt_ids if attempt_id not in inside_core],
            )
        )
    relative_dir = "normalized/phases"
    labels_relative = f"{relative_dir}/primary_event_phase_labels.jsonl"
    manifest_relative = f"{relative_dir}/capture_phase_manifest.json"
    staging_root = request.run_dir / "staging" / f"T21-{request.analysis_id}"
    reset_staging_directory(request.run_dir, staging_root)
    intervals_writer = JsonlArtifactWriter(staging_root, request.run_dir, f"{relative_dir}/capture_phase_intervals.jsonl", "capture_phase_intervals")
    labels_writer = JsonlArtifactWriter(staging_root, request.run_dir, labels_relative, "capture_phase_labels")
    for interval in intervals:
        intervals_writer.write(interval)
    for label in event_labels:
        labels_writer.write(label)
    intervals_closed = intervals_writer.close()
    labels_closed = labels_writer.close()
    manifest_closed = JsonArtifactWriter(staging_root, request.run_dir, manifest_relative, "capture_phase_manifest").write(
        {
            "schema_version": SCHEMA_VERSION,
            "tool": "T21",
            "analysis_id": str(request.analysis_id),
            "attempts_revision": request.attempts_revision,
            "interval_count": len(intervals),
            "label_count": len(event_labels),
        }
    )
    publish_closed_artifacts(request.run_dir, [intervals_closed, labels_closed, manifest_closed], manifest_relative_path=manifest_relative)
    labels_path = request.run_dir / labels_relative
    manifest_path = request.run_dir / manifest_relative
    return ClassifyCapturePhasesResult(
        status="success",
        intervals=intervals,
        primary_event_labels_artifact=ArtifactDescriptor(
            artifact_id=str(deterministic_uuid(request.analysis_id, "T21", "labels")),
            relative_path=labels_relative,
            artifact_type="capture_phase_labels",
            media_type="application/x-ndjson",
            format_schema_version=SCHEMA_VERSION,
            sha256=sha256_file(labels_path),
            byte_size=labels_path.stat().st_size,
            record_count=len(event_labels),
            creation_stage="T21",
            parent_source_sha256=request.attempts_revision,
            revision=f"sha256:{sha256_file(labels_path)}",
        ),
        manifest=ArtifactDescriptor(
            artifact_id=str(deterministic_uuid(request.analysis_id, "T21", "manifest")),
            relative_path=manifest_relative,
            artifact_type="capture_phase_manifest",
            media_type="application/json",
            format_schema_version=SCHEMA_VERSION,
            sha256=sha256_file(manifest_path),
            byte_size=manifest_path.stat().st_size,
            record_count=1,
            creation_stage="T21",
            parent_source_sha256=request.attempts_revision,
            revision=f"sha256:{sha256_file(manifest_path)}",
        ),
        visibility="anchored",
        warnings=[],
        manifest_path=manifest_path,
    )


def build_nf_lifecycle(request: BuildNFLifecycleRequest) -> BuildNFLifecycleResult:
    selected_entities = []
    entity_id = deterministic_uuid(request.analysis_id, "T22", request.approved_request_id, request.attempt_id)
    selected_entities.append(
        NFEntityRef(
            entity_id=entity_id,
            nf_instance_id=request.selectors.nf_instance_id,
            nf_type=request.selectors.nf_type,
            fqdn=request.selectors.fqdn,
            endpoints=[],
            service_names=[] if request.selectors.service_name is None else [request.selectors.service_name],
            identity_confidence="high" if request.selectors.nf_instance_id else "medium" if request.selectors.service_name else "low",
            identity_evidence_ids=[],
        )
    )
    lifecycles = []
    unresolved = []
    recovered = []
    for event in request.dependency_events:
        status = event.attributes.get("http.status")
        method = event.attributes.get("http.method")
        operation = str(event.attributes.get("http.sbi_api") or event.message_type)
        state_before = "unknown"
        state_after = "available"
        classification: Literal["normal", "failure", "recovery", "benign_startup_cleanup", "discovery_observation", "ambiguous"] = "normal"
        if isinstance(status, int) and status >= 400:
            state_after = "degraded"
            classification = "failure"
            unresolved.append(NFLifecycleFailure(failure_id=deterministic_uuid(request.analysis_id, "T22", "failure", event.event_id), event_id=event.event_id, frame=event.frame, summary=operation))
        elif event.frame < request.attempt_start_frame:
            classification = "discovery_observation"
        lifecycles.append(
            NFLifecycleEvent(
                lifecycle_event_id=deterministic_uuid(request.analysis_id, "T22", "event", event.event_id),
                entity_id=entity_id,
                service_name=request.selectors.service_name,
                frame=event.frame,
                timestamp=event.timestamp,
                operation=operation if method is None else f"{method} {operation}",
                http_status=status if isinstance(status, int) else None,
                state_before=state_before,
                state_after=state_after,
                classification=classification,
                evidence_ids=[deterministic_uuid(request.analysis_id, "T22", "evidence", event.event_id)],
                rationale_codes=[],
            )
        )
    readiness = NFReadinessSnapshot(
        attempt_id=request.attempt_id,
        frame=request.attempt_start_frame,
        entities=[
            NFEntityReadiness(
                entity_id=entity_id,
                status="not_ready" if unresolved else "ready",
                service_states=[] if request.selectors.service_name is None else [
                    NFServiceState(
                        service_name=request.selectors.service_name,
                        status="unavailable" if unresolved else "available",
                        valid_from_frame=request.frame_start,
                    )
                ],
            )
        ],
        required_service=request.selectors.service_name,
        available_candidates=[] if unresolved else [entity_id],
        unresolved_failure_ids=[item.failure_id for item in unresolved],
        status="not_ready" if unresolved else "ready",
    )
    return BuildNFLifecycleResult(
        approved_request_id=request.approved_request_id,
        attempt_id=request.attempt_id,
        selected_entities=selected_entities,
        lifecycles=lifecycles,
        readiness_snapshot=readiness,
        unresolved_failures=unresolved,
        recovered_failures=recovered,
        ambiguous_events=[],
        warnings=[],
    )


def assess_background_impact(request: AssessBackgroundImpactRequest) -> AssessBackgroundImpactResult:
    primary_events = [item for item in request.dependency_events]
    promotion_conditions = []
    demotion_conditions = []
    contradictions = []
    decision_trace = []
    impact: Literal["causal", "contributing", "unrelated", "inconclusive"] = "inconclusive"
    confidence: Literal["high", "medium", "low", "inconclusive"] = "inconclusive"
    if not primary_events:
        decision_trace.append(ImpactDecisionStep(order=1, gate="input_eligibility", result="fail", reason_codes=["no_dependency_events"], terminal_impact="inconclusive"))
    else:
        decision_trace.append(ImpactDecisionStep(order=1, gate="input_eligibility", result="pass", reason_codes=["dependency_events_present"]))
        if request.lifecycle is not None and request.lifecycle.readiness_snapshot.status == "not_ready":
            promotion_conditions.append("dependency_not_ready_at_attempt_start")
            decision_trace.append(ImpactDecisionStep(order=2, gate="requirement_mapping", result="pass", reason_codes=["readiness_not_ready"]))
            if request.attempt.outcome != "succeeded":
                impact = "causal"
                confidence = "medium"
            else:
                impact = "unrelated"
                confidence = "high"
        else:
            demotion_conditions.append("no_readiness_failure")
            impact = "unrelated" if request.attempt.outcome == "succeeded" else "inconclusive"
            confidence = "low" if impact == "inconclusive" else "high"
    causal_path = []
    if primary_events and request.initial_symptom_evidence_ids:
        causal_path.append(
            CausalLink(
                from_evidence_id=primary_events[0].evidence_ids[0] if primary_events[0].evidence_ids else request.initial_symptom_evidence_ids[0],
                to_evidence_id=request.initial_symptom_evidence_ids[0],
                relation="PRECEDES_STAGE_FAILURE",
                strength="strong" if impact in {"causal", "contributing"} else "supporting",
                rationale="dependency event precedes symptom",
            )
        )
    return AssessBackgroundImpactResult(
        impact_id=deterministic_uuid(request.analysis_id, "T23", request.approved_request_id, request.attempt.attempt_id, request.dependency_type),
        approved_request_id=request.approved_request_id,
        attempt_id=request.attempt.attempt_id,
        call_impact=impact,
        primary_dependency_event_ids=[item.event_id for item in primary_events[:1]],
        supporting_event_ids=[item.event_id for item in primary_events[1:]],
        recovery_frame=None,
        causal_path=causal_path,
        promotion_conditions=promotion_conditions,
        demotion_conditions=demotion_conditions,
        contradictions=contradictions,
        missing_evidence=[],
        counterfactual_supported=True if impact == "causal" else None,
        decision_trace=decision_trace,
        confidence=confidence,
    )


def inspect_nrf_flow(request: InspectNRFFlowRequest) -> NRFInspectionResult:
    events = [
        event
        for event in _load_all_events(request.normalization)
        if event.partition == "nrf" and request.frame_start <= event.frame <= request.frame_end
    ]
    transactions = []
    summaries = []
    failed_events: list[CanonicalEvent] = []
    for event in events:
        status = event.attributes.get("http.status") if isinstance(event.attributes.get("http.status"), int) else None
        completion_state = str(event.attributes.get("http.completion_state") or "unknown")
        if (status is not None and status >= 400) or completion_state != "complete":
            failed_events.append(event)
        transactions.append(
            NRFTransactionEvidence(
                transaction_id=deterministic_uuid(request.analysis_id, "T24", "transaction", event.event_id),
                operation=str(event.attributes.get("http.sbi_api") or event.message_type),
                request_frame=event.frame,
                response_frame=event.frame,
                method=event.attributes.get("http.method"),
                uri_template=event.attributes.get("http.path"),
                status=status,
                nf_instance_id=request.nf_instance_id,
                nf_type=request.nf_type,
                service_names=[] if request.service_name is None else [request.service_name],
                consumer_nf=request.consumer_nf,
                completion_state=completion_state,
                phase="unknown",
                problem_cause=None,
                evidence_ids=[deterministic_uuid(request.analysis_id, "T24", "evidence", event.event_id)],
            )
        )
        summaries.append(DependencyEventSummary(event_id=event.event_id, frame=event.frame, protocol=event.protocol, summary=event.message_type, evidence_ids=[deterministic_uuid(request.analysis_id, "T24", "evidence", event.event_id)]))
    lifecycle = build_nf_lifecycle(
        BuildNFLifecycleRequest(
            analysis_id=request.analysis_id,
            approved_request_id=request.request_id,
            attempt_id=request.attempt_id,
            frame_start=request.frame_start,
            frame_end=request.frame_end,
            attempt_start_frame=request.frame_start,
            selectors=NRFSelectors(
                nf_instance_id=request.nf_instance_id,
                nf_type=request.nf_type,
                service_name=request.service_name,
                fqdn=request.fqdn,
                consumer_nf=request.consumer_nf,
            ),
            dependency_events=events,
        )
    ) if events else None
    impact = None
    if events:
        call_impact: Literal["causal", "contributing", "unrelated", "inconclusive"] = "contributing" if failed_events else "unrelated"
        impact = AssessBackgroundImpactResult(
            impact_id=deterministic_uuid(request.analysis_id, "T23", request.request_id, request.attempt_id, "NRF"),
            approved_request_id=request.request_id,
            attempt_id=request.attempt_id,
            call_impact=call_impact,
            primary_dependency_event_ids=[] if not failed_events else [failed_events[0].event_id],
            supporting_event_ids=[event.event_id for event in failed_events[1:]],
            recovery_frame=None,
            causal_path=[],
            promotion_conditions=["dependency_http_failure_visible"] if failed_events else [],
            demotion_conditions=[] if failed_events else ["no_dependency_failure_evidence"],
            contradictions=[],
            missing_evidence=[],
            counterfactual_supported=True if failed_events else None,
            decision_trace=[
                ImpactDecisionStep(
                    order=1,
                    gate="failure_evidence",
                    result="pass" if failed_events else "fail",
                    reason_codes=["dependency_failure_evidence_present"] if failed_events else ["no_dependency_failure_evidence"],
                    terminal_impact=call_impact,
                )
            ],
            confidence="medium" if failed_events else "high",
        )
    candidates = []
    if failed_events and impact is not None and impact.call_impact in {"causal", "contributing"}:
        event = failed_events[0]
        candidates.append(
            FailureCandidate(
                candidate_id=deterministic_uuid(request.analysis_id, "T24", request.request_id, event.event_id),
                attempt_id=request.attempt_id,
                source_event_ids=[event.event_id],
                protocol="HTTP2",
                category="nrf_dependency_failure",
                severity="error",
                frame=event.frame,
                summary=f"NRF inspection observed {event.message_type}",
                observed={"status": event.attributes.get("http.status"), "path": event.attributes.get("http.path")},
                explicit=True,
                evidence_ids=[deterministic_uuid(request.analysis_id, "T24", "candidate_evidence", event.event_id)],
                detector="T24",
                detector_score=Decimal("0.75"),
                score_terms=[ScoreTerm(kind="base", rationale_code="nrf_dependency_observed", value=Decimal("0.75"))],
                capture_phase="unknown",
                relevance="dependency_related",
                call_impact=impact.call_impact,
            )
        )
    revision = "sha256:" + sha256_bytes(compact_json_bytes({"tool": "T24", "request_id": str(request.request_id), "event_ids": [str(event.event_id) for event in events]}))
    return NRFInspectionResult(
        request_id=request.request_id,
        analysis_id=request.analysis_id,
        initial_packet_id=request.initial_packet_id,
        attempt_id=request.attempt_id,
        status="empty" if not events else "completed",
        effective_window=FrameWindow(frame_start=request.frame_start, frame_end=request.frame_end),
        expansion_decisions=[],
        selected_entities=[] if lifecycle is None else lifecycle.selected_entities,
        transactions=transactions,
        lifecycle=lifecycle,
        discovery_chain=[],
        impact=impact,
        failure_candidates=candidates,
        full_evidence_refs=[item.evidence_ids[0] for item in summaries if item.evidence_ids],
        warnings=[],
        revision=revision,
    )


def inspect_udr_flow(request: InspectUDRFlowRequest) -> UDRInspectionResult:
    events = [
        event
        for event in _load_all_events(request.normalization)
        if event.partition == "udr" and request.frame_start <= event.frame <= request.frame_end
    ]
    transactions = []
    summaries = []
    failed_events: list[CanonicalEvent] = []
    for event in events:
        status = event.attributes.get("http.status") if isinstance(event.attributes.get("http.status"), int) else None
        completion_state = str(event.attributes.get("http.completion_state") or "unknown")
        if (status is not None and status >= 400) or completion_state != "complete":
            failed_events.append(event)
        transactions.append(
            UDRTransactionEvidence(
                transaction_id=deterministic_uuid(request.analysis_id, "T25", "transaction", event.event_id),
                consumer_nf=request.consumer_nf,
                operation=str(event.attributes.get("http.sbi_api") or event.message_type),
                data_category="subscription_data",
                request_frame=event.frame,
                response_frame=event.frame,
                method=event.attributes.get("http.method"),
                uri_template=event.attributes.get("http.path"),
                status=status,
                completion_state=completion_state,
                masked_correlation_key=request.masked_correlation_key,
                phase="unknown",
                response_structure=UDRResponseStructureSummary(top_level_keys=sorted((event.attributes.get("http.response_body") or {}).keys()) if isinstance(event.attributes.get("http.response_body"), dict) else []),
                evidence_ids=[deterministic_uuid(request.analysis_id, "T25", "evidence", event.event_id)],
            )
        )
        summaries.append(DependencyEventSummary(event_id=event.event_id, frame=event.frame, protocol=event.protocol, summary=event.message_type, evidence_ids=[deterministic_uuid(request.analysis_id, "T25", "evidence", event.event_id)]))
    impact = None
    if events:
        call_impact: Literal["causal", "contributing", "unrelated", "inconclusive"] = "contributing" if failed_events else "unrelated"
        impact = AssessBackgroundImpactResult(
            impact_id=deterministic_uuid(request.analysis_id, "T23", request.request_id, request.attempt_id, "UDR"),
            approved_request_id=request.request_id,
            attempt_id=request.attempt_id,
            call_impact=call_impact,
            primary_dependency_event_ids=[] if not failed_events else [failed_events[0].event_id],
            supporting_event_ids=[event.event_id for event in failed_events[1:]],
            recovery_frame=None,
            causal_path=[],
            promotion_conditions=["dependency_http_failure_visible"] if failed_events else [],
            demotion_conditions=[] if failed_events else ["no_dependency_failure_evidence"],
            contradictions=[],
            missing_evidence=[],
            counterfactual_supported=True if failed_events else None,
            decision_trace=[
                ImpactDecisionStep(
                    order=1,
                    gate="failure_evidence",
                    result="pass" if failed_events else "fail",
                    reason_codes=["dependency_failure_evidence_present"] if failed_events else ["no_dependency_failure_evidence"],
                    terminal_impact=call_impact,
                )
            ],
            confidence="medium" if failed_events else "high",
        )
    candidates = []
    if failed_events and impact is not None and impact.call_impact in {"causal", "contributing"}:
        event = failed_events[0]
        candidates.append(
            FailureCandidate(
                candidate_id=deterministic_uuid(request.analysis_id, "T25", request.request_id, event.event_id),
                attempt_id=request.attempt_id,
                source_event_ids=[event.event_id],
                protocol="HTTP2",
                category="udr_dependency_failure",
                severity="error",
                frame=event.frame,
                summary=f"UDR inspection observed {event.message_type}",
                observed={"status": event.attributes.get("http.status"), "path": event.attributes.get("http.path")},
                explicit=True,
                evidence_ids=[deterministic_uuid(request.analysis_id, "T25", "candidate_evidence", event.event_id)],
                detector="T25",
                detector_score=Decimal("0.74"),
                score_terms=[ScoreTerm(kind="base", rationale_code="udr_dependency_observed", value=Decimal("0.74"))],
                capture_phase="unknown",
                relevance="dependency_related",
                call_impact=impact.call_impact,
            )
        )
    revision = "sha256:" + sha256_bytes(compact_json_bytes({"tool": "T25", "request_id": str(request.request_id), "event_ids": [str(event.event_id) for event in events]}))
    return UDRInspectionResult(
        request_id=request.request_id,
        analysis_id=request.analysis_id,
        initial_packet_id=request.initial_packet_id,
        attempt_id=request.attempt_id,
        status="empty" if not events else "completed",
        effective_window=FrameWindow(frame_start=request.frame_start, frame_end=request.frame_end),
        transactions=transactions,
        retry_summary=UDRRetrySummary(),
        consumer_chain=[],
        baseline=None,
        impact=impact,
        failure_candidates=candidates,
        full_evidence_refs=[item.evidence_ids[0] for item in summaries if item.evidence_ids],
        warnings=[],
        revision=revision,
    )


def _derive_stage_statuses(state: AnalysisState) -> dict[str, str]:
    statuses = dict(state.stage_statuses)
    inferred = {
        "T04": "success" if state.attempts else "not_run",
        "T05": "success" if state.request_results else "not_run",
        "T10": "success" if state.timelines else "not_run",
        "T11": "success" if state.comparisons else "not_run",
        "T12": "success" if state.root_cause_results else "not_run",
        "T14": "not_run" if state.scenario_validation is None else state.scenario_validation.overall_status,
        "T16": "not_run" if not state.diagnoses else _aggregate_status(item.status for item in state.diagnoses),
        "T24/T25": "not_run" if not state.dependency_results else _aggregate_status(getattr(item, "status", "unknown") for item in state.dependency_results),
    }
    for tool, status in inferred.items():
        statuses.setdefault(tool, status)
    return dict(sorted(statuses.items(), key=lambda item: _tool_sort_key(item[0])))


def _aggregate_status(statuses: Iterable[str]) -> str:
    values = list(statuses)
    if not values:
        return "not_run"
    if any(value == "failed" for value in values):
        return "failed"
    if any(value in {"partial", "inconclusive", "unknown"} for value in values):
        return "partial"
    if all(value == "disabled" for value in values):
        return "disabled"
    if all(value == "empty" for value in values):
        return "empty"
    return "success"


def _tool_sort_key(tool: str) -> tuple[int, str]:
    digits = "".join(character for character in tool if character.isdigit())
    return (int(digits or 999), tool)


def _derive_report_status(
    state: AnalysisState,
    stage_statuses: dict[str, str],
    integrity_status: str,
) -> Literal["success", "partial", "failed"]:
    critical_failures = {
        tool for tool, status in stage_statuses.items()
        if status == "failed" and tool in {"T01", "T02", "T03", "T04", "T17"}
    }
    if critical_failures:
        return "failed"
    if integrity_status != "ok":
        return "partial"
    if state.publication_warnings:
        return "partial"
    if not state.attempts:
        return "partial"
    if any(status in {"failed", "partial", "inconclusive", "unknown"} for status in stage_statuses.values()):
        return "partial"
    return "success"


def _derive_report_warnings(
    state: AnalysisState,
    stage_statuses: dict[str, str],
) -> list[ReportWarning]:
    warnings: list[ReportWarning] = []
    if not state.attempts:
        warnings.append(ReportWarning(code="no_attempts", severity="warning", stage="T17", message="No procedure attempts were available for reporting."))
    for tool, status in stage_statuses.items():
        if status in {"failed", "partial", "inconclusive", "unknown"}:
            warnings.append(ReportWarning(code=f"{tool.lower()}_{status}", severity="error" if status == "failed" else "warning", stage=tool, message=f"{tool} completed with status {status}."))
    for warning in state.publication_warnings:
        warnings.append(ReportWarning(code="publication_warning", severity="warning", stage="T17", message=warning))
    return warnings


def _report_evidence_for_attempt(root: RootCauseResult | None) -> list[ReportEvidenceRef]:
    if root is None:
        return []
    refs: dict[UUID, ReportEvidenceRef] = {}
    for candidate in root.candidate_records:
        for evidence_id in candidate.evidence_ids:
            refs.setdefault(
                evidence_id,
                ReportEvidenceRef(
                    evidence_id=evidence_id,
                    event_ids=list(candidate.source_event_ids),
                    frames=[candidate.frame],
                    protocol=candidate.protocol,
                    summary=candidate.summary,
                    source_available=bool(candidate.source_event_ids),
                ),
            )
    return [refs[evidence_id] for evidence_id in sorted(refs, key=str)]


def _provider_report(diagnoses: list[GenerateDiagnosisResult]) -> ProviderReport | None:
    if not diagnoses:
        return None
    providers = [item.provider for item in diagnoses if item.provider is not None]
    mode = providers[0].mode if providers else "none"
    model = providers[0].model if providers else None
    return ProviderReport(mode=mode, model=model, status=_aggregate_status(item.status for item in diagnoses))


def _report_generated_at(capture: dict[str, Any]) -> datetime:
    value = capture.get("completed_at") or capture.get("generated_at")
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime(1970, 1, 1, tzinfo=timezone.utc)


def render_report(request: RenderReportRequest) -> RenderReportResult:
    state = request.analysis_state
    validate_inside_run(state.run_dir, state.report_dir)
    root_map = {item.attempt_id: item for item in state.root_cause_results}
    request_map = {item.attempt_id: item for item in state.request_results}
    timeline_map = {item.attempt_id: item for item in state.timelines}
    comparison_map = {item.failed_attempt_id: item for item in state.comparisons}
    diagnosis_map = {item.attempt_id: item for item in state.diagnoses}
    ue_results = []
    for attempt in state.attempts:
        root = root_map.get(attempt.attempt_id)
        req = request_map.get(attempt.attempt_id)
        timeline = timeline_map.get(attempt.attempt_id)
        comparison = comparison_map.get(attempt.attempt_id)
        diagnosis = diagnosis_map.get(attempt.attempt_id)
        evidence = _report_evidence_for_attempt(root)
        primary_candidate = _candidate_by_id(root, root.primary_candidate_id) if root is not None else None
        ue_results.append(
            UEResult(
                attempt_id=attempt.attempt_id,
                procedure=attempt.procedure_type,
                outcome=attempt.outcome,
                completion_reason=attempt.completion_reason,
                profile_alternatives=[
                    alternative.model_dump(mode="json")
                    for alternative in attempt.profile_alternatives
                ],
                ue_request={} if req is None else {name: field.value for name, field in req.fields.items() if field.value is not None},
                root_cause={} if root is None else {
                    "primary_candidate_id": None if root.primary_candidate_id is None else str(root.primary_candidate_id),
                    "primary_summary": None if primary_candidate is None else primary_candidate.summary,
                    "candidate_summaries": [
                        {"candidate_id": str(candidate.candidate_id), "summary": candidate.summary}
                        for candidate in root.candidate_records
                    ],
                    "confidence": root.confidence,
                    "rationale_codes": root.rationale_codes,
                    "limitations": root.limitations,
                    "alternatives": [str(item) for item in root.alternative_candidate_ids],
                    "ranking_revision": root.ranking_revision,
                },
                timeline=[] if timeline is None else [
                    {"frame": item.frame, "label": item.label, "message": item.message}
                    for item in timeline.items[:10]
                ],
                comparison=None if comparison is None or not comparison.comparisons else {
                    "selected_baseline_id": None if comparison.selected_baseline_id is None else str(comparison.selected_baseline_id),
                    "first_divergence": None if comparison.comparisons[0].first_divergence is None else comparison.comparisons[0].first_divergence.stage_id,
                },
                scenario=[] if state.scenario_validation is None else [
                    checkpoint.model_dump(mode="json", exclude_none=True)
                    for checkpoint in state.scenario_validation.checkpoints
                    if checkpoint.attempt_id == attempt.attempt_id
                ],
                dependency_inspections=[
                    {
                        "tool": result.__class__.__name__,
                        "status": getattr(result, "status", "unknown"),
                    }
                    for result in state.dependency_results
                    if getattr(result, "attempt_id", None) == attempt.attempt_id
                ],
                model_diagnosis=None if diagnosis is None or diagnosis.diagnosis is None else diagnosis.diagnosis.model_dump(mode="json", exclude_none=True),
                model_narration="skipped_by_policy" if diagnosis is None or diagnosis.status == "disabled" else None,
                evidence=evidence,
            )
        )
    stage_statuses = _derive_stage_statuses(state)
    report_warnings = _derive_report_warnings(state, stage_statuses)
    integrity_warnings = list(dict.fromkeys([
        *state.evidence_integrity_warnings,
        *[
            "unresolvable_evidence_reference"
            for result in ue_results
            for evidence_ref in result.evidence
            if not evidence_ref.source_available
        ],
    ]))
    integrity_status = "ok" if not integrity_warnings else "degraded"
    status = _derive_report_status(state, stage_statuses, integrity_status)
    invoked_tools = sorted(
        (tool for tool, stage_status in stage_statuses.items() if stage_status != "not_run"),
        key=_tool_sort_key,
    )
    report = AnalysisReport(
        analysis_id=request.analysis_id,
        status=status,
        generated_at=state.generated_at or _report_generated_at(state.capture),
        capture=CaptureReport(source_sha256=str(state.capture.get("source_sha256", "unknown")), packet_count=state.capture.get("packet_count")),
        pipeline=PipelineReport(
            implemented_tools=invoked_tools,
            invoked_tools=invoked_tools,
            stage_statuses=stage_statuses,
            revisions=dict(sorted(state.stage_revisions.items())),
        ),
        ue_results=ue_results,
        scenario=None if state.scenario_validation is None else ScenarioReport(
            overall_status=state.scenario_validation.overall_status,
            selected_attempt_ids=state.scenario_validation.selected_attempt_ids,
        ),
        dependency_inspections=[
            DependencyInspectionReport(
                tool=result.__class__.__name__,
                request_id=getattr(result, "request_id"),
                status=getattr(result, "status"),
                summary=f"{result.__class__.__name__}:{getattr(result, 'status')}",
            )
            for result in state.dependency_results
        ],
        provider=_provider_report(state.diagnoses),
        warnings=report_warnings,
        timings=dict(sorted(state.timings_ms.items())),
        evidence_integrity=EvidenceIntegrityReport(status=integrity_status, warnings=integrity_warnings),
    )
    relative_dir = "report"
    json_relative = f"{relative_dir}/report.json"
    md_relative = f"{relative_dir}/report.md"
    manifest_relative = f"{relative_dir}/report_manifest.json"
    staging_root = state.run_dir / "staging" / f"T17-{request.analysis_id}"
    reset_staging_directory(state.run_dir, staging_root)
    json_closed = JsonArtifactWriter(staging_root, state.run_dir, json_relative, "analysis_report").write(report)
    markdown = _render_report_markdown(report)
    md_path = staging_root / md_relative
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(markdown, encoding="utf-8")
    md_closed = _closed_text_artifact(md_relative, "analysis_report_markdown", md_path)
    manifest_closed = JsonArtifactWriter(staging_root, state.run_dir, manifest_relative, "analysis_report_manifest").write(
        {
            "schema_version": SCHEMA_VERSION,
            "tool": "T17",
            "analysis_id": str(request.analysis_id),
            "status": status,
            "json": json_relative,
            "markdown": md_relative,
        }
    )
    publish_closed_artifacts(state.run_dir, [json_closed, md_closed, manifest_closed], manifest_relative_path=manifest_relative)
    json_path = state.run_dir / json_relative
    md_final_path = state.run_dir / md_relative
    manifest_path = state.run_dir / manifest_relative
    return RenderReportResult(
        analysis_id=request.analysis_id,
        status=status,
        report_json=ArtifactDescriptor(
            artifact_id=str(deterministic_uuid(request.analysis_id, "T17", "json")),
            relative_path=json_relative,
            artifact_type="analysis_report",
            media_type="application/json",
            format_schema_version=SCHEMA_VERSION,
            sha256=sha256_file(json_path),
            byte_size=json_path.stat().st_size,
            record_count=1,
            creation_stage="T17",
            parent_source_sha256=None,
            revision=f"sha256:{sha256_file(json_path)}",
        ),
        report_markdown=ArtifactDescriptor(
            artifact_id=str(deterministic_uuid(request.analysis_id, "T17", "markdown")),
            relative_path=md_relative,
            artifact_type="analysis_report_markdown",
            media_type="text/markdown",
            format_schema_version=SCHEMA_VERSION,
            sha256=sha256_file(md_final_path),
            byte_size=md_final_path.stat().st_size,
            record_count=1,
            creation_stage="T17",
            parent_source_sha256=None,
            revision=f"sha256:{sha256_file(md_final_path)}",
        ),
        report_manifest=ArtifactDescriptor(
            artifact_id=str(deterministic_uuid(request.analysis_id, "T17", "manifest")),
            relative_path=manifest_relative,
            artifact_type="analysis_report_manifest",
            media_type="application/json",
            format_schema_version=SCHEMA_VERSION,
            sha256=sha256_file(manifest_path),
            byte_size=manifest_path.stat().st_size,
            record_count=1,
            creation_stage="T17",
            parent_source_sha256=None,
            revision=f"sha256:{sha256_file(manifest_path)}",
        ),
        warnings=[warning.code for warning in report_warnings],
        manifest_path=manifest_path,
    )


def _request_similarity(failed: UERequestResult, baseline: UERequestResult) -> Decimal:
    fields = sorted(set(failed.fields) | set(baseline.fields))
    if not fields:
        return Decimal("1.0")
    matches = 0
    total = 0
    for name in fields:
        failed_value = failed.fields.get(name).value if failed.fields.get(name) else None
        baseline_value = baseline.fields.get(name).value if baseline.fields.get(name) else None
        if failed_value is None and baseline_value is None:
            continue
        total += 1
        if failed_value == baseline_value:
            matches += 1
    if total == 0:
        return Decimal("1.0")
    return Decimal(matches) / Decimal(total)


def _request_differences(failed: UERequestResult, baseline: UERequestResult | None) -> list[FieldDifference]:
    if baseline is None:
        return []
    differences = []
    for name in sorted(set(failed.fields) | set(baseline.fields)):
        failed_value = failed.fields.get(name).value if failed.fields.get(name) else None
        baseline_value = baseline.fields.get(name).value if baseline.fields.get(name) else None
        if failed_value != baseline_value:
            differences.append(FieldDifference(field_name=name, failed_value=failed_value, baseline_value=baseline_value, category="request_changed"))
    return differences


def _align_stages(failed: ProcedureAttempt, baseline: ProcedureAttempt) -> tuple[list[StageAlignment], AttemptDivergence | None]:
    failed_stages = sorted(failed.stage_timings, key=lambda item: (item.first_frame, item.last_frame, str(item.stage_timing_id)))
    baseline_stages = sorted(baseline.stage_timings, key=lambda item: (item.first_frame, item.last_frame, str(item.stage_timing_id)))
    failed_by_key = _stage_occurrences(failed_stages)
    baseline_by_key = _stage_occurrences(baseline_stages)
    keys = set(failed_by_key) | set(baseline_by_key)
    ordered_keys = sorted(
        keys,
        key=lambda key: (
            min(
                failed_by_key[key].first_frame if key in failed_by_key else 2**63,
                baseline_by_key[key].first_frame if key in baseline_by_key else 2**63,
            ),
            key[1],
            key[0],
        ),
    )
    alignment: list[StageAlignment] = []
    for stage_id, occurrence in ordered_keys:
        failed_stage = failed_by_key.get((stage_id, occurrence))
        baseline_stage = baseline_by_key.get((stage_id, occurrence))
        if failed_stage is not None and baseline_stage is not None:
            relation = "matched" if failed_stage.status == baseline_stage.status else "changed"
            failed_status = failed_stage.status
            baseline_status = baseline_stage.status
        elif failed_stage is not None:
            relation = "extra_in_failed"
            failed_status = failed_stage.status
            baseline_status = "missing"
        else:
            relation = "missing_in_failed"
            failed_status = "missing"
            baseline_status = baseline_stage.status
        alignment.append(
            StageAlignment(
                stage_id=stage_id,
                occurrence=occurrence,
                failed_status=failed_status,
                baseline_status=baseline_status,
                relation=relation,
                failed_evidence_ids=[] if failed_stage is None else [deterministic_uuid(failed.attempt_id, "T11", "failed_stage", failed_stage.stage_timing_id)],
                baseline_evidence_ids=[] if baseline_stage is None else [deterministic_uuid(baseline.attempt_id, "T11", "baseline_stage", baseline_stage.stage_timing_id)],
            )
        )
    first_alignment = next((item for item in alignment if item.relation != "matched"), None)
    return alignment, None if first_alignment is None else _alignment_divergence(failed, baseline, first_alignment)


def _stage_occurrences(stages: list[Any]) -> dict[tuple[str, int], Any]:
    counts: DefaultDict[str, int] = defaultdict(int)
    indexed: dict[tuple[str, int], Any] = {}
    for stage in stages:
        counts[stage.stage_id] += 1
        indexed[(stage.stage_id, counts[stage.stage_id])] = stage
    return indexed


def _alignment_divergence(
    failed: ProcedureAttempt,
    baseline: ProcedureAttempt,
    alignment: StageAlignment,
) -> AttemptDivergence:
    return AttemptDivergence(
        divergence_id=deterministic_uuid(
            failed.attempt_id,
            "T11",
            "divergence",
            alignment.stage_id,
            alignment.occurrence,
            baseline.attempt_id,
        ),
        stage_id=alignment.stage_id,
        category=alignment.relation,
        failed_value=alignment.failed_status,
        baseline_value=alignment.baseline_status,
        failed_evidence_ids=alignment.failed_evidence_ids,
        baseline_evidence_ids=alignment.baseline_evidence_ids,
        causal_relevance="strong",
        rationale="first_semantic_stage_divergence" if alignment.occurrence == 1 else "repeated_stage_divergence",
    )


def _candidate_by_id(root: RootCauseResult, candidate_id: UUID | None) -> FailureCandidate | None:
    if candidate_id is None:
        return None
    for candidate in root.candidate_records:
        if candidate.candidate_id == candidate_id:
            return candidate
    return None


def _comparison_evidence(comparison: CompareAttemptsResult | None) -> AttemptComparisonEvidence | None:
    if comparison is None or not comparison.comparisons:
        return None
    selected = comparison.comparisons[0]
    return AttemptComparisonEvidence(
        baseline_attempt_id=selected.baseline_attempt_id,
        first_divergence_stage_id=None if selected.first_divergence is None else selected.first_divergence.stage_id,
        summary="selected_baseline_comparison",
    )


def _scenario_evidence(validation: ValidateScenarioResult | None) -> list[CheckpointEvidence]:
    if validation is None:
        return []
    return [
        CheckpointEvidence(
            checkpoint_id=item.checkpoint_id,
            status=item.status,
            expected=item.expected,
            observed=item.observed,
            evidence_ids=item.evidence_ids,
        )
        for item in validation.checkpoints
    ]


def _packet_evidence_from_request(request_result: UERequestResult) -> list[PacketEvidenceRecord]:
    records = []
    for field in request_result.fields.values():
        if field.value is None:
            continue
        records.append(
            PacketEvidenceRecord(
                evidence_id=field.evidence_ids[0] if field.evidence_ids else deterministic_uuid(request_result.analysis_id, "T15", "field", request_result.attempt_id, field.name),
                source_event_ids=list(field.source_event_ids),
                frames=list(field.source_frames),
                protocol="REQUEST",
                record_type="request_field",
                observed={"name": field.name, "value": field.value},
                source_refs=[ref.model_dump(mode="json", exclude_none=True) for ref in field.raw_refs],
                exact=True,
                masked=request_result.ue is not None,
            )
        )
    return records


def _count_tokens(counter: TokenCounterSpec, value: Any) -> int:
    payload = compact_json_bytes(value)
    if counter.method in {"utf8_bytes_v1", "pinned_tokenizer"}:
        return len(payload)
    raise ValueError(f"unsupported token counter method {counter.method}")


def _encode_cursor(tool: str, analysis_id: UUID, revision: str, payload: dict[str, Any]) -> str:
    encoded_payload = compact_json_bytes(payload)
    secret = f"{tool}:{analysis_id}:{revision}".encode("utf-8")
    digest = hmac.new(secret, encoded_payload, hashlib.sha256).hexdigest()
    envelope = {"payload": payload, "digest": digest}
    return base64.urlsafe_b64encode(compact_json_bytes(envelope)).decode("ascii")


def _decode_cursor(tool: str, analysis_id: UUID, revision: str, cursor: str) -> dict[str, Any]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("ascii"))
        envelope = json.loads(raw.decode("utf-8"))
    except Exception as exc:  # pragma: no cover - malformed cursor path
        raise ValueError("invalid pagination cursor") from exc
    payload = envelope.get("payload")
    digest = envelope.get("digest")
    if not isinstance(payload, dict) or not isinstance(digest, str):
        raise ValueError("invalid pagination cursor")
    expected = hmac.new(
        f"{tool}:{analysis_id}:{revision}".encode("utf-8"),
        compact_json_bytes(payload),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(digest, expected):
        raise ValueError("pagination cursor authentication failed")
    return payload


def _build_evidence_registry(
    analysis_id: UUID,
    source_revision: str,
    events: list[CanonicalEvent],
    attempts: list[ProcedureAttempt],
    candidates: list[FailureCandidate],
    request_results: list[UERequestResult],
) -> dict[UUID, EvidenceRegistryEntry]:
    event_by_id = {event.event_id: event for event in events}
    attempts_by_event_id: DefaultDict[UUID, list[UUID]] = defaultdict(list)
    for attempt in attempts:
        for event_id in attempt.event_ids:
            attempts_by_event_id[event_id].append(attempt.attempt_id)
    registry: dict[UUID, EvidenceRegistryEntry] = {}
    for event in events:
        evidence_id = deterministic_uuid(analysis_id, "T18", event.event_id)
        registry[evidence_id] = EvidenceRegistryEntry(
            evidence_id=evidence_id,
            source_revision=source_revision,
            partition=event.partition,
            source_event_ids=[event.event_id],
            attempt_ids=sorted(attempts_by_event_id.get(event.event_id, []), key=str),
            record_id=evidence_id,
            source_refs=list(event.raw_refs),
            checksum_sha256=_registry_checksum(event.raw_refs),
            authorization_tags=[f"partition:{event.partition}", f"protocol:{event.protocol}"],
        )
    for request_result in request_results:
        for field in request_result.fields.values():
            for evidence_id in field.evidence_ids:
                source_event_ids = [event_id for event_id in field.source_event_ids if event_id in event_by_id]
                _merge_registry_entry(
                    registry,
                    EvidenceRegistryEntry(
                        evidence_id=evidence_id,
                        source_revision=source_revision,
                        partition=_registry_partition(source_event_ids, event_by_id),
                        source_event_ids=source_event_ids,
                        attempt_ids=[request_result.attempt_id],
                        source_refs=[ref for event_id in source_event_ids for ref in event_by_id[event_id].raw_refs],
                        checksum_sha256=_registry_checksum([ref for event_id in source_event_ids for ref in event_by_id[event_id].raw_refs]),
                        field_paths=list(field.field_paths),
                        authorization_tags=["kind:request_field"],
                    ),
                )
    for candidate in candidates:
        source_event_ids = [event_id for event_id in candidate.source_event_ids if event_id in event_by_id]
        for evidence_id in candidate.evidence_ids:
            _merge_registry_entry(
                registry,
                EvidenceRegistryEntry(
                    evidence_id=evidence_id,
                    source_revision=source_revision,
                    partition=_registry_partition(source_event_ids, event_by_id),
                    source_event_ids=source_event_ids,
                    attempt_ids=[candidate.attempt_id],
                    candidate_ids=[candidate.candidate_id],
                    source_refs=[ref for event_id in source_event_ids for ref in event_by_id[event_id].raw_refs],
                    checksum_sha256=_registry_checksum([ref for event_id in source_event_ids for ref in event_by_id[event_id].raw_refs]),
                    field_paths=[f"candidate.{candidate.category}"],
                    authorization_tags=[f"detector:{candidate.detector}", f"category:{candidate.category}"],
                ),
            )
    return registry


def _merge_registry_entry(registry: dict[UUID, EvidenceRegistryEntry], entry: EvidenceRegistryEntry) -> None:
    existing = registry.get(entry.evidence_id)
    if existing is None:
        registry[entry.evidence_id] = entry
        return
    registry[entry.evidence_id] = existing.model_copy(
        update={
            "source_event_ids": sorted(set(existing.source_event_ids + entry.source_event_ids), key=str),
            "attempt_ids": sorted(set(existing.attempt_ids + entry.attempt_ids), key=str),
            "candidate_ids": sorted(set(existing.candidate_ids + entry.candidate_ids), key=str),
            "source_refs": existing.source_refs + entry.source_refs,
            "field_paths": sorted(set(existing.field_paths + entry.field_paths)),
            "authorization_tags": sorted(set(existing.authorization_tags + entry.authorization_tags)),
        }
    )


def _registry_partition(source_event_ids: list[UUID], event_by_id: dict[UUID, CanonicalEvent]) -> str:
    partitions = {event_by_id[event_id].partition for event_id in source_event_ids if event_id in event_by_id}
    if not partitions:
        return "unknown"
    if len(partitions) == 1:
        return next(iter(partitions))
    return "mixed"


def _registry_checksum(source_refs: list[SourceRef]) -> str | None:
    checksums = sorted({ref.artifact_sha256 for ref in source_refs if ref.artifact_sha256})
    if not checksums:
        return None
    return "sha256:" + sha256_bytes(compact_json_bytes(checksums))


def _ensure_registry_entry_authorized(
    capability: EvidenceCapability,
    entry: EvidenceRegistryEntry,
    event_by_id: dict[UUID, CanonicalEvent],
    attempts_by_event_id: dict[UUID, list[UUID]],
) -> None:
    for attempt_id in entry.attempt_ids:
        if not _attempt_authorized(capability, attempt_id):
            raise ValueError(f"evidence {entry.evidence_id} is outside capability scope")
    for event_id in entry.source_event_ids:
        event = event_by_id.get(event_id)
        if event is None:
            raise ValueError(f"evidence {entry.evidence_id} references unknown event {event_id}")
        _ensure_authorized_event(capability, event, attempt_ids=attempts_by_event_id.get(event_id, []))


def _raw_content_from_source_refs(normalization: NormalizeEventsResult, source_refs: list[SourceRef]) -> dict[str, Any]:
    root = normalization.manifest_path
    for _ in range(3):
        root = root.parent
    raw_refs = []
    for source_ref in source_refs:
        entry = source_ref.model_dump(mode="json", exclude_none=True)
        source_path = root / source_ref.decoder_file
        if source_ref.byte_offset is not None and source_ref.byte_length is not None and source_path.exists():
            with source_path.open("rb") as handle:
                handle.seek(source_ref.byte_offset)
                payload = handle.read(source_ref.byte_length)
            entry["raw_bytes_b64"] = base64.b64encode(payload).decode("ascii")
            entry["byte_sha256"] = "sha256:" + hashlib.sha256(payload).hexdigest()
        else:
            entry["raw_bytes_unavailable"] = True
        raw_refs.append(entry)
    return {
        "source_revision": normalization.revision,
        "raw_refs": raw_refs,
        "source_artifacts": sorted({ref.decoder_file for ref in source_refs}),
    }


def _capability_attempt_allowlist(capability: EvidenceCapability) -> set[UUID] | None:
    return None if not capability.attempt_ids else set(capability.attempt_ids)


def _validate_capability(
    capability: EvidenceCapability,
    *,
    analysis_id: UUID,
    revision: str,
    detail: str,
) -> None:
    if not capability.holder.strip():
        raise ValueError("evidence capability holder is required")
    if not capability.purpose.strip():
        raise ValueError("evidence capability purpose is required")
    if capability.analysis_id != analysis_id:
        raise ValueError("evidence capability analysis_id mismatch")
    if detail not in capability.allowed_details:
        raise ValueError(f"detail {detail} is not authorized for this capability")
    if capability.frame_start is not None and capability.frame_end is not None and capability.frame_start > capability.frame_end:
        raise ValueError("evidence capability frame_start exceeds frame_end")
    if not revision:
        raise ValueError("evidence revision is required")


def _event_within_capability(capability: EvidenceCapability, event: CanonicalEvent) -> bool:
    if event.partition not in capability.partition_allowlist:
        return False
    if capability.frame_start is not None and event.frame < capability.frame_start:
        return False
    if capability.frame_end is not None and event.frame > capability.frame_end:
        return False
    return True


def _attempt_authorized(capability: EvidenceCapability, attempt_id: UUID | None) -> bool:
    allowlist = _capability_attempt_allowlist(capability)
    if allowlist is None or attempt_id is None:
        return True
    return attempt_id in allowlist


def _ensure_authorized_event(
    capability: EvidenceCapability,
    event: CanonicalEvent,
    *,
    attempt_ids: Iterable[UUID] = (),
) -> None:
    if not _event_within_capability(capability, event):
        raise ValueError(f"event {event.event_id} is outside capability scope")
    if any(not _attempt_authorized(capability, attempt_id) for attempt_id in attempt_ids):
        raise ValueError(f"event {event.event_id} is outside authorized attempts")


def _request_query_digest(payload: dict[str, Any]) -> str:
    return sha256_bytes(compact_json_bytes(payload))


def _paginate_items(
    *,
    tool: str,
    analysis_id: UUID,
    revision: str,
    query_payload: dict[str, Any],
    cursor: str | None,
    items: list[Any],
    page_size_bytes: int,
    max_records: int,
) -> tuple[list[Any], bool, str | None]:
    if page_size_bytes <= 0:
        raise ValueError("page_size_bytes must be positive")
    if max_records <= 0:
        raise ValueError("max_records must be positive")
    expected_digest = _request_query_digest(query_payload)
    start = 0
    if cursor is not None:
        payload = _decode_cursor(tool, analysis_id, revision, cursor)
        if payload.get("query_digest") != expected_digest:
            raise ValueError("pagination cursor query mismatch")
        start = int(payload.get("offset", 0))
    selected: list[Any] = []
    byte_budget = 0
    index = start
    while index < len(items) and len(selected) < max_records:
        item = items[index]
        item_size = len(compact_json_bytes(item))
        if selected and byte_budget + item_size > page_size_bytes:
            break
        if not selected and item_size > page_size_bytes:
            raise ValueError("page_size_bytes is too small for the first authorized record")
        selected.append(item)
        byte_budget += item_size
        index += 1
    truncated = index < len(items)
    next_cursor = None
    if truncated:
        next_cursor = _encode_cursor(
            tool,
            analysis_id,
            revision,
            {"query_digest": expected_digest, "offset": index},
        )
    return selected, truncated, next_cursor


def _trim_evidence_packet(
    packet: EvidencePacket,
    budget: ResolvedTokenBudget,
) -> tuple[EvidencePacket, list[EvidenceTruncation], int]:
    packet = packet.model_copy(deep=True)
    truncations: list[EvidenceTruncation] = []
    cap = min(budget.effective_input_tokens, budget.hard_input_cap)

    def current_count() -> int:
        return _count_tokens(budget.counter, packet)

    token_count = current_count()
    if token_count <= cap:
        return packet, truncations, token_count

    optional_sections: list[tuple[str, str]] = [
        ("dependency_evidence", "tail_trimmed"),
        ("timeline", "tail_trimmed"),
        ("scenario_results", "tail_trimmed"),
        ("downstream_effects", "tail_trimmed"),
        ("alternatives", "tail_trimmed"),
        ("evidence", "tail_trimmed"),
        ("dependency_tools_available", "trimmed"),
    ]
    for field_name, reason in optional_sections:
        value = getattr(packet, field_name)
        if not value:
            continue
        if isinstance(value, list):
            while value and token_count > cap:
                value.pop()
                truncations.append(EvidenceTruncation(section=field_name, reason=reason))
                token_count = current_count()
        else:
            setattr(packet, field_name, [] if isinstance(value, list) else None)
            truncations.append(EvidenceTruncation(section=field_name, reason=reason))
            token_count = current_count()
        if token_count <= cap:
            break
    if token_count > cap:
        raise ValueError("mandatory evidence exceeds configured token budget")
    return packet, truncations, token_count


def _provider_headers(config: ProviderConfig) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if config.api_key_env:
        api_key = os.environ.get(config.api_key_env)
        if not api_key:
            raise ValueError(f"provider api key env {config.api_key_env} is not set")
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


def _local_provider_payload(request: GenerateDiagnosisRequest) -> dict[str, Any]:
    primary = request.packet.primary_failure
    dependency_requests = []
    if request.pass_stage == "initial" and primary is not None:
        dependency_requests = [
            item.model_dump(mode="json", exclude_none=True)
            for item in _deterministic_dependency_requests(request.packet, request.attempt_id)
        ]
    return {
        "schema_version": "2.0",
        "ue_request_summary": f"{request.packet.ue_request.procedure} requested",
        "outcome_summary": f"attempt ended {request.packet.attempt.outcome}",
        "root_cause_summary": "no deterministic primary candidate" if primary is None else primary.summary,
        "primary_candidate_id": None if primary is None else str(primary.candidate_id),
        "alternative_candidate_ids": [str(item.candidate_id) for item in request.packet.alternatives],
        "reasoning_steps": [
            {
                "summary": "provider synthesized diagnosis from deterministic packet",
                "candidate_ids": [] if primary is None else [str(primary.candidate_id)],
                "evidence_ids": [] if primary is None else [str(evidence_id) for evidence_id in primary.evidence_ids],
            }
        ],
        "evidence_ids": [] if primary is None else [str(evidence_id) for evidence_id in primary.evidence_ids],
        "confidence": "inconclusive" if primary is None else "medium",
        "limitations": list(request.packet.deterministic_limitations),
        "deterministic_conflicts": [],
        "dependency_evidence_requests": dependency_requests,
    }


def _http_provider_payload(request: GenerateDiagnosisRequest) -> dict[str, Any]:
    return {
        "analysis_id": str(request.analysis_id),
        "attempt_id": str(request.attempt_id),
        "pass_stage": request.pass_stage,
        "packet": request.packet.model_dump(mode="json", exclude_none=True),
    }


def _invoke_provider_transport(request: GenerateDiagnosisRequest) -> tuple[dict[str, Any], ProviderMetadata]:
    config = request.provider_config
    if config.mode == "local" and not config.base_url:
        return _local_provider_payload(request), ProviderMetadata(mode="local", model=config.model, request_id="local-deterministic")
    if not config.base_url:
        raise ValueError("provider base_url is required for remote transport")
    body = compact_json_bytes(_http_provider_payload(request))
    http_request = urllib_request.Request(
        config.base_url,
        data=body,
        headers=_provider_headers(config),
        method="POST",
    )
    with urllib_request.urlopen(http_request, timeout=config.timeout_seconds) as response:
        raw = response.read()
        payload = json.loads(raw.decode("utf-8"))
    if isinstance(payload, dict) and "diagnosis" in payload and isinstance(payload["diagnosis"], dict):
        diagnosis_payload = payload["diagnosis"]
        request_id = payload.get("request_id")
    else:
        diagnosis_payload = payload
        request_id = payload.get("request_id") if isinstance(payload, dict) else None
    return diagnosis_payload, ProviderMetadata(mode=config.mode, model=config.model, request_id=None if request_id is None else str(request_id))


def _deterministic_dependency_requests(packet: EvidencePacket, attempt_id: UUID) -> list[DependencyEvidenceRequest]:
    primary = packet.primary_failure
    if primary is None:
        return []
    frame_start = packet.timeline[0].frame if packet.timeline else max(0, primary.frame - 20)
    if primary.protocol == "HTTP2" and primary.category in {"http_status_failure", "http_incomplete", "udr_dependency_failure"}:
        return [
            DependencyEvidenceRequest(
                tool="inspect_udr_flow",
                attempt_id=attempt_id,
                reason_code="SUBSCRIBER_DATA_FAILURE_SUSPECTED",
                rationale="visible control-plane symptom suggests hidden subscriber-data dependency",
                initial_evidence_ids=list(primary.evidence_ids),
                frame_start=frame_start,
                frame_end=primary.frame,
                consumer_nf="UNKNOWN",
                resource_or_operation=primary.category,
            )
        ]
    if primary.protocol in {"HTTP2", "MULTI"} and primary.category in {"missing_transition", "nrf_dependency_failure"}:
        return [
            DependencyEvidenceRequest(
                tool="inspect_nrf_flow",
                attempt_id=attempt_id,
                reason_code="DISCOVERY_FAILURE_SUSPECTED",
                rationale="missing or upstream failure pattern suggests hidden discovery or readiness issue",
                initial_evidence_ids=list(primary.evidence_ids),
                frame_start=frame_start,
                frame_end=primary.frame,
                nf_type="NRF",
                service_name="nnrf-disc",
            )
        ]
    return []


def _validate_provider_diagnosis(
    request: GenerateDiagnosisRequest,
    payload: dict[str, Any],
) -> tuple[ModelDiagnosis, list[ModelValidationError], list[str]]:
    validation_errors: list[ModelValidationError] = []
    warnings: list[str] = []
    diagnosis = ModelDiagnosis.model_validate(payload)
    primary = request.packet.primary_failure
    if primary is not None and diagnosis.primary_candidate_id not in {None, primary.candidate_id}:
        diagnosis.deterministic_conflicts.append(
            ModelDeterministicConflict(
                field_name="primary_candidate_id",
                model_value=diagnosis.primary_candidate_id,
                deterministic_value=primary.candidate_id,
                reason="provider_primary_candidate_disagrees_with_deterministic_root",
            )
        )
    valid_requests: list[DependencyEvidenceRequest] = []
    for dependency_request in diagnosis.dependency_evidence_requests:
        if request.pass_stage == "final":
            warnings.append("final_pass_tool_requests_rejected")
            continue
        if dependency_request.attempt_id != request.attempt_id:
            validation_errors.append(ModelValidationError(field_name="dependency_evidence_requests.attempt_id", reason="attempt_id_mismatch"))
            continue
        if dependency_request.frame_start > dependency_request.frame_end:
            validation_errors.append(ModelValidationError(field_name="dependency_evidence_requests.frame_range", reason="frame_start_exceeds_frame_end"))
            continue
        valid_requests.append(dependency_request)
    diagnosis.dependency_evidence_requests = valid_requests[: request.provider_config.max_total_calls_per_pass]
    return diagnosis, validation_errors, warnings


def _terminate_process_group(proc: subprocess.Popen[bytes], grace_seconds: float = 2.0) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=grace_seconds)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    proc.wait()


def _publish_evidence_packet(analysis_id: UUID, packet: EvidencePacket, run_dir: Path, evidence_dir: Path, counter: TokenCounterSpec) -> BuildEvidencePacketResult:
    relative_dir = f"evidence/packets/{packet.packet_id}"
    artifact_relative = f"{relative_dir}/packet.json"
    manifest_relative = f"{relative_dir}/packet_manifest.json"
    staging_root = run_dir / "staging" / f"T15-{packet.packet_id}"
    reset_staging_directory(run_dir, staging_root)
    trimmed_packet, truncations, token_count = _trim_evidence_packet(packet, packet.token_budget)
    packet_closed = JsonArtifactWriter(staging_root, run_dir, artifact_relative, "evidence_packet").write(trimmed_packet)
    manifest_closed = JsonArtifactWriter(staging_root, run_dir, manifest_relative, "evidence_packet_manifest").write(
        {
            "schema_version": SCHEMA_VERSION,
            "tool": "T15",
            "analysis_id": str(analysis_id),
            "packet_id": str(trimmed_packet.packet_id),
            "pass_stage": trimmed_packet.pass_stage,
            "token_count": token_count,
            "truncations": [item.model_dump(mode="json") for item in truncations],
        }
    )
    publish_closed_artifacts(run_dir, [packet_closed, manifest_closed], manifest_relative_path=manifest_relative)
    artifact_path = run_dir / artifact_relative
    manifest_path = run_dir / manifest_relative
    return BuildEvidencePacketResult(
        packet=trimmed_packet,
        artifact=ArtifactDescriptor(
            artifact_id=str(deterministic_uuid(analysis_id, "T15", trimmed_packet.packet_id, "artifact")),
            relative_path=artifact_relative,
            artifact_type="evidence_packet",
            media_type="application/json",
            format_schema_version=SCHEMA_VERSION,
            sha256=sha256_file(artifact_path),
            byte_size=artifact_path.stat().st_size,
            record_count=1,
            creation_stage="T15",
            parent_source_sha256=None,
            revision=f"sha256:{sha256_file(artifact_path)}",
        ),
        token_count=token_count,
        token_counter=counter,
        truncations=truncations,
        warnings=[],
        manifest=ArtifactDescriptor(
            artifact_id=str(deterministic_uuid(analysis_id, "T15", trimmed_packet.packet_id, "manifest")),
            relative_path=manifest_relative,
            artifact_type="evidence_packet_manifest",
            media_type="application/json",
            format_schema_version=SCHEMA_VERSION,
            sha256=sha256_file(manifest_path),
            byte_size=manifest_path.stat().st_size,
            record_count=1,
            creation_stage="T15",
            parent_source_sha256=None,
            revision=f"sha256:{sha256_file(manifest_path)}",
        ),
        manifest_path=manifest_path,
    )


def _closed_text_artifact(relative_path: str, artifact_type: str, staged_path: Path):
    from harness.shared import ClosedArtifact

    return ClosedArtifact(
        relative_path=relative_path,
        artifact_type=artifact_type,
        media_type="text/markdown",
        format_schema_version=SCHEMA_VERSION,
        sha256=sha256_file(staged_path),
        byte_size=staged_path.stat().st_size,
        record_count=1,
        staged_path=staged_path,
    )


def _render_report_markdown(report: AnalysisReport) -> str:
    lines = [
        "# Analysis Report",
        "",
        f"Analysis ID: `{report.analysis_id}`",
        f"Status: `{report.status}`",
        "",
        "## Attempts",
    ]
    for result in report.ue_results:
        lines.extend(
            [
                f"### Attempt `{result.attempt_id}`",
                f"- Procedure: `{result.procedure}`",
                f"- Outcome: `{result.outcome}`",
                f"- Completion: `{result.completion_reason}`",
            ]
        )
        if result.root_cause:
            lines.append(f"- Root Cause: `{result.root_cause}`")
    return "\n".join(lines) + "\n"


def _load_all_events(normalization: NormalizeEventsResult) -> list[CanonicalEvent]:
    descriptor = artifact_by_relative_path(normalization.artifacts, "normalized/events/events.jsonl")
    if descriptor is None:
        raise FileNotFoundError("normalized events artifact not found")
    run_dir = normalization.manifest_path.parents[2]
    return [
        CanonicalEvent.model_validate(record)
        for record in iter_jsonl(run_dir / descriptor.relative_path)
    ]


def _resolve_anchor_frame(anchor: ContextAnchor, events: list[CanonicalEvent], candidates: list[FailureCandidate] | None = None) -> int:
    if anchor.frame is not None:
        return anchor.frame
    if anchor.event_id is not None:
        for event in events:
            if event.event_id == anchor.event_id:
                return event.frame
        raise ValueError(f"unknown anchor event_id {anchor.event_id}")
    if anchor.candidate_id is not None and candidates:
        for candidate in candidates:
            if candidate.candidate_id == anchor.candidate_id:
                if candidate.source_event_ids:
                    for event in events:
                        if event.event_id == candidate.source_event_ids[0]:
                            return event.frame
                return candidate.frame
        raise ValueError(f"unknown anchor candidate_id {anchor.candidate_id}")
    if anchor.evidence_id is not None and candidates:
        for candidate in candidates:
            if anchor.evidence_id in candidate.evidence_ids:
                if candidate.source_event_ids:
                    for event in events:
                        if event.event_id == candidate.source_event_ids[0]:
                            return event.frame
                return candidate.frame
        raise ValueError(f"unknown anchor evidence_id {anchor.evidence_id}")
    if not events:
        raise ValueError("no events available to resolve anchor")
    return events[0].frame


def _field_path_results(payload: dict[str, Any], field_paths: list[str]) -> list[FieldPathResult]:
    return [_field_path_result(payload, field_path) for field_path in field_paths]


def _field_path_result(payload: dict[str, Any], field_path: str) -> FieldPathResult:
    current: Any = payload
    for part in [segment for segment in field_path.split(".") if segment]:
        if isinstance(current, dict) and part in current:
            current = current[part]
            continue
        return FieldPathResult(field_path=field_path, found=False)
    return FieldPathResult(field_path=field_path, found=True, value=current)
