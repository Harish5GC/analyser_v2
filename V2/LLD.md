# V2 5G Call Failure Analysis Harness Low-Level Design

## 1. Proposed Package Layout

```text
V2/
  requirement.md
  architecture.md
  LLD.md
  tools/
    README.md
    T01_decode_capture.md
    T02_normalize_events.md
    T03_build_identity_graph.md
    T04_segment_attempts.md
    T05_get_ue_request.md
    T06_find_http_failures.md
    T07_find_nas_ngap_failures.md
    T08_find_pfcp_failures.md
    T09_detect_missing_transitions.md
    T10_get_attempt_timeline.md
    T11_compare_attempts.md
    T12_rank_root_causes.md
    T13_parse_scenario.md
    T14_validate_scenario.md
    T15_build_evidence_packet.md
    T16_generate_diagnosis.md
    T17_render_report.md
    T18_lookup_full_evidence.md
    T19_get_packet_context.md
    T20_targeted_redecode.md
    T21_classify_capture_phases.md
    T22_build_nf_lifecycle.md
    T23_assess_background_impact.md
    T24_inspect_nrf_flow.md
    T25_inspect_udr_flow.md
  harness/
    __init__.py
    cli.py
    config.py
    orchestrator.py
    errors.py
    models/
      common.py
      events.py
      identity.py
      attempts.py
      failures.py
      evidence.py
      tool_requests.py
      scenario.py
      reports.py
      run_store.py
    decoder/
      runner.py
      manifest.py
      command.py
      validation.py
      errors.py
    normalize/
      base.py
      http2.py
      ngap.py
      nas.py
      pfcp.py
      partition_router.py
    storage/
      event_store.py
      jsonl_store.py
      run_store.py
      evidence_repository.py
      frame_index.py
      primary_reader.py
      nrf_reader.py
      udr_reader.py
      nrf_index.py
      udr_index.py
    analysis/
      identity_graph.py
      session_linker.py
      scoring.py
      capture_phases.py
      attempt_engine.py
      attempt_definitions.py
      primary_http.py
      nas_ngap.py
      pfcp.py
      transitions.py
      retries.py
      consistency.py
      ranker.py
      compare.py
      profiles/
        registration.py
        pdu_session.py
        service_request.py
        emergency.py
        mobility.py
        handover.py
        roaming.py
        deregistration.py
    dependency_tools/
      registry.py
      request_validator.py
      executor.py
      nrf/
        inspector.py
        lifecycle.py
        discovery.py
        impact.py
      udr/
        inspector.py
        transactions.py
        correlation.py
        masking.py
        impact.py
    scenario/
      parser.py
      validator.py
    evidence/
      initial_builder.py
      expanded_builder.py
      lookup.py
      packet_context.py
      targeted_redecode.py
      masking.py
      token_budget.py
    providers/
      base.py
      openai_compatible.py
      disabled.py
    reporting/
      builder.py
      markdown.py
    prompts/
      initial_diagnosis.txt
      final_diagnosis.txt
      scenario_system.txt
    schemas/
      evidence_packet.schema.json
      model_diagnosis.schema.json
      tool_request.schema.json
      report.schema.json
  tests/
    unit/
    integration/
    fixtures/
```

The package starts as Python because orchestration, model APIs and diagnostic rules change faster than PCAP decoding. Existing Go decoders remain the decode engine. Detailed T01-T25 implementation contracts are indexed in `tools/README.md`.

### 1.1 Dependency boundaries

Directory separation is not sufficient to protect lazy NRF/UDR evidence. Constructors and interfaces enforce these boundaries:

- `analysis` receives `PrimaryEventReader` only.
- `dependency_tools.nrf` receives `NRFEventReader` only after request validation.
- `dependency_tools.udr` receives `UDREventReader` only after request validation.
- `evidence.initial_builder` cannot import NRF/UDR readers.
- `evidence.expanded_builder` accepts completed `DependencyInspectionResult` objects, not direct NRF/UDR readers.
- Only `dependency_tools.executor` owns all dependency reader capabilities.

The orchestrator coordinates the phases but does not pass the complete event store into primary detectors.

## 2. Command-Line Interface

Primary command:

```bash
python -m V2.harness.cli analyze capture.pcap \
  --output-root V2/output \
  --provider local \
  --base-url http://localhost:8000/v1 \
  --model qwen-model \
  --scenario "UE should establish an IPv4 session on DNN internet1"
```

OpenRouter:

```bash
OPENROUTER_API_KEY=... python -m V2.harness.cli analyze capture.pcap \
  --provider openrouter \
  --model <model-name>
```

Deterministic-only:

```bash
python -m V2.harness.cli analyze capture.pcap --provider none
```

CLI arguments:

```text
analyze PCAP
  --output-root PATH
  --scenario TEXT
  --scenario-file PATH
  --provider none|local|openrouter
  --base-url URL
  --model NAME
  --api-key-env NAME
  --ue SELECTOR
  --attempt UUID
  --max-model-attempts N
  --model-attempt-order policy
  --include-nrf-success
  --include-udr-success
  --unmasked-local-evidence
  --decoder-binary PATH
  --config PATH
  --log-level LEVEL
```

`--ue` and `--attempt` narrow both deterministic reporting focus and model
narration. `--max-model-attempts` and `--model-attempt-order` configure the
model narration policy defined in section 28; they never reduce deterministic
analysis, which always covers every persisted attempt.

`--include-nrf-success` and `--include-udr-success` affect report and
dependency-expanded packet summaries only after a model-approved dependency
inspection has run. They do not trigger dependency inspection, grant primary
partition access, or put NRF/UDR success records in the initial packet.
`--unmasked-local-evidence` is valid only for `provider="local"` and only
when the resolved masking policy explicitly allows it. Reports, manifests,
provider ledgers and remote-provider packets remain masked regardless of this
flag.

Exit codes:

- `0`: analysis completed, regardless of whether the call itself failed.
- `2`: invalid input/configuration.
- `3`: fatal decode failure.
- `4`: fatal internal analysis error.
- `5`: report write failure.

Model failure does not change exit code from `0` when deterministic analysis completed.

## 3. Configuration Model

```python
class HarnessConfig(BaseModel):
    output_root: Path
    decoder_binary: Path
    decoder_timeout_seconds: int = 600
    provider: Literal["none", "local", "openrouter"] = "none"
    base_url: str | None = None
    model: str | None = None
    api_key_env: str | None = None
    secret_ref: str | None = None
    model_timeout_seconds: int = 120
    temperature: float = 0.1
    max_model_input_tokens: int = 12000
    max_model_output_tokens: int = 2000
    model_input_target_min_tokens: int = 2000
    model_input_target_max_tokens: int = 8000
    model_token_safety_margin: int = 256
    model_profile_version: str | None = None
    token_counter_profile: str = "utf8_bytes_v1"
    max_total_model_calls_per_pass: int = 3
    max_transport_retries_per_pass: int = 1
    max_content_recovery_calls_per_pass: int = 1
    dependency_lookup_mode: Literal["model_requested"] = "model_requested"
    max_dependency_requests_per_attempt: int = 2
    dependency_context_frames_before: int = 100
    dependency_context_frames_after: int = 100
    mask_remote_evidence: bool = True
    attempt_idle_timeout_seconds: float = 30.0
    retention_days: int | None = None
    include_nrf_success: bool = False
    include_udr_success: bool = False
    unmasked_local_evidence: bool = False
    context_frames_before: int = 20
    context_frames_after: int = 20
    max_context_frames: int = 500
    max_full_record_bytes: int = 10_000_000
    max_model_attempts_per_run: int = 5
    model_attempt_order: Literal[
        "severity_then_first_frame", "first_frame", "last_frame"
    ] = "severity_then_first_frame"
    enabled_capabilities: set[CapabilityName] = Field(default_factory=set)
```

`api_key_env` names an environment variable resolved only inside the provider
process boundary. `secret_ref` is an opaque secret-manager reference. Raw API
key values are invalid in persisted configuration, manifests, provider
ledgers and reports.

Precedence:

```text
CLI argument > environment variable > YAML config > default
```

Validation rules:

- `openrouter` requires model and populated API-key environment variable.
- `local` requires base URL and model.
- `none` ignores model settings.
- Remote evidence masking cannot be disabled for OpenRouter.
- `unmasked_local_evidence=true` is rejected unless `provider="local"` and
  the resolved `MaskingPolicy.local_unmasked_allowed` is true.
- `include_nrf_success` and `include_udr_success` never imply dependency
  inspection; they are disclosure controls for approved dependency results.

### 3.1 Version vocabulary and capability gates

Version terms have distinct runtime meanings:

```python
CapabilityName = Literal[
    "cli_single_run",
    "jsonl_run_store",
    "profile_registry",
    "canonical_artifact_revisions",
    "two_pass_dependency_inspection",
    "bounded_targeted_redecode",
    "authenticated_evidence_cursors",
    "openai_compatible_provider",
    "masking_policy",
    "api_service",
    "sqlite_event_store",
    "queued_analysis",
    "additional_dependency_tools",
    "vendor_specific_profiles",
    "learned_anomaly_ranking",
]

class VersionVocabulary(BaseModel):
    product_generation: Literal["V2"]
    release_milestone: str
    document_revision: str
    schema_versions: dict[str, str]
    policy_versions: dict[str, str]
    artifact_revisions: dict[str, str]
    enabled_capabilities: set[CapabilityName]
```

`product_generation` names this harness generation. `release_milestone` is
roadmap metadata and must not control behavior. `document_revision` identifies
these Markdown contracts. `schema_versions` identify persisted payload
compatibility. `policy_versions` identify checksummed config/profile/policy
inputs. `artifact_revisions` identify immutable tool output generations.

Runtime behavior is selected by `enabled_capabilities` and validated resolved
configuration, never by matching prose such as a milestone number. Enabling a
new capability requires an owner, config schema, manifest disclosure, issue
codes where applicable and tests before tools may branch on it.

## 4. Core Data Models

All models use Pydantic v2 and include `schema_version = "2.0"` at persisted boundaries.

### 4.1 Source reference

```python
class SourceRef(BaseModel):
    decoder_file: str
    json_path: str
    frame: int
    field_path: str | None = None
    original_value: JsonValue | None = None
    record_id: UUID | None = None
    byte_offset: int | None = None
    byte_length: int | None = None
    artifact_sha256: str
```

Large original values are truncated only in reports and model evidence. Complete values remain available through `record_id` and artifact offsets.

### 4.2 Canonical event

```python
class CanonicalEvent(BaseModel):
    event_id: UUID
    protocol: Literal["NAS", "NGAP", "HTTP2", "PFCP"]
    frame: int
    timestamp: Decimal | None
    timestamp_precision: Literal[
        "seconds", "milliseconds", "microseconds", "nanoseconds", "unknown"
    ] = "unknown"
    src: str | None
    dst: str | None
    direction: Literal["UE_TO_NETWORK", "NETWORK_TO_UE", "NF_TO_NF", "UNKNOWN"]
    message_type: str
    outcome: Literal["request", "success", "failure", "notification", "unknown"]
    identifiers: EventIdentifiers
    attributes: dict[str, JsonValue]
    raw_refs: list[SourceRef]
    partition: Literal["primary", "nrf", "udr"]
    validation_status: Literal["valid", "partial", "quarantined"]
    issues: list[Issue] = Field(default_factory=list)
```

JSONL is the physical persistence format; `CanonicalEvent` is the logical
schema. `timestamp` is normalized to absolute Unix-epoch decimal seconds when
available and records source precision. Frame order is the deterministic
fallback. `raw_refs` is plural for every logical event, including events whose
primary source is one decoded record.

### 4.3 Event identifiers

```python
class EventIdentifiers(BaseModel):
    supi: str | None = None
    suci: str | None = None
    gpsi: str | None = None
    guti: str | None = None
    pei: str | None = None
    amf_ue_ngap_id: str | None = None
    ran_ue_ngap_id: str | None = None
    pdu_session_id: int | None = None
    procedure_transaction_id: int | None = None
    http2_key: str | None = None
    correlation_id: str | None = None
    sm_context_ref: str | None = None
    pfcp_sequence: int | None = None
    cp_seid: str | None = None
    up_seid: str | None = None
    ue_ip: str | None = None
    charging_id: str | None = None
```

### 4.4 Identity graph

```python
class IdentityEdge(BaseModel):
    left_type: str
    left_value: str
    right_type: str
    right_value: str
    confidence: Decimal
    reason: str
    event_ids: list[UUID]
    valid_from_frame: int
    valid_to_frame: int | None

class UEContext(BaseModel):
    ue_id: UUID
    aliases: dict[str, set[str]]
    edge_ids: list[UUID]
    warnings: list[str]
```

Confidence threshold bands are named, configured T03 values:

```python
class IdentityLinkThresholds(BaseModel):
    auto_link_threshold: Decimal = Decimal("0.90")
    warning_link_threshold: Decimal = Decimal("0.70")
```

- `confidence >= auto_link_threshold` and no hard conflict: automatic link.
- `warning_link_threshold <= confidence < auto_link_threshold`: link with a
  recorded warning that lowers downstream correlation confidence.
- `confidence < warning_link_threshold`: candidate only; UE contexts are never
  merged from candidates.

Validation requires `auto_link_threshold > warning_link_threshold`. These two
fields replace the former `minimum_auto_link_confidence`; no separate
auto-link knob exists. Threshold-boundary behavior (exactly `0.90`, exactly
`0.70`) is fixed by the inclusive lower bound of each band and covered by unit
tests.

### 4.5 Procedure attempt

```python
class ProfileSelectionAlternative(BaseModel):
    profile_id: str
    procedure: ProcedureType
    confidence: Decimal
    score_terms: list[ScoreTerm]
    status: Literal["selected", "alternative", "rejected", "disambiguated"]
    evidence_ids: list[UUID]
    rationale_codes: list[str]
    rejection_reason: str | None = None

class StageTimingObservation(BaseModel):
    stage_id: str
    status: Literal["observed", "absent", "not_applicable", "inconclusive"]
    anchor: Literal[
        "event_frame", "timeout_deadline", "capture_boundary",
        "profile_condition", "derived_interval"
    ]
    start_frame: int | None
    end_frame: int | None
    start_time: Decimal | None
    end_time: Decimal | None
    precision: Literal["frame_exact", "time_exact", "frame_range", "time_range", "unknown"]
    source: Literal[
        "T04", "T05", "T06", "T07", "T08", "T09", "T21", "T22", "T23"
    ]
    evidence_ids: list[UUID]
    reason_codes: list[str]

class ProcedureAttempt(BaseModel):
    attempt_id: UUID
    ue_id: UUID
    procedure: ProcedureType
    profile_id: str
    profile_alternatives: list[ProfileSelectionAlternative] = Field(default_factory=list)
    sequence: int
    parent_attempt_id: UUID | None
    start_frame: int
    end_frame: int | None
    start_time: Decimal | None
    end_time: Decimal | None
    request_signature: dict[str, JsonValue]
    identifiers: EventIdentifiers
    current_state: str
    transitions: list[StateTransition]
    event_ids: list[UUID]
    retries: list[RetryRecord]
    stage_timings: list[StageTimingObservation] = Field(default_factory=list)
    outcome: Literal["open", "succeeded", "failed", "aborted", "timed_out", "incomplete_capture"]
    completion_reason: str | None
```

### 4.6 Failure candidate

```python
class FailureCandidate(BaseModel):
    candidate_id: UUID
    attempt_id: UUID
    protocol: str
    category: str
    severity: Literal["info", "warning", "error", "critical"]
    frame: int
    related_frames: list[int]
    component: str | None
    summary: str
    observed: dict[str, JsonValue]
    expected: dict[str, JsonValue] | None
    explicit: bool
    downstream: bool = False
    cleanup: bool = False
    evidence_ids: list[UUID]
    detector: str
    detector_score: Decimal
    score_terms: list[ScoreTerm]
    capture_phase: str
    relevance: Literal["attempt_related", "dependency_related", "startup_background", "concurrent_background", "post_call_background", "unresolved_infrastructure"]
    call_impact: Literal["causal", "contributing", "unrelated", "inconclusive"]
```

`ScoreTerm` is the named score component defined in section 12; detectors
persist every base/bonus/penalty term they apply, and `detector_score` is the
clamped sum of those terms.

Field ownership is fixed; a published candidate is immutable:

| Field | Owner | Rule |
|---|---|---|
| `severity` | Emitting detector (T06-T09, T24/T25 adapters) | Assigned from the detector's versioned rule table; never recomputed downstream. |
| `capture_phase` | Emitting detector | Resolved through the `DetectionContext` phase reader (T21 intervals). |
| `relevance` | Emitting detector | Defaults to `attempt_related` for attempt-assigned evidence; background/dependency labels per detector rules. |
| `call_impact` | T23 only | Every primary candidate is published with `call_impact="inconclusive"`. Only a T23 assessment, wrapped by T24/T25 into a new dependency candidate, carries another value. |
| `detector_score`, `score_terms` | Emitting detector | T12 consumes them as ranking inputs and persists its own `RankedCandidate`; it never mutates the source candidate. |
| `downstream`, `cleanup` | Emitting detector (initial flags); T12 (final classification) | T12 records its downstream/cleanup conclusions in `RankedCandidate.classification`, not by rewriting the candidate. |

```python
class RootCauseResult(BaseModel):
    attempt_id: UUID
    primary_candidate_id: UUID | None
    alternative_candidate_ids: list[UUID]
    downstream_candidate_ids: list[UUID]
    deterministic_confidence: Literal["high", "medium", "low", "inconclusive"]
    rationale_codes: list[str]
```

### 4.8 NF lifecycle models

```python
class NFLifecycleEvent(BaseModel):
    nf_instance_id: str | None
    nf_type: str | None
    service_names: list[str]
    frame: int
    operation: str
    http_status: int | None
    state_before: str
    state_after: str
    classification: Literal["normal", "benign_startup_cleanup", "failure", "recovery", "unknown"]
    evidence_ids: list[UUID]

class BackgroundImpact(BaseModel):
    candidate_id: UUID
    attempt_id: UUID
    call_impact: Literal["causal", "contributing", "unrelated", "inconclusive"]
    recovery_frame: int | None
    rationale_codes: list[str]
    evidence_ids: list[UUID]
```

`NFReadinessSnapshot` is the service-requirement snapshot defined in section
23.4. Lifecycle events feed readiness, but readiness is never collapsed into
one global NF-instance state.

### 4.9 UE request

```python
class UERequest(BaseModel):
    attempt_id: UUID
    procedure: str
    registration_type: str | None
    service_type: str | None
    request_type: str | None
    dnn: str | None
    snssai: SNSSAI | None
    pdu_session_id: int | None
    procedure_transaction_id: int | None
    pdu_type: str | None
    ssc_mode: str | None
    qos: dict[str, JsonValue] | None
    source_event_ids: list[UUID]
    missing_fields: list[str]
```

### 4.10 Evidence stage and model pass

Two distinct enums describe the two-generation flow. They are never collapsed
into one type:

```python
EvidenceStage = Literal["primary", "dependency_expanded"]
ModelPass = Literal["initial", "final"]
```

- `EvidenceStage` labels deterministic evidence generations: T12 rankings,
  T14 validations and T15 packets.
- `ModelPass` labels T16 provider invocations only.

Mapping and legal transitions:

| EvidenceStage | Consumed by ModelPass | Transition rule |
|---|---|---|
| `primary` | `initial` | Always the first generation. The T15 packet built at stage `primary` is referred to throughout these documents as the "initial packet" because it feeds the initial model pass. |
| `dependency_expanded` | `final` | Created only through the section 19.3 commit barrier from admitted inspection results. Exactly one final pass per attempt; no further transition exists. |

A `final` pass without a `dependency_expanded` packet is illegal, as is a
second `dependency_expanded` generation for the same attempt. Artifacts of
both stages are immutable; the expanded generation references its primary
parent by revision, never by mutation.

## 5. Decoder Runner Design

Interface:

```python
class DecoderRunner(Protocol):
    def decode(self, pcap_path: Path, run_dir: Path) -> DecoderManifest: ...
```

Subprocess command:

```text
<decoder_binary> decode <pcap_path> --output-dir <run_dir>/decoded --format v2
```

Until the Go CLI supports `decode`, the adapter may invoke the existing `analyze --offline` command inside the run directory. This is temporary because fixed filenames make concurrent or isolated execution harder.

The runner must:

- Capture stdout/stderr into run logs.
- Enforce timeout.
- Record binary hash/version and `tshark --version`.
- Validate JSON files before returning.
- Never parse model output from decoder process logs.
- Copy or filesystem-reflink the source PCAP into `source/` and verify its checksum before analysis; do not use a mutable hard link.
- Retain both raw/full and derived cleaned outputs.
- Include checksums, sizes and record counts in the decoder manifest.

## 6. Normalizer Interfaces

```python
class ProtocolNormalizer(Protocol):
    protocol: str
    def iter_events(self, source: Path) -> Iterator[CanonicalEvent]: ...
```

### 6.1 HTTP/2 normalization

For each conversation:

1. Parse stream key and frames.
2. Classify SBI service from URI path.
3. Extract method and status.
4. Extract identifiers from headers, URI and selected body paths.
5. Parse `ProblemDetails` into fixed attributes.
6. Emit one request event and one response event when present.
7. Emit an incomplete-response marker when response is absent.

No body is copied wholesale into canonical events. Only configured semantic fields and bounded excerpts are retained.

The full HTTP/2 record remains unchanged in `decoded/full/` and is reachable through `SourceRef`. Canonical-body reduction must not remove data from the retained record.

### 6.2 NAS normalization

NAS extraction recursively searches known Wireshark paths but maps results to stable names.

NAS message, IE, cause and release-compatibility mappings come from one
resolved protocol codepoint registry. LLD and tool specs must not duplicate
NAS codepoint tables; they reference registry names and semantic fields.

```python
class ProtocolCodepointRegistry(BaseModel):
    registry_name: Literal["5g_nas_ngap_pfcp"]
    registry_version: str
    schema_version: str
    sha256: str
    nas_message_types: dict[str, str]
    nas_causes: dict[str, str]
    ngap_procedures: dict[str, str]
    ngap_causes: dict[str, str]
    pfcp_message_types: dict[str, str]
    pfcp_causes: dict[str, str]
```

The section 29 resolver validates this registry at startup and passes an
immutable handle to T02. Unknown NAS message codes remain events with
`message_type = "NAS_UNKNOWN_<code>"` and preserve the raw code in
`attributes`. Registry changes enter the T02 revision through
`policy_versions`.

### 6.3 NGAP normalization

NGAP normalizer emits the NGAP procedure event and invokes the NAS normalizer for every `NAS_PDU_tree` or `pDUSessionNAS_PDU_tree`. Embedded NAS events inherit the outer NGAP frame and identifiers.

### 6.4 PFCP normalization

PFCP requests and responses are initially linked by `response_to`, then by sequence number, endpoints and time when `response_to` is absent.

### 6.5 Partition routing

Partition routing is versioned, table-driven and conservative. NAS, NGAP and
PFCP events always route to the `primary` partition in V2. HTTP/2/SBI events
route through the resolved primary/NRF/UDR partition policy using normalized
service/API/resource/producer/consumer metadata, never only host substrings.
T02 records the partition policy version and partition reason on each event
and in the normalization manifest.

## 7. Storage Interfaces

```python
class PartitionedEventWriter(Protocol):
    def append(self, event: CanonicalEvent) -> None: ...
    def finalize(self) -> None: ...


class PrimaryEventReader(Protocol):
    def for_attempt(self, attempt_id: UUID) -> Iterable[CanonicalEvent]: ...
    def by_frame(self, start: int, end: int) -> Iterable[CanonicalEvent]: ...
    def by_protocol(self, protocol: str) -> Iterable[CanonicalEvent]: ...
    def by_identifier(self, kind: str, value: str) -> Iterable[CanonicalEvent]: ...
    def get(self, event_id: UUID) -> CanonicalEvent: ...


class NRFEventReader(Protocol):
    def by_nf_instance(self, nf_instance_id: str, start: int, end: int): ...
    def by_service(self, service_name: str, start: int, end: int): ...
    def by_consumer(self, consumer_nf: str, start: int, end: int): ...


class UDREventReader(Protocol):
    def by_operation(self, operation: str, start: int, end: int): ...
    def by_consumer(self, consumer_nf: str, start: int, end: int): ...
    def by_masked_correlation(self, key: str, start: int, end: int): ...
```

`PartitionedJsonlEventStore` writes the complete ordered `events.jsonl` plus `primary_events.jsonl`, `nrf_events.jsonl` and `udr_events.jsonl`. It builds compact general, NRF and UDR index files. The store factory gives the orchestrator a `PrimaryEventReader` and injects the NRF/UDR readers directly into `DependencyToolExecutor`. Primary detectors never receive a generic partition selector. Writes use temporary files plus `os.replace`.

### 7.1 Full evidence repository

```python
class EvidenceRepository(Protocol):
    def get_full_record(self, ref: SourceRef) -> FullRecord: ...
    def by_frame(self, frame: int, protocol: str | None = None) -> list[FullRecord]: ...
    def frame_window(self, start: int, end: int, detail: DetailMode) -> ContextPage: ...
    def by_stream(self, protocol: str, stream_key: str) -> list[FullRecord]: ...
    def targeted_redecode(self, query: RedecodeQuery) -> DerivedArtifact: ...
```

Canonical artifact layout:

```text
source/
  capture.pcap
  source_manifest.json
decoder/
  raw/<protocol>.packets.jsonl
  full/http2/streams/<stream-document-uuid>.json
  full/http2/stream_index.jsonl
  full/ngap/messages.jsonl
  full/ngap/message_index.jsonl
  full/pfcp/messages.jsonl
  full/pfcp/message_index.jsonl
  decoder_manifest.json
normalized/
  events/events.jsonl
  events/primary_events.jsonl
  events/nrf_events.jsonl
  events/udr_events.jsonl
  identity/
  attempts/
  diagnostics/
  phases/
  scenario/
evidence/
  registry/
  packets/
  context/<query-id>/
  targeted_redecode/<query-id>/
  dependency/<request-id>/
model/
  calls/
  ledgers/
reports/
  report.json
  report.md
  report_manifest.json
indexes/
  frame_index.json
  stream_index.json
  nrf_index.json
  udr_index.json
  identifier_index.json
  attempt_index.json
  evidence_index.json
  artifact_index.json
staging/
manifest.json
```

Every published file or directory collection has an `ArtifactDescriptor` or
`CollectionDescriptor` (section 23.2). Writers publish through `staging/`,
fsync, validate descriptors and promote with atomic rename. `manifest.json` is
published last. T19 context queries and T20 targeted re-decodes are immutable
query-owned directories containing request, result, child index and manifest
artifacts; they are not single loose JSONL files.

### 7.2 Context lookup algorithm

For an anchor failure frame:

1. Resolve failure/evidence IDs to source frames and complete records.
2. Read the configured pre/post frame window through `frame_index`.
3. Include correlated attempt events plus uncorrelated neighboring packets.
4. If required protocol trees are absent, execute bounded targeted re-decode.
5. Save the context query and results as immutable derived evidence.
6. Return a summary page plus continuation token when results exceed caller limits.

The model never receives the unbounded result automatically. `EvidenceBuilder` selects bounded excerpts while reports retain links to the complete artifacts.

### 7.3 Targeted re-decode safety

T20's full normative contract is `tools/T20_targeted_redecode.md`.
`RedecodeQuery` accepts structured fields only; display predicates are a typed
allowlisted AST rather than caller-supplied tshark text:

```python
class RedecodeQuery(BaseModel):
    selection: RedecodeSelection
    display_filter: SafeDisplayFilter | None
    protocol_trees: list[AllowedProtocolTree]
    fields: list[AllowedField]
    decode_as: list[ValidatedDecodeAs]
    source_access_requirement: Literal["allow_scan", "require_indexed"]
```

The implementation applies three independent limits: published result
records/bytes, extracted slice plus tshark resources, and source bytes/packets
scanned to locate the slice. Default scan-preslice mode is O(source position)
even though tshark sees only the slice. Source-size-independent extraction is
claimed only when T01's optional validated frame/time/block-offset index is
used.

Before extraction, a deterministic context planner expands target packets to
include TCP reassembly and HTTP/2 HPACK state, complete SCTP/NGAP fragments,
complete IP datagrams, decode-as state and required pcapng metadata. Missing,
unauthorized or over-limit context fails closed. The extractor produces a
checksummed slice-local-to-source frame map; all derived `SourceRef` values are
restored through that map.

Slices and frame maps live only in query-owned staging. The published manifest
retains source/index/slice/map checksums, access mode, context ranges, extractor
and tshark identities, measured scan/dissection/output costs and cleanup
outcome. Staging is removed on success and every failure path.

## 8. Correlation Algorithm

### 8.1 Exact correlation signals

Score `1.0`:

- Same SUPI/SUCI/GUTI in events.
- Same AMF/RAN UE NGAP ID pair within a valid interval.
- Explicit HTTP correlation ID or SM context reference.
- Explicit PFCP response relationship.

### 8.2 Strong correlation signals

Score `0.9`:

- Same PDU session ID + PTI + UE context.
- Same UE IP/DNN/S-NSSAI linked across SM context and PFCP session.
- PFCP SEID mapping established by request/response pair.

### 8.3 Supporting signals

Score `0.2-0.6`:

- Timestamp proximity.
- Matching DNN or S-NSSAI.
- Matching NF endpoints.
- Same access tunnel identifiers.

Supporting signals cannot create a cross-UE link without at least one exact or strong signal.

## 9. Attempt Segmentation Algorithm

Events are processed by UE in frame order.

For each initiating event:

1. Compute procedure type.
2. Build request signature.
3. Search open attempts with matching UE, procedure, PTI/session and retry window.
4. Attach as retry when matched.
5. Otherwise create a new attempt and increment its per-procedure sequence.
6. Route subsequent events by identifiers and expected-state compatibility.
7. Close on terminal success/failure.
8. At EOF, classify open attempts using capture-boundary and timeout rules.

Attempt key is internal and never based only on PDU session ID:

```text
attempt_id = UUID
logical match = ue_id + procedure + transaction identifiers + time window
```

### 9.1 Capture phase classification

After attempts are segmented, build merged active intervals across all UEs. Apply configurable pre-roll/post-roll only for dependency correlation, not for automatic failure attribution.

Each event receives:

- A capture phase.
- Zero or more overlapping attempt IDs.
- A correlation confidence for each linked attempt.

An HTTP event inside an active interval remains background unless identifiers, dependency stage or NF lifecycle establish relevance.

### 9.2 NF lifecycle transition rules

These rules execute only inside `inspect_nrf_flow` after an approved model evidence request. NRF NFM operations are interpreted per NF instance:

- Successful registration/create/update moves toward `registered`/`available`.
- Explicit suspended/unavailable status changes update service readiness.
- Successful deregistration moves to `deregistered`.
- Deregistration `404` before later successful registration is `benign_startup_cleanup`.
- Failed registration/update leaves the previous known state and records an unresolved failure.
- A later successful registration/update resolves prior failures at its frame.

When NF instance ID is unavailable, FQDN/IP/NF type/service may form a lower-confidence lifecycle identity. Such state must not be promoted to a call root cause without another strong link.

## 10. State Machine Definition

Definitions are declarative. `profiles/README.md` is the normative registry
contract for source-file layout, resolution, release/deployment overlays,
condition facts, compatibility, review and requirement-to-fixture
traceability. The models below describe the resolved runtime view consumed by
T04 and T09; tools never load or patch profile YAML directly.

```python
class StageDefinition(BaseModel):
    name: str
    applicability: Literal["mandatory", "conditional", "optional"]
    condition: Expression | None = None
    event_matchers: list[EventMatcher]
    repeatable: bool = False
    terminal_success: bool = False
    terminal_failure: bool = False
    timeout_seconds: float | None = None

class ProcedureDefinition(BaseModel):
    procedure: ProcedureType
    profile_id: str
    release: str
    deployment_profile: str
    start_matchers: list[EventMatcher]
    stages: list[StageDefinition]
    allowed_variants: list[list[str]]
    visibility_requirements: list[VisibilityRequirement]
    correlation_rules: list[CorrelationRule]
    failure_branches: list[FailureBranch]
```

For PDU session establishment, the engine tracks logical stages rather than enforcing a single vendor-specific packet order:

```text
UE_REQUEST
SM_CONTEXT_CREATE
DEPENDENCY_CALLS (optional/repeatable)
PFCP_ESTABLISHMENT
NGAP_RESOURCE_SETUP
UE_ACCEPT
ACTIVE
```

Each deployment profile may mark a stage mandatory or optional. Defaults follow common 5GC behavior and must avoid declaring failure solely because an unobserved interface was outside the capture point.

### 10.1 Procedure and profile types

`ProcedureType` must include at least:

```text
INITIAL_REGISTRATION
MOBILITY_REGISTRATION_UPDATE
PERIODIC_REGISTRATION_UPDATE
EMERGENCY_REGISTRATION
NON_3GPP_REGISTRATION
AUTHENTICATION
NAS_SECURITY
UE_SERVICE_REQUEST
NETWORK_TRIGGERED_SERVICE
PAGING
PDU_SESSION_ESTABLISHMENT
EMERGENCY_PDU_SESSION_ESTABLISHMENT
PDU_SESSION_MODIFICATION
PDU_SESSION_RELEASE
UE_CONTEXT_RELEASE
UE_DEREGISTRATION
NETWORK_DEREGISTRATION
XN_HANDOVER
N2_HANDOVER
INTER_AMF_HANDOVER
PATH_SWITCH
HANDOVER_CANCEL_ROLLBACK
INTER_SYSTEM_MOBILITY
ACCESS_MOBILITY
ROAMING_REGISTRATION
HOME_ROUTED_ROAMING_SESSION
LOCAL_BREAKOUT_ROAMING_SESSION
```

One high-level procedure may have multiple `profile_id` values for release, access, roaming topology and vendor behavior.

### 10.2 Stage applicability

`mandatory` stages are enforced only when their interface is visible. `conditional` stages become mandatory when their expression evaluates true. `optional` stages add context but cannot independently fail an attempt. Repeatability and terminal behavior are independent flags.

### 10.3 Visibility model

```python
VisibilityDomain = Literal["reference_point", "sbi_service", "sbi_api"]
VisibilityState = Literal["visible", "partial", "not_captured", "unknown"]

class ReferencePointVisibility(BaseModel):
    key: str
    endpoint_roles: tuple[str, str]
    supported_releases: list[str]
    supported_deployment_profiles: list[str]
    realized_by_sbi_services: list[str] = Field(default_factory=list)

class SBIServiceVisibility(BaseModel):
    service_name: str
    producer_nf: str
    supported_releases: list[str]
    supported_deployment_profiles: list[str]
    api_names: list[str] = Field(default_factory=list)

class SBIAPIVisibility(BaseModel):
    api_name: str
    service_name: str
    supported_releases: list[str]
    supported_deployment_profiles: list[str]

class VisibilityRegistry(BaseModel):
    reference_points: dict[str, ReferencePointVisibility]
    sbi_services: dict[str, SBIServiceVisibility]
    sbi_apis: dict[str, SBIAPIVisibility]

class VisibilityRequirement(BaseModel):
    domain: VisibilityDomain
    key: str
    evidence_matchers: list[EventMatcher]
    required_for_missing_stage_failure: bool
    minimum_state: Literal["visible", "partial"] = "visible"
```

Visibility is resolved from the selected release/deployment profile, not from a
timeless enum. `reference_point` keys name point-to-point architecture
reference points, while `sbi_service` and `sbi_api` keys name service-based
interfaces and concrete APIs from normalized HTTP/SBI metadata. The namespaces
are disjoint: `Nnrf` is valid SBI service visibility, not a reference-point
key; NRF-to-NRF roaming visibility is represented by `N27`.

The release/profile registry must include the reference points needed by the
supported procedure families, including `N7` (SMF-PCF policy), `N13`
(UDM-AUSF authentication), `N35` (UDM-UDR), `N36` (PCF-UDR), and `N37`
(NEF-UDR). Existing keys such as `N1`, `N2`, `N4`, `N8`, `N9`, `N10`, `N11`,
`N12`, `N15`, `N16`, `N22`, `N27`, `N40`, and `Xn` remain registry entries
when applicable to the selected release/deployment profile.

The engine derives `visible`, `partial`, `not_captured`, or `unknown` per
domain/key. A missing mandatory stage becomes `inconclusive` unless every
required visibility entry for that stage reaches its `minimum_state`, or the
scenario/capture metadata explicitly guarantees equivalent visibility.

### 10.4 Profile selection

Profile scoring uses:

1. Explicit NAS registration/request type.
2. NGAP procedure family.
3. Access type and PLMN/topology evidence.
4. Presence of handover/path-switch messages.
5. Emergency indication or emergency DNN.
6. Scenario constraints.

Observed protocol evidence has precedence over scenario wording. Profiles
within `0.10` of the highest score remain alternatives until later stages
disambiguate them. T04 persists every selected, alternative, rejected and later
disambiguated profile in `ProcedureAttempt.profile_alternatives`, including
score terms, confidence, evidence and rationale codes. T17 renders these as
procedure-profile alternatives; they are not root-cause alternatives and must
not be mixed into T12 candidate ranking.

### 10.5 Registration profiles

Registration attempts share a parent definition but have distinct stage sets:

- Initial: authentication/security and initial context are expected when required.
- Mobility update: old-context transfer, location update and session-context update are conditional.
- Periodic update: context validation and Registration Accept are central; full authentication is optional.
- Emergency: emergency policy and limited-service variants apply.
- Non-3GPP: access-specific context and identifiers remain separate from 3GPP access.

T03 represents 3GPP, untrusted N3IWF and trusted TNGF access as distinct
time-bounded access-context nodes and registration states under a shared UE.
T04 keys attempts/state by access context and never merges concurrent access
registrations. Explicit access mobility creates evidence-backed relations
between source/target attempts while preserving both histories. The normative
profile anchors and fixtures are in `profiles/README.md` section 5.2.

For initial, mobility and periodic profiles, `REGISTRATION_COMPLETE` is a
conditional acknowledgement stage. The selected release/deployment overlay
evaluates `attempt.registration_accept_requires_ack`, derived from the decoded
Registration Accept and its acknowledgement-triggering information elements.
`true` makes the stage mandatory, `false` makes it not applicable, and
`unknown` makes absence inconclusive. Observing Registration Complete in other
attempts is not an applicability rule.

The start matcher must read the NAS registration type. If unavailable, the profile is `REGISTRATION_UNKNOWN` and the report lists candidate variants.

### 10.6 Emergency profiles

Emergency registration and emergency PDU session attempts carry `emergency = true` in the request signature. The profile controls whether authentication, subscription, charging and normal DNN rules are mandatory, conditional or absent.

An emergency attempt must not be compared against a normal successful attempt. Baseline selection requires the same emergency classification.

### 10.7 Handover profiles

Xn handover detection:

- Path Switch Request without preceding N2 Handover Required in the same UE context.
- Optional PFCP/SBI path update.
- Path Switch Acknowledge as terminal success.

N2 handover detection:

- Handover Required starts the attempt.
- Handover Request/Acknowledge and Handover Command are preparation stages.
- Handover Notify and path/session update complete execution.
- Handover Preparation Failure, Handover Failure or failed rollback are terminal failure branches.

Inter-AMF handover extends N2 handover with source/target AMF context transfer and time-bounded remapping of NGAP identifiers.

### 10.8 Roaming profiles

```python
class RoamingContext(BaseModel):
    topology: Literal["home", "visited_unknown", "home_routed", "local_breakout", "inconclusive"]
    home_plmn: str | None
    serving_plmn: str | None
    visited_nf_domains: set[str]
    home_nf_domains: set[str]
    evidence_ids: list[UUID]
    alternatives: list[TopologyAlternative]
    confidence: Literal["high", "medium", "low", "inconclusive"]
    fault_domains: FaultDomainMap
    topology_revision: str
```

T03 owns this classification and publishes time-bounded
`RoamingTopologyInterval` records plus independent `FaultDomainMap` records.
T04 attaches the applicable interval to each attempt. T11 uses topology only
for baseline compatibility; T12 classifies each candidate's actual domain
against the map; T14 evaluates scenario topology conditions; T17 renders the
selected topology, alternatives/confidence/evidence and candidate fault domain
as separate concepts.

Home-routed profiles expect V-SMF/H-SMF and home/visited path stages only when visible. Local-breakout profiles must not flag absent H-SMF or N9 activity. Failure candidates are assigned a fault domain: `UE`, `RAN`, `VISITED_CORE`, `HOME_CORE`, `INTER_PLMN`, `UPF_PATH` or `UNKNOWN`.

### 10.9 Mobility profile correlation

Mobility attempts use identifier validity intervals. When AMF/RAN IDs change, the old and new identities are linked through context-transfer events, handover messages, PDU session IDs, security context and time proximity. An identifier reused after its validity interval must not link unrelated UEs.

PFCP tunnel changes during handover are expected. The consistency detector
compares the target NGAP tunnel with resulting PFCP FAR/PDR updates rather
than comparing against source tunnel values. Directional F-TEID checks are
profile/stage-aware: NGAP downlink transport parameters are compared to PFCP
FAR Outer Header Creation for the downlink path, while PFCP-created uplink PDR
F-TEID values are compared to the NGAP/session expectation for uplink user
plane. During path switch, target-path checks activate only after the profile's
target-activation stage; source and target tunnels may legally coexist until
old-path cleanup. N9/inter-UPF variants use profile-declared intermediate
tunnel roles instead of one static direction rule.

### 10.10 Reachability and mobile-terminated delivery profiles

Reachability-loss and mobile-terminated delivery analysis is profile-driven,
not inferred from one missing packet. The profile families are:

- `PAGING`: network paging trigger, paging attempt window, UE response or
  timeout.
- `NETWORK_TRIGGERED_SERVICE`: network downlink trigger, paging when idle,
  service request, access-resource activation and user-plane delivery.
- `UE_SERVICE_REQUEST`: UE-triggered service restoration, access-resource
  activation and bearer/tunnel readiness.

T04 selects the profile and attempt bounds. T06 owns primary SBI symptoms such
as failed or unanswered N1N2 message transfer and other core-triggered
delivery requests. T07 owns explicit NAS/NGAP paging, service-request,
resource setup, non-delivery and reject observations. T08 owns PFCP Session
Report, downlink-data, user-plane path failure and directional tunnel
activation observations. T09 owns absent-stage conclusions only after the
profile timeout and visibility checks say the missing stage was observable.

A missing paging response, service request or user-plane delivery stage is
`inconclusive` when capture bounds, radio/core visibility, identity linkage or
idle/reachable state are insufficient. Downlink Data and other routine PFCP
reports remain observations unless the profile and policy map them to the
failed delivery stage.

## 11. Detector Interfaces

Every detector receives the same attempt-scoped `DetectionContext`, created by
the orchestrator (section 19.4). It is the only sanctioned source for capture
bounds, phase lookup and resolved policy tables inside T06-T09:

```python
class DetectionContext(BaseModel):
    analysis_id: UUID
    attempt_id: UUID
    capture: CaptureMetadata
    phase_reader: CapturePhaseReader
    visibility: InterfaceVisibility
    assignment_confidence: Literal["high", "medium", "low"]
    policies: ResolvedPolicySet
```

- `capture` supplies first/last frame and timestamp so timeout and
  capture-boundary decisions (for example T08's
  `request_only_capture_boundary`) have a defined input.
- `phase_reader` resolves any frame to its T21 interval so every candidate can
  populate `capture_phase` deterministically.
- `visibility` is the attempt's persisted T04 reference-point and SBI
  visibility.
- `policies` contains the immutable handles produced by the configuration
  resolver (section 29) for operation policies, cause dictionaries and timeout
  tables; detectors never receive bare version strings.

```python
class FailureDetector(Protocol):
    name: str
    def detect(
        self,
        attempt: ProcedureAttempt,
        events: Sequence[CanonicalEvent],
        context: DetectionContext,
    ) -> list[FailureCandidate]: ...
```

### 11.1 HTTP scoring

- `5xx`: base `0.90`.
- `4xx`: base `0.85`.
- Explicit `ProblemDetails.cause`: add `0.05`.
- No response after timeout: base `0.75`.
- Retry loop ending in failure: add `0.05`.
- Primary HTTP detection skips all transactions assigned to the NRF or UDR partitions.
- NRF/UDR failures cannot become candidates until the corresponding inspection tool returns them.
- Resolved startup/background `4xx` returned by an NRF inspection is excluded from call ranking and reported as infrastructure history.
- Unresolved NF registration/readiness failure is eligible only after the requested NRF inspection and background-impact assessment.

### 11.2 NAS/NGAP scoring

- Explicit NAS reject with cause: base `0.90` as terminal failure.
- NGAP unsuccessful outcome with cause: base `0.95`.
- NAS Non Delivery or Error Indication: base `0.85`.
- Missing expected response: base `0.65` unless capture boundary lowers confidence.

### 11.3 PFCP scoring

- Non-accepted response cause: base `0.95`.
- PFCP Association Setup/Update/Release rejection or unrecovered timeout for
  a node pair selected by the attempt: base `0.90`.
- Request timeout: base `0.80`.
- Session Report Error Indication or user-plane path failure mapped to the
  attempt SEID/F-TEID: base `0.85`.
- Session/SEID inconsistency: base `0.75`.
- Directional F-TEID role mismatch: base `0.75-0.90` by explicitness and
  profile stage.

Scores rank candidates but do not represent statistical probability.

### 11.4 PFCP node, report and tunnel-role contracts

T08 owns these observations. Association and routine report observations are
persisted even when they do not become failure candidates:

```python
class PFCPAssociationObservation(BaseModel):
    observation_id: UUID
    node_pair_id: UUID
    local_node: str | None
    remote_node: str | None
    message_family: Literal[
        "association_setup", "association_update", "association_release",
        "heartbeat"
    ]
    outcome: Literal[
        "accepted", "rejected", "timed_out", "released",
        "restart_detected", "recovered", "unknown"
    ]
    availability: Literal["available", "unavailable", "degraded", "unknown"]
    recovery_timestamp_before: str | None
    recovery_timestamp_after: str | None
    attempt_link: Literal[
        "selected_node_pair", "used_session", "supporting_only",
        "unrelated", "unknown"
    ]
    evidence_ids: list[UUID]

class PFCPSessionReportObservation(BaseModel):
    report_id: UUID
    report_type: Literal[
        "error_indication", "user_plane_path_failure", "downlink_data",
        "usage", "session_report", "unknown"
    ]
    seid: str | None
    f_teids: list[str]
    mapped_attempt_id: UUID | None
    relevance: Literal[
        "attempt_failure_evidence", "observation", "unrelated",
        "inconclusive"
    ]
    evidence_ids: list[UUID]

class TunnelRoleExpectation(BaseModel):
    role: Literal[
        "ngap_downlink_transport", "pfcp_far_outer_header_creation",
        "pfcp_uplink_pdr_f_teid", "n9_intermediate_tunnel",
        "source_path", "target_path", "cleanup_path"
    ]
    stage_id: str
    activation: Literal["source_active", "target_prepared", "target_active", "cleanup"]
    address: str | None
    teid: str | None
    qfi: str | None
    evidence_ids: list[UUID]

class PFCPConsistencyResult(BaseModel):
    check_id: UUID
    check_type: str
    expected: list[TunnelRoleExpectation]
    observed: list[TunnelRoleExpectation]
    status: Literal["consistent", "inconsistent", "inconclusive", "not_applicable"]
    evidence_ids: list[UUID]
    rationale: str
```

Association observations derive attempt candidates only when the attempt
selected or used that node pair and the observation is causally reachable for
the failed stage. T08 must never publish one node-level candidate shared
directly by multiple attempts. Session Report Error Indication and user-plane
path failure can be candidate evidence only when SEID/F-TEID/session mapping
links them to the attempt; Downlink Data, Usage and other reports remain
observations unless profile/cause policy explicitly promotes them.

Tunnel-role expectations are the only T08 input for F-TEID consistency checks.
T08 compares role-to-role expectations (`ngap_downlink_transport` to
`pfcp_far_outer_header_creation`, uplink expectation to
`pfcp_uplink_pdr_f_teid`, and profile-declared N9/source/target/cleanup roles)
rather than globally matching every TEID/address it can see.

PFCP transaction/report `unknown` is an observation state for incomplete,
unsupported or unclassified PFCP evidence. Diagnostic confidence is separate:
partial visibility, an unknown transaction outcome, missing context or
conflicting role evidence may make a candidate or consistency result
`inconclusive`, but `inconclusive` is not added to PFCP transaction-outcome
enums.

## 12. Root-Cause Ranking Algorithm

This section is the canonical score model; `tools/T12_rank_root_causes.md`
elaborates eligibility, relations and persistence using exactly these terms.

For each eligible candidate:

```text
rank_score = detector_base
           + explicit_failure_bonus
           + exact_attempt_link_bonus
           + cross_protocol_explanatory_bonus
           + first_divergence_bonus
           + terminal_explanation_bonus
           + inspected_dependency_impact_bonus
           - downstream_penalty
           - cleanup_penalty
           - recovered_retry_penalty
           - assignment_ambiguity_penalty
           - incomplete_capture_penalty
           - contradiction_penalty
```

| Term | Sign | Meaning |
|---|---|---|
| `detector_base` | + | Clamped sum of the candidate's detector score terms (sections 11.1-11.3). Replaces the former name `detector_score` in ranking formulas. |
| `explicit_failure_bonus` | + | Explicit protocol rejection/cause over inferred absence. |
| `exact_attempt_link_bonus` | + | Exact transaction/identity attempt association. |
| `cross_protocol_explanatory_bonus` | + | Candidate explains later effects through supported links. |
| `first_divergence_bonus` | + | Candidate occurs at or explains the T11 first divergence. Replaces the former name `baseline_divergence_bonus`. |
| `terminal_explanation_bonus` | + | Candidate accounts for the terminal UE effect. |
| `inspected_dependency_impact_bonus` | + | T23 `causal`/`contributing` impact on an admitted dependency candidate. |
| `downstream_penalty` | - | Candidate is explained by an earlier supported cause. |
| `cleanup_penalty` | - | Cleanup/release after the attempt already failed. |
| `recovered_retry_penalty` | - | Failure followed by successful retry/recovery. |
| `assignment_ambiguity_penalty` | - | Low-confidence attempt assignment. Replaces the former name `ambiguous_correlation_penalty`. |
| `incomplete_capture_penalty` | - | Capture boundary weakens the inference. |
| `contradiction_penalty` | - | Evidence contradicts the candidate's claim. |

Every applied term is persisted as a named `ScoreTerm`:

```python
class ScoreTerm(BaseModel):
    name: str
    value: Decimal
    rationale_code: str
    evidence_ids: list[UUID]
```

`rank_score` is the sum of persisted terms clamped to configured bounds; the
scalar is derived, never stored without its terms. Weights, bounds and
thresholds are versioned ranking policy resolved through section 29 and are
part of the ranking revision hash. Ties are broken by the deterministic order
in `tools/T12` section 16 (causal dominance, explicit over inferred,
correlation strength, terminal/divergence explanation, earlier causal stage,
policy protocol priority, candidate UUID).

Temporal rules:

- A candidate after a terminal failure cannot be primary unless it exposes an earlier hidden cause through explicit linkage.
- A UE-facing NAS reject is terminal evidence but may be downstream of an earlier SBI/PFCP/NGAP failure.
- The earliest event is not automatically primary; routine retries or recoverable failures may precede success.
- Events before an attempt start are ineligible unless `call_impact` is `causal` or `contributing`.
- Timestamp proximity alone cannot promote background activity.

The ranker marks a candidate downstream when:

- It occurs after another candidate that causally explains it.
- It is a cleanup/release caused by an already failed procedure.
- Its request contains a reference to the failed upstream transaction.

## 13. Attempt Comparison

Baseline selection is lexicographic. Eligibility filters apply first; ordering
criteria then compare surviving candidates strictly in sequence, so a later
criterion can never override an earlier one:

Eligibility (all required):

1. Same resolved UE.
2. Same procedure/profile family, with the T11 compatibility rules
   (emergency, access type, roaming topology, handover type).
3. `outcome=succeeded`.
4. Earlier than the failed attempt (future-success baselines are a deferred
   `population_baselines` capability, not a V2 behavior).
5. Sufficient reference-point/SBI visibility for the compared stages.

Ordering (strict priority):

1. Higher request-signature similarity band. Similarity is computed as a
   versioned `Decimal` score but compared in configured bands (for example
   `exact`, `high`, `partial`) so that minor numeric noise cannot outrank the
   band order.
2. Within the same band, nearest earlier attempt by frame.
3. Remaining ties: lowest attempt UUID lexical order.

T11 retains its numeric `baseline_score` and per-component weights for audit
of every candidate considered, but the score never overrides this lexicographic
order. `tools/T11_compare_attempts.md` is the elaboration of this contract.

Stage comparison output:

```python
class AttemptComparison(BaseModel):
    failed_attempt_id: UUID
    baseline_attempt_id: UUID
    similarity: float
    first_divergence_stage: str | None
    failed_observation: str | None
    baseline_observation: str | None
    changed_request_fields: dict[str, ValueChange]
    missing_stages: list[str]
    evidence_ids: list[UUID]
```

Dynamic fields excluded from comparison include frame, timestamp, sequence, stream ID, SEID, TEID, UUID and invocation timestamp unless a detector explicitly requires them.

### 13.1 Attempt timeline contract

T10 owns timeline construction. It provides evidence-linked chronological
views for reports, model packets and bounded investigation, but it does not
diagnose, rerank or mutate candidates.

```python
TimelineMode = Literal["internal", "model", "report", "dependency_expanded"]
TimelineLabel = Literal[
    "expected",
    "anomalous",
    "failure",
    "retry",
    "cleanup",
    "terminal",
    "missing_transition",
    "dependency_evidence",
]

class TimelineItem(BaseModel):
    item_id: UUID
    attempt_id: UUID
    child_attempt_id: UUID | None = None
    event_id: UUID | None = None
    candidate_id: UUID | None = None
    checkpoint_id: UUID | None = None
    frame: int
    timestamp: Decimal | None
    sort_ordinal: int
    protocol: str
    direction: str
    stage_id: str | None = None
    message: str
    label: TimelineLabel
    outcome: str | None = None
    identifiers: dict[str, str]
    evidence_ids: list[UUID]
    full_record_available: bool
    summary_attributes: dict[str, JsonValue]

class AttemptTimelineResult(BaseModel):
    schema_version: Literal["2.0"]
    attempt_id: UUID
    mode: TimelineMode
    items: list[TimelineItem]
    total_matching: int
    returned: int
    truncated: bool
    next_cursor: str | None
    revision: str
    issues: list[Issue] = Field(default_factory=list)
```

Mode limits are hard maxima: `model` returns at most 20 items, `internal` 50,
`report` 100 and `dependency_expanded` 50 unless resolved configuration lowers
the value. Configuration cannot raise the `model` cap above 20. Labels are
closed for a schema/policy revision; adding a label requires a schema update,
renderer support and golden report coverage.

Timeline items cite event, candidate, checkpoint and evidence IDs. Synthetic
missing-transition items use profile deadline/anchor frames and cite the
candidate/stage evidence; they never fabricate a packet frame. T10 may expose
checkpoint or candidate evidence for downstream explanation, but diagnostic
conclusions remain owned by T12/T14/T17.

## 14. Scenario Models

Scenario models are owned by the tool specifications and registered in the
shared-model registry (section 23):

- `ScenarioSpec`, `ScenarioCheckpoint`, `ScenarioSelectors`,
  `ExpectedRequest`, `ScenarioTextSpan`, `ScenarioConflict`,
  `ScenarioMatcher`, `ScenarioCondition`, `ScenarioTimeScope` and
  `CheckpointOrdering` are defined in `tools/T13_parse_scenario.md`
  section 5a.
- `CheckpointResult`, `ScenarioAttemptCandidate` and
  `ScenarioEvidenceConflict` are defined in
  `tools/T14_validate_scenario.md` sections 6, 7 and 16.

Invariant: the scenario parser prompt must explicitly return `null` for
unspecified values, and the validator, not the model, decides checkpoint
status.

## 15. Evidence Packet

```python
class EvidencePacket(BaseModel):
    schema_version: Literal["2.0"]
    packet_id: UUID
    pass_stage: EvidenceStage
    analysis_id: UUID
    parent_packet_id: UUID | None
    root_cause_revision: str
    scenario_validation_revision: str | None
    dependency_result_revisions: list[str]
    ue: MaskedUEIdentity
    ue_request: UERequest
    attempt: AttemptSummary
    primary_failure: FailureEvidence | None
    alternatives: list[FailureEvidence]
    downstream_effects: list[FailureEvidence]
    timeline: list[TimelineEvidence]
    comparison: AttemptComparison | None
    scenario_results: list[CheckpointResult]
    evidence: list[EvidenceRecord]
    dependency_evidence: list[DependencyInspectionResult] = Field(default_factory=list)
    warnings: list[str]
```

Token budgeting order:

1. UE request and primary evidence are mandatory.
2. Scenario failures and exact evidence are retained.
3. Timeline is reduced to state transitions and anomalies.
4. Alternative candidates are truncated after five.
5. Baseline details are reduced to first divergence.
6. Bodies are shortened before any mandatory evidence is removed.

Mandatory evidence is a named construction invariant:

```python
class MandatoryEvidenceSet(BaseModel):
    ue_request_evidence_ids: list[UUID]
    attempt_identity_evidence_ids: list[UUID]
    primary_candidate_evidence_ids: list[UUID]
    terminal_effect_evidence_ids: list[UUID]
    required_checkpoint_evidence_ids: list[UUID]
    first_divergence_evidence_ids: list[UUID]
    dependency_causal_evidence_ids: list[UUID] = Field(default_factory=list)
```

T15 may shorten nonessential bodies, repeated successful timeline items,
verbose alternatives and low-priority context during normal trimming. It must
not remove any record referenced by `MandatoryEvidenceSet`. If the mandatory
set plus schema guide cannot fit the resolved pass budget, packet
construction fails deterministically before T16 is invoked; T15 must not
silently degrade by dropping mandatory evidence.

The packet built at `pass_stage="primary"` is the initial packet (section
4.10). It cannot contain detailed NRF or UDR events and sets
`parent_packet_id=None` with no dependency revisions. A dependency-expanded
packet names the exact initial parent packet and may contain only admitted
outputs from `inspect_nrf_flow` or `inspect_udr_flow`; its
ranking/scenario/dependency revisions must match the section 19.3 lineage. The
expanded packet, consumed by the final model pass, must still satisfy the
configured token budget.

### 15.1 Lazy dependency inspectors

```python
class DependencyInspector(Protocol):
    tool_name: Literal["inspect_nrf_flow", "inspect_udr_flow"]

    def inspect(
        self,
        request: DependencyEvidenceRequest,
        repository: EvidenceRepository,
    ) -> DependencyInspectionResult: ...
```

`NRFInspector` receives an `NRFEventReader` at construction and may use lifecycle and impact helpers over only the selected NF/service and bounded interval. `UDRInspector` receives a `UDREventReader`, pairs only selected data-access transactions, and correlates them with the requesting NF. Inspectors return evidence records and conclusions; they do not call the model.

`DependencyToolExecutor` owns the validator and both inspectors. It clamps requested bounds to the attempt's configured pre/post window, enforces masking, rejects unknown tool names and records every accepted or rejected request in the run manifest. This executor is the only primary-runtime object capable of reaching NRF/UDR readers.

## 16. Model Provider Interface

Provider client abstractions live in `harness/providers/` and are shared by
scenario parsing (T13) and diagnosis generation (T16). T16 owns diagnosis
ledgering, pass validation and dependency-request validation; it does not own
the provider package. T14 is deterministic and never invokes a provider.

```python
class ProviderConfig(BaseModel):
    provider: Literal["none", "local", "openrouter"]
    base_url: str | None
    model: str | None
    api_key_env: str | None = None
    secret_ref: str | None = None
    timeout_seconds: int
    structured_output: Literal["require", "prefer", "disabled"] = "require"
    runtime_revision: str

class ProviderMetadata(BaseModel):
    provider: Literal["none", "local", "openrouter"]
    model: str | None
    base_url_origin: str | None
    runtime_revision: str
    request_id: str | None = None
    token_usage: dict[str, int] = Field(default_factory=dict)
```

```python
class ModelProvider(Protocol):
    def generate_json(
        self,
        system_prompt: str,
        user_payload: dict[str, JsonValue],
        response_model: type[BaseModel],
    ) -> ModelResult: ...
```

`OpenAICompatibleProvider` configuration:

```python
OpenAI(
    base_url=config.base_url,
    api_key=secret_resolver.resolve(config.api_key_env, config.secret_ref),
    timeout=config.model_timeout_seconds,
)
```

For `provider="local"`, missing credentials resolve to the literal
`"local-no-key"` only inside the provider adapter and are never persisted as a
secret. For remote providers, an unresolved credential reference is a startup
configuration failure (`exit 2`).

The gateway uses the persisted per-pass call ledger defined by T16 section
12.1. Every actual provider invocation consumes the shared total cap. One
transport retry is shared across the pass, and at most one content-recovery
call is permitted: structured-output fallback or schema repair, never both.
The default maximum is three calls per pass. Call reservation and each outcome
are persisted before another invocation; cancellation/restart cannot reset the
counter. No protocol evidence is expanded during fallback or repair.

## 17. Model Diagnosis Contract

This section is the canonical definition of the model-facing dependency
request and the inspection-result union. T16, T23, T24 and T25 reference it.

```python
DependencyReasonCode = Literal[
    "DISCOVERY_FAILURE_SUSPECTED",
    "NF_REGISTRATION_OR_READINESS_SUSPECTED",
    "SCP_ROUTING_OR_SELECTION_SUSPECTED",
    "SUBSCRIBER_DATA_FAILURE_SUSPECTED",
    "DEPENDENCY_TIMEOUT_SUSPECTED",
]

class DependencyEvidenceRequest(BaseModel):
    tool: Literal["inspect_nrf_flow", "inspect_udr_flow"]
    attempt_id: UUID
    reason_code: DependencyReasonCode
    rationale: str
    initial_evidence_ids: list[UUID]
    frame_start: int
    frame_end: int
    nf_type: str | None = None
    service_name: str | None = None
    nf_instance_id: str | None = None
    fqdn: str | None = None
    consumer_nf: str | None = None
    resource_or_operation: str | None = None
    masked_correlation_key: str | None = None
```

Routing and adaptation:

- The `tool` field is the only dispatch discriminator. A shared reason code
  such as `DEPENDENCY_TIMEOUT_SUSPECTED` is unambiguous because routing never
  depends on the reason code.
- `DependencyToolExecutor` validates the generic request, then adapts it to
  the typed internal contract — `InspectNRFFlowRequest` (T24 section 4) or
  `InspectUDRFlowRequest` (T25 section 4) — adding `request_id`,
  `analysis_id` and `initial_packet_id` from approved run state. The typed
  requests carry no redundant dependency-type field; the executor's choice of
  inspector is the routing.
- `initial_evidence_ids` is mandatory input to T24/T25 rationale validation:
  every cited ID must exist in the initial packet and at least one must
  support the selected reason category.

The inspection-result union consumed by T10, T12, T14, T15, T17 and the
expansion validator:

```python
DependencyInspectionResult = NRFInspectionResult | UDRInspectionResult
```

The union is discriminated by the concrete result type. Consumers that need a
string discriminator use T23's `dependency_type` (`"NRF"` for
`NRFInspectionResult`, `"UDR"` for `UDRInspectionResult`); it is derived from
the type, never stored as an extra field on T24/T25 results.

```python
class ModelDiagnosis(BaseModel):
    ue_request_summary: str
    outcome_summary: str
    root_cause_summary: str
    primary_candidate_id: UUID | None
    alternative_candidate_ids: list[UUID]
    reasoning_steps: list[str]
    evidence_ids: list[UUID]
    confidence: Literal["high", "medium", "low", "inconclusive"]
    limitations: list[str]
    dependency_evidence_requests: list[DependencyEvidenceRequest] = Field(default_factory=list)
```

Validation rules:

- Candidate IDs must exist in the packet.
- Evidence IDs must exist in the packet.
- Model cannot introduce new frame numbers.
- Model cannot change deterministic observed values.
- Each dependency request must target the current failed attempt and overlap its configured pre/post evidence bounds.
- `inspect_nrf_flow` requires an NRF-related reason code and at least one NF/service selector.
- `inspect_udr_flow` requires a subscriber-data/dependency reason and at least one consumer/resource selector.
- At most one request per dependency type is accepted for an attempt.
- Requests in the final model pass are rejected; there is no recursive tool loop.
- Invalid references are removed and recorded as warnings.

## 18. Report Contract

Top-level `report.json`:

```python
class PipelineDecoderReport(BaseModel):
    status: Literal["success", "partial", "failed", "absent"]
    manifest_revision: str | None
    protocol_statuses: dict[str, str]
    artifacts: list[ArtifactDescriptor]
    issues: list[Issue] = Field(default_factory=list)

class PipelineReport(BaseModel):
    decoder: PipelineDecoderReport
    normalization_revision: str | None
    identity_revision: str | None
    attempts_revision: str | None
    diagnostics_revisions: dict[str, str]
    scenario_revision: str | None
    provider_runtime_revision: str | None

class ReportTiming(BaseModel):
    stage_key: str
    elapsed_ms: int
    started_at: str | None
    completed_at: str | None

class AnalysisReport(BaseModel):
    schema_version: Literal["2.0"]
    analysis_id: UUID
    status: Literal["success", "partial", "failed"]
    capture: CaptureMetadata
    pipeline: PipelineReport
    ue_results: list[UEResult]
    scenario: ScenarioResult | None
    provider: ProviderMetadata | None
    warnings: list[Issue]
    timings: list[ReportTiming]
    evidence_integrity: EvidenceIntegrityReport
```

`UEResult` contains all attempts. Each failed attempt contains deterministic
root cause, model diagnosis when available, timeline, profile alternatives,
observability timing rows and evidence. T17 maps tool-local statuses into the
top-level run status: critical publication/source/decode/report failures can
make the run `failed`; absent protocols, partial decode, provider/scenario
failures, unknown phase and evidence limitations make the run `partial`; UE
call failure alone does not.

Golden report normalization is versioned. It masks or normalizes volatile
fields including UUIDs, generated timestamps, run-relative paths, durations,
provider request IDs, token usage and revision digests while preserving
ordering, status, evidence references and deterministic conclusions.

## 19. Orchestration Contract

### 19.1 Invariants

- T01-T04 are run-scoped hard dependencies. T05-T12 are deterministic per-attempt processing; T13/T14, T15/T16 and T18-T25 retain their documented gates.
- T06, T07 and T08 may execute concurrently for one attempt. T09 starts only after all three explicit-detector results for that attempt are available.
- Candidate, timeline, comparison, ranking, diagnosis and dependency-result maps are keyed by `attempt_id`. Cross-attempt candidate accumulation is forbidden.
- Primary code receives only `PrimaryEventReader`. `DependencyToolExecutor` is the only runtime object owning NRF/UDR reader factories.
- T10 primary timelines exist before T11 comparison and before T15 model-packet construction. T05 request extraction exists before T11, T14 and T15.
- T18-T20 are called only through bounded, capability-checked evidence requests. They are not unconditional pipeline stages and their artifacts never mutate T01/T02 evidence.
- Every executed tool result is persisted before the run manifest records that invocation as complete. Optional skipped tools are recorded according to run-manifest policy without converting deterministic success into failure.
- T17 runs even when scenario parsing, provider invocation or dependency inspection is disabled or fails.

### 19.2 Runtime placement

| Tools | Scope | Required predecessor | Gate |
|---|---|---|---|
| T01 -> T02 -> T03 -> T04 -> T21 | Run | Previous tool in chain | Mandatory after successful run setup; partial results follow each tool's contract. |
| T13 | Run/request | Validated input | Scenario text supplied. It may run independently of the capture chain. |
| T05 | Attempt | T04 | Every persisted attempt. |
| T06/T07/T08 | Attempt | T04, T21 and detection context | Every persisted attempt; explicit detectors may run concurrently. |
| T09 | Attempt | T06/T07/T08 for same attempt | Every persisted attempt. |
| T10 primary | Attempt | T05-T09 | Every persisted attempt. |
| T11 | Attempt | T05, T10 and eligible successful attempts | Failed/incomplete diagnostic target. No baseline is a valid result. |
| T12 primary | Attempt | T06-T09 and optional T11 | Failed/incomplete diagnostic target. |
| T14 primary | Scenario/run | T13, T04, T05 and T09 | Valid scenario exists. |
| T15 primary / T16 initial | Attempt | T05, T10-T12 and optional T14 | Provider enabled and attempt selected by the model narration policy (section 28). |
| T24/T25 | Attempt/request | Schema-valid initial T16 request | Approved bounded dependency request. |
| T22 | Internal T24 | Approved NRF request | Invoked only by `NRFInspector`. |
| T23 | Internal T24/T25 | Retrieved bounded dependency evidence | Invoked only inside the selected inspector. |
| T12/T14 dependency-expanded | Attempt/scenario | Completed T24/T25 results | Dependency results affect ranking or scenario checkpoints. |
| T15 dependency-expanded / T16 final | Attempt | Expanded deterministic results | At least one admitted dependency result; exactly one final pass. |
| T18/T19/T20 | On demand | Capability and bounded selector/query | Validated evidence need; T20 only when retained detail is insufficient. |
| T17 | Run | Completed deterministic stages and any optional outcomes | Mandatory final publication. |

### 19.3 Dependency-expanded commit contract

For each selected attempt, the orchestrator creates an `ExpansionInputSet` only after every approved T24/T25 request for that attempt terminates:

```python
class ExpansionInputSet(BaseModel):
    analysis_id: UUID
    attempt_id: UUID
    initial_packet_id: UUID
    primary_ranking_revision: str
    primary_scenario_revision: str | None
    admitted_results: list[DependencyInspectionResult]
    rejected_or_failed_request_ids: list[UUID]
```

An inspection result is admitted only when:

- status is `completed`, `empty` or `partial`;
- `analysis_id`, `attempt_id`, request ID and initial packet ID match approved run state;
- its revision and referenced evidence pass integrity validation;
- it was produced from an initial-pass request and has not already been consumed by another expansion generation.

The admitted result set is sorted by dependency type then request ID before hashing and execution. Empty results are meaningful inspected outcomes: they can preserve the primary ranking while adding limitations or resolve a scenario's "not inspected" state. Failed, unpublished or integrity-invalid results never enter deterministic evidence/ranking inputs.

Processing order is strict:

1. T12 consumes the primary ranking lineage plus all admitted results for the attempt and publishes a new dependency-expanded ranking revision.
2. T14 reruns only when the scenario contains checkpoints that can consume an admitted dependency result. It preserves unaffected checkpoint IDs/status/evidence and publishes one run-level dependency-expanded validation after all selected attempts' inspections settle.
3. T15 verifies that the initial packet, expanded T12 revision, latest applicable T14 revision and admitted inspection revisions form one lineage. It then creates a new packet; it never patches the initial packet in place.
4. T16 verifies `pass_stage=final` against `packet.pass_stage=dependency_expanded`, then performs exactly one final call. Candidate/evidence references are validated against the expanded packet and revised deterministic artifacts.
5. T17 receives both primary and expanded generations plus inspection outcomes, including failed/invalid requests that were excluded from expansion.

If `admitted_results` is empty, steps 1-4 are skipped. The initial T12/T14/T16 artifacts remain authoritative and T17 records why expansion did not occur.

### 19.4 Pseudocode

```python
def analyze(request: AnalysisRequest) -> AnalysisReport:
    run = run_store.create(request)
    manifest = run_manifest.start(run, request)
    retained_pcap = run_store.retain_source(request.pcap_path, run.source_dir)

    scenario_parse = None
    if request.scenario:
        scenario_parse = execute_and_publish(
            manifest, "T13", lambda: scenario_parser.parse(request.scenario)
        )

    decoder_result = execute_and_publish(
        manifest,
        "T01",
        lambda: decoder_runner.decode(retained_pcap, run, request.config),
    )
    normalization = execute_and_publish(
        manifest, "T02", lambda: normalizer.normalize(decoder_result, run)
    )

    primary_reader = event_store_factory.open_primary_reader(normalization)
    dependency_executor = dependency_tool_factory.create_executor(
        normalization=normalization,
        evidence_repository=evidence_repository,
        config=run.config,
    )

    identities = execute_and_publish(
        manifest, "T03", lambda: identity_graph.build(primary_reader)
    )
    segmented = execute_and_publish(
        manifest,
        "T04",
        lambda: attempt_engine.segment(primary_reader, identities),
    )
    attempts = segmented.attempts
    phases = execute_and_publish(
        manifest,
        "T21",
        lambda: phase_classifier.classify(primary_reader, attempts),
    )

    request_results = {}
    explicit_results = {}
    missing_results = {}
    timelines = {}
    comparisons = {}
    primary_roots = {}

    for attempt in attempts:
        attempt_id = attempt.attempt_id
        events = primary_reader.for_attempt(attempt_id)
        context = detection_context_factory.create(
            attempt=attempt,
            phases=phases,
            capture=normalization.capture_metadata,
            visibility=attempt.visibility,
            policies=run.resolved_policies,
        )

        request_results[attempt_id] = execute_and_publish(
            manifest, "T05", lambda: request_extractor.extract(attempt, events)
        )
        http_result, nas_ngap_result, pfcp_result = execute_explicit_detectors(
            manifest=manifest,
            attempt=attempt,
            events=events,
            context=context,
        )
        explicit_results[attempt_id] = (
            http_result,
            nas_ngap_result,
            pfcp_result,
        )
        missing_results[attempt_id] = execute_and_publish(
            manifest,
            "T09",
            lambda: missing_detector.detect(
                attempt=attempt,
                events=events,
                explicit_results=explicit_results[attempt_id],
                context=context,
            ),
        )
        timelines[attempt_id] = execute_and_publish(
            manifest,
            "T10",
            lambda: timeline_builder.build_primary(
                attempt,
                request_results[attempt_id],
                explicit_results[attempt_id],
                missing_results[attempt_id],
            ),
        )

    diagnostic_attempts = [a for a in attempts if a.outcome != "succeeded"]
    for attempt in diagnostic_attempts:
        attempt_id = attempt.attempt_id
        comparisons[attempt_id] = execute_and_publish(
            manifest,
            "T11",
            lambda: comparator.compare(
                target=attempt,
                attempts=attempts,
                requests=request_results,
                timelines=timelines,
            ),
        )
        attempt_candidates = collect_candidates(
            explicit_results[attempt_id], missing_results[attempt_id]
        )
        primary_roots[attempt_id] = execute_and_publish(
            manifest,
            "T12:primary",
            lambda: ranker.rank_primary(
                attempt=attempt,
                candidates=attempt_candidates,
                comparison=comparisons[attempt_id],
            ),
        )

    scenario_primary = None
    if scenario_parse and scenario_parse.scenario:
        scenario_primary = execute_and_publish(
            manifest,
            "T14:primary",
            lambda: scenario_validator.validate_primary(
                scenario_parse.scenario,
                attempts,
                request_results,
                missing_results,
                primary_reader,
            ),
        )

    diagnoses = {}
    initial_packets = {}
    initial_diagnoses = {}
    dependency_outcomes_by_attempt = {}
    dependency_results_by_attempt = {}
    expanded_roots = {}
    scenario_expanded = scenario_primary

    if provider.enabled:
        model_attempts = model_attempt_selector.select(
            diagnostic_attempts, request, scenario_primary
        )

        # Finish every initial pass and approved inspection before producing any
        # run-level dependency-expanded scenario revision or final model pass.
        for attempt in model_attempts:
            attempt_id = attempt.attempt_id
            initial_packets[attempt_id] = execute_and_publish(
                manifest,
                "T15:primary",
                lambda: evidence_builder.build_initial(
                    attempt=attempt,
                    request_result=request_results[attempt_id],
                    timeline=timelines[attempt_id],
                    comparison=comparisons[attempt_id],
                    root=primary_roots[attempt_id],
                    scenario=scenario_primary,
                    token_budget=model_runtime.budget_for("initial"),
                ),
            )
            initial_diagnoses[attempt_id] = execute_and_publish(
                manifest,
                "T16:initial",
                lambda: diagnosis_generator.generate_initial(
                    initial_packets[attempt_id],
                    provider_config=model_runtime.provider_config,
                ),
            )
            dependency_outcomes_by_attempt[attempt_id] = (
                dependency_executor.settle_approved(
                    requests=initial_diagnoses[attempt_id].dependency_evidence_requests,
                    attempt=attempt,
                    initial_packet=initial_packets[attempt_id],
                    manifest=manifest,
                )
            )
            dependency_results_by_attempt[attempt_id] = (
                expansion_validator.admit(
                    outcomes=dependency_outcomes_by_attempt[attempt_id],
                    analysis_id=run.analysis_id,
                    attempt_id=attempt_id,
                    initial_packet=initial_packets[attempt_id],
                    primary_ranking=primary_roots[attempt_id],
                    primary_scenario=scenario_primary,
                )
            )

        for attempt in model_attempts:
            attempt_id = attempt.attempt_id
            dependency_results = dependency_results_by_attempt[attempt_id]
            if not dependency_results:
                diagnoses[attempt_id] = initial_diagnoses[attempt_id]
                continue

            expanded_roots[attempt_id] = execute_and_publish(
                manifest,
                "T12:dependency_expanded",
                lambda: ranker.rank_dependency_expanded(
                    attempt=attempt,
                    primary_result=primary_roots[attempt_id],
                    dependency_results=dependency_results,
                    comparison=comparisons[attempt_id],
                ),
            )

        completed_dependencies = {
            attempt_id: results
            for attempt_id, results in dependency_results_by_attempt.items()
            if results
        }
        if scenario_primary and completed_dependencies:
            scenario_expanded = execute_and_publish(
                manifest,
                "T14:dependency_expanded",
                lambda: scenario_validator.validate_expanded(
                    scenario_primary, completed_dependencies
                ),
            )

        for attempt in model_attempts:
            attempt_id = attempt.attempt_id
            dependency_results = dependency_results_by_attempt[attempt_id]
            if not dependency_results:
                continue

            final_packet = execute_and_publish(
                manifest,
                "T15:dependency_expanded",
                lambda: evidence_builder.build_expanded(
                    initial_packets[attempt_id],
                    dependency_results,
                    expanded_roots[attempt_id],
                    scenario_expanded,
                    token_budget=model_runtime.budget_for("final"),
                ),
            )
            diagnoses[attempt_id] = execute_and_publish(
                manifest,
                "T16:final",
                lambda: diagnosis_generator.generate_final(
                    final_packet,
                    provider_config=model_runtime.provider_config,
                ),
            )

    analysis_state = manifest.build_analysis_state(
        attempts=attempts,
        requests=request_results,
        explicit=explicit_results,
        missing=missing_results,
        timelines=timelines,
        comparisons=comparisons,
        primary_roots=primary_roots,
        expanded_roots=expanded_roots,
        scenario=scenario_expanded,
        dependencies=dependency_results_by_attempt,
        dependency_outcomes=dependency_outcomes_by_attempt,
        diagnoses=diagnoses,
    )
    report = execute_and_publish(
        manifest, "T17", lambda: report_builder.render(analysis_state)
    )
    run_manifest.finalize(manifest, report.status)
    return report
```

`execute_explicit_detectors` invokes T06, T07 and T08 with the same attempt-scoped `DetectionContext`, persists each result independently, and returns only after all three complete or reach their documented partial/failure outcome. `DependencyToolExecutor.settle_approved` performs request validation before creating scoped readers, waits for every approved request to terminate and returns all outcomes for reporting. `expansion_validator.admit` returns only lineage- and integrity-valid `completed`, `empty` or `partial` results in canonical order. T22 and T23 are internal calls and are still recorded as nested manifest invocations. T18-T20 calls are issued by their authorized consumers and persisted through the same manifest helper even though they do not appear as unconditional calls above.

## 20. Logging and Metrics

Structured log fields:

- `analysis_id`.
- `stage`.
- `ue_id` and `attempt_id` when applicable.
- `protocol`.
- `duration_ms`.
- `event_count`.
- `warning_code` or `error_code`.

Logs must not contain unmasked subscriber identifiers, authorization headers or API keys.

Metrics:

- Decode packets/messages per protocol.
- Normalized event count.
- UE and attempt count.
- Failure candidates by detector/category.
- Correlation ambiguity count.
- Evidence token estimate.
- Model latency, retry count and token usage.
- Accepted/rejected dependency request count by tool and reason code.
- NRF/UDR records scanned and returned per approved lookup.

## 21. Test Design

### 21.1 Unit tests

- NAS extraction for registration, service request, PDU establishment and rejects.
- Protocol registry resolution: NAS message/cause mappings come from the
  single resolved codepoint registry, and NAS/NGAP/PFCP events route to the
  primary partition.
- HTTP `ProblemDetails`, missing response and retry detection.
- PFCP cause and request/response pairing.
- PFCP association observation indexing, node-pair availability, restart
  recovery timestamp discontinuity and attempt candidate derivation only
  through selected/used node pairs.
- PFCP Session Report handling: Error Indication/user-plane path failure maps
  to an attempt by SEID/F-TEID, while downlink-data/usage reports remain
  observations unless profile/cause policy promotes them.
- PFCP `unknown` transaction/report outcome remains an observation state and
  maps to diagnostic `inconclusive` only through detector confidence rules;
  no `inconclusive` transaction outcome is accepted.
- Directional F-TEID role checks for NGAP downlink transport, PFCP FAR Outer
  Header Creation, PFCP-created uplink PDR F-TEID, path-switch activation and
  N9 intermediate tunnel roles.
- Identity graph confidence and conflict handling.
- Attempt segmentation with reused PDU session IDs.
- Alternative profile persistence and rendering, separate from root-cause
  alternatives.
- Retry versus new-attempt decisions.
- State transition completion and missing stages.
- Root-cause downstream/cleanup classification.
- Baseline selection and first divergence.
- Evidence token-budget trimming.
- Full-record lookup by event, frame and stream.
- Pre/post context windows containing correlated and uncorrelated packets.
- T10 model timeline hard cap of 20 items, closed eight-label taxonomy,
  candidate/checkpoint evidence references and rejection of diagnostic
  conclusion mutation.
- Targeted re-decode argument validation, bounds and provenance.
- Artifact checksum verification and corruption handling.
- Model output validation and invalid evidence references.
- Registration-profile selection for initial, mobility, periodic and emergency types.
- Emergency-policy conditional stages and emergency-only baseline comparison.
- Xn versus N2 handover profile selection.
- Inter-AMF identity remapping and identifier validity intervals.
- Successful handover cancellation/rollback versus failed rollback.
- Roaming topology classification and home/visited fault-domain assignment.
- Home-routed versus local-breakout stage applicability.
- Reference-point/SBI visibility preventing false missing-stage failures.
- Release/profile visibility registry validation: `N7`, `N13`, `N35`, `N36`
  and `N37` are accepted reference points when supported; `Nnrf` is rejected
  as a reference point and accepted only as SBI service visibility.
- Capture preamble, active and postamble classification with overlapping UE attempts.
- Benign NF deregistration `404` followed by successful registration before a call.
- Unresolved NF registration failure promoted only when the call uses that NF/service.
- Concurrent unrelated NRF errors excluded despite occurring during an active call.
- NRF/UDR partitions are inaccessible to primary detectors and the initial evidence builder.
- Dependency request validation, window clamping, selector requirements and duplicate rejection.
- Final model-pass requests are rejected to prevent recursive lookup loops.
- Identity link bands at exact boundaries (`0.90` auto-links, `0.8999...` warns, `0.70` warns, below `0.70` stays candidate) and `auto_link_threshold > warning_link_threshold` validation.
- `EvidenceStage`/`ModelPass` legality: final pass without an expanded packet rejected; second expanded generation for one attempt rejected; `primary` packet feeding `final` rejected.
- Generic `DependencyEvidenceRequest` adaptation to typed T24/T25 requests, including `tool`-based routing with the shared `DEPENDENCY_TIMEOUT_SUSPECTED` reason code and mandatory `initial_evidence_ids` validation.
- Evidence registry: deterministic `evidence_id` minting, duplicate-mint no-op, divergent-payload collision error, and T18 resolution of every emitted evidence ID with `provider=none`.
- `primary_internal` capability: T05 can resolve assigned primary evidence
  fields, but direct IDs, indexes, cursors and selector expansion cannot reach
  NRF/UDR records without approved dependency capability.
- Canonical artifact tree publication: descriptor validation rejects path
  traversal, schema/media mismatch, unverifiable record counts, child
  checksum mismatch, extra/missing collection members and manifest-before-data
  publication.
- Authenticated cursor validation rejects tampered signatures, expired
  cursors, cross-run reuse, cross-scope reuse, stale artifact revisions and
  requests outside the original capability bounds.
- `FailureCandidate` ownership: detectors emit `call_impact="inconclusive"`; only T23-wrapped dependency candidates carry other values; T12 output never mutates a published candidate.
- Model narration policy: explicit `--attempt`/`--ue` selection, deterministic ordering modes, cap enforcement and skipped-attempt disclosure in manifest/report.
- Configuration resolver: missing/invalid/checksum-mismatched policy version fails at startup; resolved handles reach detectors through `DetectionContext`.
- Version vocabulary: release milestone text cannot alter runtime behavior;
  tools branch only on validated capability gates and resolved configuration.
- Operational flags: `include_nrf_success`, `include_udr_success` and
  `unmasked_local_evidence` are persisted, scoped and rejected when unsafe or
  incompatible with provider/masking policy.
- Shared provider abstraction: T13 and T16 use `harness/providers` contracts,
  while T14 remains deterministic and T16 owns diagnosis-call ledgers.
- Deployment resource profiles cap local provider behavior without depending
  on specific hardware names or benchmark prose.
- Secret handling: `secret_ref` and `api_key_env` resolve only inside the
  provider boundary; raw API-key values in persisted config, manifests,
  provider ledgers or reports fail validation.
- NF readiness cardinality: multiple `ServiceRequirement` rows aggregate
  across candidate NF instances with ready/not-ready/partial/unknown
  outcomes and missing-observation evidence.
- Reachability-loss and mobile-terminated delivery ownership across paging,
  service request, NGAP/PFCP activation and user-plane delivery symptoms.
- Observability timing checklist emits distinct observed/absent/not-applicable/
  inconclusive timings with frame-first precision and T17 report rendering.
- T15 mandatory-evidence guarantee: nonessential details may be shortened,
  mandatory records are never removed and construction fails before provider
  invocation when mandatory content cannot fit.
- Revision envelopes: byte-identical revisions for identical inputs; sibling generation on config change; stale parent revision rejected by section 19.3 lineage validation.
- Run-store lifecycle: lease acquisition/recovery, descriptor validation
  before finalize, retention expiry, legal hold and idempotent delete journal.
- Masking policy: deterministic equality-preserving masks within one policy
  revision, changed masks across salts, remote-provider forced masking and
  local unmask rejection when policy disallows it.
- Report pipeline schema: T17 maps decoder/normalizer/provider/scenario
  partials to top-level status without treating UE call failure as run
  failure; golden normalization preserves evidence ordering and conclusions.
- Logical JSONL schema validation: partition, validation status, issue list,
  source refs and timestamp precision are validated independently from the
  physical JSONL file layout.
- Canonical Decimal/timestamp serialization: no binary floats, RFC 3339 UTC
  generated datetimes, source timestamp precision preservation and
  deterministic revision hashes.
- Baseline selection lexicographic order: higher similarity band beats nearer frame; frame decides only within a band; future success never selected.
- Every machine-readable issue code emitted by any stage is a registered member of `issue_registry.yaml`; unregistered codes fail validation.

### 21.2 Integration fixtures

Required fixture cases:

1. Successful registration and PDU session establishment.
2. HTTP `4xx` causing NAS reject.
3. HTTP `5xx` followed by retries and terminal reject.
4. UDR/NRF traffic remains absent from initial evidence despite containing one relevant failure.
5. PFCP rejected establishment.
6. PFCP request timeout.
7. NGAP unsuccessful PDU resource setup.
8. Explicit NAS reject with no visible upstream cause.
9. Request with no response due to truncated capture.
10. Two UEs with overlapping timestamps.
11. Same UE, nine successful cycles and tenth establishment failure.
12. Same PDU session ID reused with different PTIs.
13. Scenario matching success.
14. Scenario mismatch and missing evidence.
15. Local model unavailable, deterministic report succeeds.
16. OpenRouter malformed response, repair/fallback succeeds.
17. Initial registration success and each major reject branch.
18. Periodic registration success, timeout and repeated retry failure.
19. Mobility registration with AMF context transfer.
20. Emergency registration with limited-service/unauthenticated policy.
21. Emergency PDU session establishment and emergency DNN failure.
22. UE service request and network-triggered paging/service restoration.
23. Paging timeout with no UE response.
24. Xn handover visible only from Path Switch Request onward.
25. N2 handover success, preparation failure, execution failure and cancel/rollback.
26. Inter-AMF handover with old/new NGAP identifier mapping.
27. Handover radio success followed by PFCP path-update failure.
28. Idle mobility with no core procedure, producing no false failure.
29. PFCP Association Setup/Update/Release rejection, timeout and restart
    before/during a selected attempt.
30. PFCP Session Report Error Indication and user-plane path failure mapped to
    the attempt, plus non-failure reports preserved as observations.
31. Directional F-TEID consistency for uplink/downlink, path switch and N9
    variants.
32. Alternative profile reporting for Xn versus incomplete N2, periodic versus
    mobility registration and home-routed versus local-breakout roaming.
33. NF readiness with multiple service/version/endpoint requirements and
    partial NRF observations.
34. Reachability loss and mobile-terminated delivery failure across paging,
    service request and user-plane activation.
35. Observability timing checklist in report JSON/Markdown.
36. 3GPP/non-3GPP access registration and mobility kept separate.
37. Home-routed roaming registration/session success and home-network failure.
38. Local-breakout roaming session without false H-SMF/N9 missing-stage errors.
39. Roaming restriction, unsupported slice and inter-PLMN routing failure.
40. Release/profile visibility differentiates reference points from SBI
    service/API visibility for policy, authentication, NRF and UDR flows.
41. UE-initiated and network-initiated deregistration.
42. Normal context release and cleanup after an earlier failure.
43. A normalized event omits a required body field and full-record lookup recovers it.
44. Root cause requires packets before and after the explicit failure frame.
45. Initial decoder output lacks a protocol tree and targeted re-decode recovers it.
46. Retained artifact checksum mismatch causes an evidence-integrity warning/failure.
47. Capture starts before NFs; the model requests NRF inspection and recovered deregistration `404` responses remain background only.
48. NF registration fails before the call; a call-flow discovery symptom triggers NRF inspection and the unresolved state is linked to the attempt.
49. NRF startup errors exist, but the model makes no dependency request and no NRF records enter model evidence.
50. A UDM-facing subscriber-data error triggers bounded UDR inspection and reveals the causal UDR failure.
51. The model requests capture-wide NRF/UDR data and the validator rejects or clamps the request.
52. A final-pass dependency request is rejected and does not create a third model pass.
53. Two failed attempts in one run retain disjoint candidate sets, rankings, packets and diagnoses.
54. T06/T07/T08 may complete in any order, but T09 for an attempt never starts until all three results are published.
55. No scenario skips T13/T14 without degrading deterministic status; an invalid/partial scenario result does not stop capture analysis.
56. `provider=none` skips T15/T16/T24/T25 and still publishes a deterministic T17 report for every attempt.
57. An enabled provider with no dependency request performs one initial pass and no final pass.
58. Dependency requests from multiple selected attempts complete before one run-level dependency-expanded T14 revision and before any final T16 pass.
59. T18/T19/T20 remain uninvoked when retained evidence is sufficient and cannot be reached without a bounded capability-checked request.
60. Direct top-level invocation of T22 or T23 is rejected; both succeed only under their documented T24/T25 parent invocation.
61. Empty admitted inspection result produces one expanded T12/T15 generation with unchanged primary cause plus an inspected-no-match limitation.
62. Partial admitted inspection contributes only integrity-valid evidence and preserves missing portions as limitations.
63. Failed or integrity-invalid inspection is visible in T17 but cannot appear in T12, T14, T15 or final T16 evidence.
64. NRF and UDR inspections completing in opposite orders produce byte-identical admitted-result ordering, expanded revisions and packet IDs.
65. Expanded T15 construction fails for stale primary ranking, stale scenario validation, cross-attempt result, duplicate revision or mismatched parent packet.
66. Canonical run tree contains source, decoder, normalized, evidence, model,
    report and index descriptors; corrupt or missing descriptor members make
    the run partial/failed according to stage criticality.
67. A published T19 context result pages through authenticated cursors; tamper,
    expiry and stale revision are rejected while the original cursor remains
    valid for the published revision.
68. Run finalization followed by retention expiry deletes only when no active
    lease and no legal hold exist; evidence/report links remain resolvable
    before expiry.
69. Remote-provider analysis masks SUPI/GPSI/PEI/GUTI/UE IP, UDR subscriber
    data and authorization material while preserving equality in one run.
70. Local unmasked evidence is accepted only with `provider=local`, explicit
    CLI flag and a policy that permits it; reports and manifests remain
    masked.
71. Report JSON uses `pipeline` status fields and golden normalization removes
    volatile UUID/timestamp/path/duration/provider/revision values without
    changing deterministic conclusions.
72. Raw secret values in YAML config, manifest, provider ledger or report are
    rejected; `api_key_env` and `secret_ref` are the only persisted handles.
73. Logical canonical events are partitioned into primary/NRF/UDR JSONL files
    with validation issues; quarantined events do not enter primary detectors.
74. Decimal timestamps and generated UTC datetimes produce byte-identical
    revisions across machines; source timestamp precision appears in reports.
75. Evidence/report links issued before a sibling generation fail as stale
    rather than resolving to the sibling artifact.

### 21.3 Orchestration contract tests

Use fake tool adapters that append `(tool, attempt_id, pass_stage)` to an invocation log and return deterministic fixture results. Assert the dependency order and gates defined in section 19. The test must randomize completion order of T06-T08 and run at least two attempts concurrently to expose global-list or late-binding mistakes. Manifest assertions must prove that each executed result is published before its completed status and that skipped optional stages are represented without fabricated artifacts.

### 21.4 Golden reports

Store expected deterministic `report.json` files for fixture captures. Model prose is not golden-tested. Tests validate model schema and evidence references only.

## 22. Implementation Sequence

1. Implement the shared foundations first: version vocabulary/capability
   gates (section 3.1), shared model registry (section 23), artifact
   descriptors, evidence registry (section 24), revision envelopes (section
   25), issue registry (section 26), authenticated cursors (section 30),
   run-store lifecycle (section 31), masking policy (section 32),
   canonicalization (section 33), protocol codepoint registry and the
   configuration/resource resolver (section 29).
2. Add Go decoder output-directory support, retain the source PCAP, and emit
   checksummed raw/full HTTP/NAS/PFCP artifacts, collection descriptors and
   indexes in the canonical run tree.
3. Implement canonical models, logical JSONL validation, partitioned JSONL
   store, NRF/UDR indexes and protocol normalizers.
4. Implement identity graph and attempt segmentation.
5. Add the scenario-profile registry and initial, mobility, periodic, emergency and non-3GPP registration profiles.
6. Add service request, paging, PDU lifecycle, mobility, handover, roaming, deregistration and NF-dependency profiles.
7. Implement primary protocol detectors and root-cause ranking without NRF/UDR partition access.
8. Implement the dependency request validator, NRF inspector, UDR inspector and bounded second model pass.
9. Add baseline comparison and bounded timeline.
10. Add scenario parser/validator.
11. Add evidence builder, authenticated evidence/context lookup and privacy
    masking.
12. Add OpenAI-compatible provider and deterministic fallback.
13. Add reports, CLI, fixtures and golden integration tests.

No model integration should begin before canonical events, attempts and deterministic failure candidates are testable.

## 23. Shared Model Registry

Every model used by more than one tool has exactly one owning module. Tool
specifications reference these definitions and must not re-declare diverging
copies. Serialization schemas are generated from the owning module and
versioned with `schema_version`. Import direction is one way: tool packages
import from `harness/models/`; `harness/models/` imports nothing from tool
packages.

| Model | Owner module | Defined in |
|---|---|---|
| `SourceRef`, `CanonicalEvent`, `EventIdentifiers` | `models/events.py` | Section 4.1-4.3 |
| `IdentityEdge`, `UEContext`, `IdentityLinkThresholds` | `models/identity.py` | Section 4.4 |
| `AccessContextKey`, `AccessRegistrationState` | `models/identity.py` | T03 sections 6.2 and 6.5 |
| `RoamingTopologyInterval`, `TopologyAlternative`, `TopologyEvidenceTerm`, `FaultDomainMap` | `models/topology.py` | T03 section 4.1; section 10.8 |
| `ProcedureAttempt`, `ProfileSelectionAlternative`, `StageTimingObservation`, `StateTransition`, `RetryRecord`, `InterfaceVisibility` | `models/attempts.py` | Sections 4.5, 23.1, 23.6 |
| `FailureCandidate`, `ScoreTerm`, `TerminalEffect` | `models/failures.py` | Sections 4.6, 12; T07 section 10 |
| `PFCPAssociationObservation`, `PFCPSessionReportObservation`, `TunnelRoleExpectation`, `PFCPConsistencyResult` | `models/pfcp.py` | Section 11.4; T08 sections 7, 12, 13 |
| `EvidenceRecord`, `EvidenceCapability`, `CursorEnvelope`, `CursorPage` | `models/evidence.py` | Sections 24, 30 |
| `EvidenceStage`, `ModelPass` | `models/common.py` | Section 4.10 |
| `VersionVocabulary`, `CapabilityName` | `models/common.py` | Section 3.1 |
| `TokenCounterSpec`, `ResolvedTokenBudget`, `ResolvedModelRuntime` | `models/token_budget.py` | Section 29.1; T15 section 4 |
| `ArtifactDescriptor`, `CollectionMemberDescriptor`, `CollectionDescriptor` | `models/common.py` | Section 23.2 |
| `CaptureMetadata`, `FrameWindow`, `PhaseRoll`, `CapturePhaseInterval`, `CapturePhaseLabel` | `models/phases.py` | Section 23.1; T21 sections 5, 12 |
| `ProtocolCodepointRegistry` | `models/protocol_registry.py` | Section 6.2; T02 section 9 |
| `TimelineMode`, `TimelineLabel`, `TimelineItem`, `AttemptTimelineResult` | `models/timeline.py` | Section 13.1; T10 |
| `EventMatcher`, `ConditionExpression`, profile models | `models/profiles.py` | Section 23.3; `profiles/README.md` |
| `DetectionContext`, `ResolvedPolicySet` | `models/detection.py` | Sections 11, 29 |
| `DependencyEvidenceRequest`, `DependencyReasonCode`, `DependencyInspectionResult` | `models/tool_requests.py` | Section 17 |
| `ExpansionBudget`, `ExpansionDecision` | `models/tool_requests.py` | T24 section 15 |
| `DependencyEventSummary`, `DependencyBaselineComparison`, `UDRBaselineComparison` | `models/dependency.py` | Section 23.4 |
| `NFEntityReadiness`, `NFReadinessSnapshot`, `ServiceRequirement` | `models/dependency.py` | Section 23.4; T22 section 15 |
| Scenario models | `models/scenario.py` | Section 14 pointers |
| `Issue`, issue codes | `errors.py` | Section 26 |
| `RunManifest`, `AnalysisState`, `ReportPolicy` | `models/reports.py` | Section 27; T17 section 4 |
| `ProviderConfig`, `ProviderMetadata` | `models/providers.py` | Section 16; T13/T16 |
| `RunStoreState`, `RetentionPolicy`, `RunLease` | `models/run_store.py` | Section 31 |
| `MaskedUEIdentity`, `MaskingPolicy`, `MaskingDecision` | `evidence/masking.py` | Sections 23.5, 32 |
| `EvidenceIntegrityReport`, `GoldenNormalizationPolicy` | `models/reports.py` | Sections 18, 23.5 |
| `MandatoryEvidenceSet` | `models/evidence_packet.py` | Section 15; T15 |
| `DeploymentResourceProfile` | `models/config.py` | Section 29.2 |
| `ProblemDetailsSummary`, `MissingField`, `FieldDifference`, `StageAlignment`, `CanonicalizationPolicy` | `models/common.py` | Sections 23.5, 33 |

### 23.1 Attempt and capture support models

```python
class StateTransition(BaseModel):
    stage_id: str
    from_state: str
    to_state: str
    event_id: UUID | None
    frame: int | None
    occurred_at: Decimal | None
    reason_codes: list[str] = Field(default_factory=list)

class RetryRecord(BaseModel):
    retry_ordinal: int
    event_id: UUID
    frame: int
    same_transaction: bool
    reason_codes: list[str] = Field(default_factory=list)

class VisibilityEvidence(BaseModel):
    state: VisibilityState
    evidence_ids: list[UUID] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

class InterfaceVisibility(BaseModel):
    reference_points: dict[str, VisibilityEvidence]
    sbi_services: dict[str, VisibilityEvidence] = Field(default_factory=dict)
    sbi_apis: dict[str, VisibilityEvidence] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)

class CaptureMetadata(BaseModel):
    first_frame: int
    last_frame: int
    first_timestamp: Decimal | None
    last_timestamp: Decimal | None
    packet_count: int
    source_sha256: str

class FrameWindow(BaseModel):
    frame_start: int
    frame_end: int

class PhaseRoll(BaseModel):
    pre_frames: int
    post_frames: int
    pre_seconds: Decimal | None = None
    post_seconds: Decimal | None = None
```

Keys in `InterfaceVisibility.reference_points`, `.sbi_services`, and
`.sbi_apis` come from the release/profile visibility registry (section 10.3),
not a hard-coded enum. A key may appear in only one namespace. Condition facts
project these states into `visibility.<reference_point>`,
`visibility.service.<service_name>`, and `visibility.api.<api_name>`:
`visible` becomes `observed`, `not_captured` becomes `not_observed`, and
`partial`/`unknown` become `unknown`. A stage that can be evaluated with
partial capture declares `minimum_state="partial"` in its
`VisibilityRequirement` rather than relying on fact projection.

### 23.2 Artifact and collection descriptors

```python
class ArtifactDescriptor(BaseModel):
    artifact_id: UUID
    relative_path: str
    artifact_type: str
    protocol: str | None = None
    media_type: str
    format_schema_version: str
    sha256: str
    byte_size: int
    record_count: int | None = None
    creation_stage: str
    parent_source_sha256: str | None = None
    revision: str | None = None

class CollectionMemberDescriptor(BaseModel):
    relative_path: str
    sha256: str
    byte_size: int
    record_count: int | None = None
    artifact_type: str
    media_type: str
    format_schema_version: str

class CollectionDescriptor(BaseModel):
    collection_id: UUID
    relative_dir: str
    artifact_type: str
    index_artifact: ArtifactDescriptor
    member_count: int
    members_sha256: str
    members: list[CollectionMemberDescriptor]
    parent_source_sha256: str | None = None
    revision: str | None = None
```

`relative_path`/`relative_dir` are run-directory relative, must not contain
`..` or absolute components, and are validated before any read/write. For a
collection (for example HTTP/2 stream documents), `index_artifact` is the
ordered child index whose entries each carry the member checksum and size;
`members_sha256` is the checksum over the ordered index entries. Validation of
a collection requires validating the index and every referenced member. A
descriptor is invalid if media/schema type mismatches content, record counts
cannot be verified when declared, a child is missing or extra, parent source
checksum conflicts, or any path resolves outside the run root after symlink
resolution.

### 23.3 Matchers and conditions

```python
class EventMatcher(BaseModel):
    protocol: str | None = None
    message_types: list[str] = Field(default_factory=list)
    outcome: str | None = None
    attribute_equals: dict[str, JsonValue] = Field(default_factory=dict)
    identifier_present: list[str] = Field(default_factory=list)

class ConditionExpression(BaseModel):
    op: Literal["and", "or", "not", "eq", "ne", "present", "absent", "in"]
    fact: str | None = None
    value: JsonValue | None = None
    children: list["ConditionExpression"] = Field(default_factory=list)
```

Facts are allowlisted attempt/request/visibility/profile keys published in
`profiles/README.md`. Arbitrary code, regex bodies and JSONPath are forbidden
in both models.

### 23.4 Dependency support models

```python
class DependencyEventSummary(BaseModel):
    event_id: UUID
    frame: int
    timestamp: Decimal | None
    operation: str
    status_or_cause: str | None
    entity_or_context: str | None
    phase: str
    evidence_ids: list[UUID]

class DependencyBaselineComparison(BaseModel):
    comparison_id: UUID
    failed_operation_evidence_ids: list[UUID]
    baseline_operation_evidence_ids: list[UUID]
    status_changed: bool
    structure_changed: bool
    retry_count_changed: bool
    propagation_outcome_changed: bool
    rationale_codes: list[str]

class UDRBaselineComparison(DependencyBaselineComparison):
    consumer_nf: str | None
    data_category: str | None
    masked_context_equal: bool | None

class ServiceRequirement(BaseModel):
    requirement_id: UUID
    service_name: str
    api_version: str | None = None
    endpoint: str | None = None
    consumer_nf: str | None = None
    required_by_stage: str | None = None
    optional: bool = False

class NFEntityReadiness(BaseModel):
    entity_id: UUID
    requirement_ids: list[UUID]
    service_name: str
    api_version: str | None
    endpoint: str | None
    status: Literal["ready", "not_ready", "partially_ready", "unknown"]
    missing_observations: list[MissingField] = Field(default_factory=list)
    evidence_ids: list[UUID]

class NFReadinessSnapshot(BaseModel):
    attempt_id: UUID
    frame: int
    requirements: list[ServiceRequirement]
    entities: list[NFEntityReadiness]
    status: Literal["ready", "not_ready", "partially_ready", "unknown"]
    available_entity_ids: list[UUID]
    unresolved_requirement_ids: list[UUID]
    missing_observations: list[MissingField] = Field(default_factory=list)
    evidence_ids: list[UUID]
```

`DependencyBaselineComparison` is the common base used by T23;
`UDRBaselineComparison` is its only specialization (T25). The two names in
earlier drafts referred to this single hierarchy.

NF readiness snapshots are keyed by `ServiceRequirement[]`, not by one global
NF state. T22 records each required service/version/endpoint tuple and then
aggregates matching `NFEntityReadiness` rows across eligible NF instances:
all required non-optional tuples ready -> `ready`; at least one required tuple
proven unavailable -> `not_ready`; mixed ready/missing/partial observations ->
`partially_ready`; insufficient visibility or selector ambiguity -> `unknown`.
Missing and partial observations stay attached to the affected requirement so
T23 can distinguish unavailable service from incomplete NRF evidence.

### 23.5 Report-facing support models

```python
class MaskedUEIdentity(BaseModel):
    ue_alias: str
    masked_forms: dict[str, str] = Field(default_factory=dict)

class ProblemDetailsSummary(BaseModel):
    status: int | None
    cause: str | None
    title: str | None
    detail_excerpt: str | None
    invalid_params: list[str] = Field(default_factory=list)
    parse_state: str

class MissingField(BaseModel):
    name: str
    reason_code: str
    visibility: str
    checked_event_ids: list[UUID]
    recoverable_via: Literal["T18", "T20", "none"]

class FieldDifference(BaseModel):
    field_name: str
    failed_value: JsonValue | None
    baseline_value: JsonValue | None
    category: str

class StageAlignment(BaseModel):
    stage_id: str
    occurrence: int
    status: Literal["matched", "changed", "missing_in_failed", "extra_in_failed", "not_comparable"]
    evidence_ids: list[UUID]

class EvidenceIntegrityReport(BaseModel):
    checked_evidence_count: int
    missing_evidence_ids: list[UUID] = Field(default_factory=list)
    corrupt_artifact_ids: list[UUID] = Field(default_factory=list)
    unresolved_source_refs: list[SourceRef] = Field(default_factory=list)
    status: Literal["valid", "warning", "failed"]

class GoldenNormalizationPolicy(BaseModel):
    policy_version: str
    normalize_uuid_fields: list[str]
    normalize_timestamp_fields: list[str]
    normalize_path_fields: list[str]
    normalize_duration_fields: list[str]
    normalize_provider_metadata: bool = True
    normalize_revision_digests: bool = True
```

The typed warning aliases that appear in tool contracts (`DecodeWarning`,
`NormalizationWarning`, `IdentityWarning`, `AttemptWarning`,
`DetectorWarning`) are all the single `Issue` model of section 26 carrying a
tool-scoped code namespace; they are type aliases, not separate classes.

### 23.6 Observability timing checklist

Every attempt publishes `StageTimingObservation` rows for the checklist below
when the relevant profile stage exists. Timings are stage observations, not
diagnoses; `absent`, `not_applicable` and `inconclusive` are distinct states.

| Timing key | Source anchor | Owner |
|---|---|---|
| `attempt.trigger` | first profile trigger event or explicit mid-capture basis | T04 |
| `request.first_ue_or_network_message` | NAS/NGAP initiating frame, paging trigger or network downlink trigger | T04/T05 |
| `dependency.first_primary_sbi` | first attempt-correlated primary SBI request/response | T06 |
| `pfcp.first_session_operation` | first mapped PFCP session or association operation | T08 |
| `access.first_resource_action` | NGAP resource/context setup, modify, release, handover or path-switch frame | T07 |
| `missing.deadline` | profile timeout deadline after predecessor/trigger | T09 |
| `terminal.outcome` | terminal success/failure/abort/timeout/capture-boundary frame | T04/T09 |
| `phase.window` | T21 core and expanded attempt interval | T21 |
| `dependency.recovery` | T22/T23 recovery or unresolved-at-attempt-start frame | T22/T23 |

Source anchors use frame numbers as the primary ordering key and decimal
timestamps only when present and validated. `not_applicable` means the
selected profile/stage condition is false; `absent` means the stage was
applicable but no matching event was observed with sufficient visibility;
`inconclusive` means capture bounds, visibility, identity or decoder state do
not support a positive or absent conclusion. T17 renders these timings in JSON
for every attempt and in Markdown for failed/incomplete attempts.

## 24. Evidence Registry

The evidence registry defines evidence identity once for the whole harness.
Evidence must resolve through T18 without T15 and without any model provider.

### 24.1 Canonical record

```python
class EvidenceRecord(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    evidence_id: UUID
    analysis_id: UUID
    record_type: str
    protocol: str | None
    source_event_ids: list[UUID]
    frames: list[int]
    source_refs: list[SourceRef]
    observed: dict[str, JsonValue]
    minted_by: str
    revision_scope: str

class EvidenceCapability(BaseModel):
    capability_id: UUID
    analysis_id: UUID
    scope: Literal[
        "primary_internal",
        "dependency_inspection",
        "report_drilldown",
        "packet_context",
        "targeted_redecode",
    ]
    holder_tool: str
    attempt_id: UUID | None = None
    request_id: UUID | None = None
    partition_allowlist: list[Literal["primary", "nrf", "udr"]]
    frame_bounds: FrameWindow | None = None
    selector_hash: str | None = None
    artifact_revision: str
    expires_at: datetime | None = None
```

`primary_internal` is the capability issued to T05 for local recovery of
fields from already assigned primary events. It allows only `primary` partition
source refs for the current attempt and cannot be exchanged for dependency
reader access. T18 validates capabilities after selector expansion and rejects
NRF/UDR access through direct evidence IDs, indexes, cursors or broadened
selectors unless the caller holds an approved dependency-inspection
capability.

### 24.2 Identity and minting

- `evidence_id = UUIDv5(analysis_id, canonical(sorted(source_event_ids)) +
  record_type + revision_scope)`.
- `revision_scope` is the revision (section 25) of the artifact generation the
  record belongs to, so re-extraction under changed config yields a new ID
  rather than silently rebinding an old one.
- The tool that first cites evidence mints the record at detection/extraction
  time through one shared helper in `evidence/registry.py`. T06-T09 mint for
  primary candidates; T05 for request provenance; T11/T14 for
  comparison/checkpoint citations; T22-T25 for dependency evidence; T19/T20
  register derived-context records. T15 selects and re-serializes existing
  records; it never mints.
- `record_type` values are registered semantic types (for example
  `http_transaction`, `nas_message`, `pfcp_transaction`, `stage_expectation`,
  `nf_lifecycle_event`, `udr_transaction`, `derived_context`,
  `derived_redecode`).

### 24.3 Storage, deduplication and resolution

- Records append to `evidence/registry/evidence_records.jsonl`; the storage
  layer maintains `indexes/evidence_index.jsonl` mapping `evidence_id` to
  byte offset, source events, source refs, artifact descriptor and revision.
- Minting the same identity twice is a no-op when the payload hash matches and
  an evidence-integrity error when it differs (collision with divergent
  content).
- T18 resolves `evidence_id -> evidence index -> source events/records`
  exactly as its section 7 chain describes, with the caller's revision or
  cursor envelope pinned to the same artifact generation. Report evidence
  references resolve in `provider=none` runs.
- Records are immutable once the owning generation publishes; superseding
  generations mint new IDs through `revision_scope`.
- Published evidence IDs remain resolvable for the run retention lifetime
  unless the run is quarantined for integrity failure. T18 rejects stale,
  cross-run or cross-revision evidence/cursor combinations instead of
  resolving them against the nearest available generation.

## 25. Revision Model

A revision identifies one immutable generation of a tool's output.

### 25.1 Envelope

```python
class RevisionEnvelope(BaseModel):
    revision: str
    tool: str
    tool_version: str
    schema_version: str
    config_hash: str
    policy_versions: dict[str, str]
    input_checksums: dict[str, str]
    parent_revisions: dict[str, str]
    created_in_stage: str
```

- `revision = "sha256:" + hex(sha256(canonical_serialization(envelope minus
  revision)))`. Canonical serialization is UTF-8 JSON with sorted keys and
  Decimal-as-string.
- Every artifact-producing tool exposes its `revision` in its result and
  manifest (this adds an explicit `revision: str` to results that predate the
  rule, including T04's `SegmentAttemptsResult`).
- Consumers record the exact input revisions they used in their own
  `parent_revisions`, which is how section 19.3 lineage validation works.

### 25.2 Rules

- Same inputs, configuration and versions produce byte-identical revisions on
  any supported machine.
- A producer never overwrites a published revision; changed
  inputs/config/policy create a sibling generation. Staging plus manifest-last
  publication (already required per tool) is the only legal publication
  sequence.
- Each tool mints its own revision; no caller mints on a tool's behalf. T01
  participates like every other tool: re-decoding into a run directory that
  already contains a published decode generation is rejected rather than
  merged.
- Compatibility: consumers must reject a parent revision whose
  `schema_version` they do not support, and must surface—not silently
  upgrade—mixed-generation lineages.
- External references such as evidence IDs, report links and cursor envelopes
  carry the exact artifact revision they were issued against. Reusing those
  references after a sibling generation is published is a stale-reference
  error, not an implicit upgrade.

## 26. Issue Registry

All machine-readable warnings and errors use one registered vocabulary.

```python
class Issue(BaseModel):
    code: str
    severity: Literal["info", "warning", "error", "critical"]
    stage: str
    attempt_id: UUID | None = None
    evidence_ids: list[UUID] = Field(default_factory=list)
    message: str
    retryable: bool = False
```

- Codes are uppercase snake case, namespaced by owning stage/tool prefix:
  `T02_VALUE_PARSE_FAILED`, `T02_AMBIGUOUS_DEPENDENCY_PARTITION`,
  `T15_TOKEN_BUDGET_BELOW_TARGET`, `T15_EVIDENCE_BUDGET_EXCEEDED`,
  `RUN_EVIDENCE_INTEGRITY`,
  `RUN_ACCESS_BOUNDARY`. Cross-tool recurring conditions own `RUN_`-prefixed
  codes so "evidence-integrity" and "access-boundary" are single codes
  everywhere.
- The registry lives at `harness/config/issue_registry.yaml`: code, owner,
  severity bounds, message template, remediation hint and aggregation
  behavior (whether repeated instances collapse in reports).
- Emitting an unregistered code is a validation error in tests (section
  21.1). Free-text human messages remain allowed; machine `code` values must
  be registered.
- Existing per-spec code mentions map onto this namespace
  (`VALUE_PARSE_FAILED -> T02_VALUE_PARSE_FAILED`, lowercase completion-state
  strings in T01/T06 are state values, not issue codes).

## 27. Run Manifest and Analysis State

### 27.1 Run manifest

`manifest.json` at the run root is the orchestrator's authoritative stage
ledger, written through staged updates and finalized last:

```python
class StageInvocation(BaseModel):
    stage_key: str
    tool: str
    scope: Literal["run", "attempt", "request", "internal"]
    attempt_id: UUID | None
    request_id: UUID | None
    status: str
    revision: str | None
    artifacts: list[ArtifactDescriptor]
    issues: list[Issue]
    started_at: datetime
    elapsed_ms: int

class RunManifest(BaseModel):
    schema_version: Literal["2.0"]
    analysis_id: UUID
    config_hash: str
    run_store_state: RunStoreState
    retention_policy: RetentionPolicy
    invocations: list[StageInvocation]
    selected_model_attempt_ids: list[UUID]
    skipped_model_attempt_ids: list[UUID]
    dependency_request_ledger: list[DependencyRequestOutcome]
    publication: Literal["in_progress", "finalized", "failed"]
```

`stage_key` matches the section 19.4 keys (`T12:primary`,
`T15:dependency_expanded`, nested T22/T23 invocations). Each invocation's
`status` uses its tool's documented status vocabulary; the manifest does not
flatten them into one enum.
`run_store_state` is the latest section 31 state snapshot at manifest
publication time; active lease details are omitted from final reports but
remain in the run-store journal.

### 27.2 Analysis state

`AnalysisState` is the validated in-memory aggregate T17 consumes; it is
assembled from published artifacts only:

```python
class AnalysisState(BaseModel):
    analysis_id: UUID
    manifest: RunManifest
    capture: CaptureMetadata
    attempts: list[ProcedureAttempt]
    requests: dict[UUID, UERequestResult]
    explicit_results: dict[UUID, ExplicitDetectorResults]
    missing_results: dict[UUID, DetectMissingTransitionsResult]
    timelines: dict[UUID, AttemptTimelineResult]
    comparisons: dict[UUID, CompareAttemptsResult]
    primary_roots: dict[UUID, RootCauseResult]
    expanded_roots: dict[UUID, RootCauseResult]
    scenario: ValidateScenarioResult | None
    dependency_results: dict[UUID, list[DependencyInspectionResult]]
    dependency_outcomes: dict[UUID, list[DependencyRequestOutcome]]
    diagnoses: dict[UUID, GenerateDiagnosisResult]
```

### 27.3 Run-status aggregation

Run status is derived from stage criticality, not from a universal stage
enum. T17 section 10 holds the canonical mapping; in summary: failure of a
critical chain stage (T01 unusable, storage publication, report write) makes
the run `failed`; partial/absent protocols, detector partials, scenario or
provider failures, rejected dependency requests and `unknown` phase visibility
make it `partial`; everything required complete makes it `success` even when
every analyzed call failed.

## 28. Model Narration Policy

Deterministic analysis always covers every persisted attempt. The narration
policy chooses which failed/incomplete attempts additionally receive model
passes:

1. When `--attempt` is supplied, narrate exactly those attempts (if eligible).
2. Otherwise, when `--ue` is supplied, restrict eligibility to that UE's
   failed/incomplete attempts.
3. Eligible attempts are ordered by `model_attempt_order`:
   `severity_then_first_frame` (default; highest deterministic primary
   severity, then earliest start frame), `first_frame`, or `last_frame`.
4. The first `max_model_attempts_per_run` attempts are selected. Ordering and
   selection are deterministic for identical inputs.

`model_attempt_selector.select(...)` in section 19.4 implements exactly this.
Selected and skipped attempt IDs are recorded in the run manifest, and T17
must disclose attempts that were analyzed deterministically but skipped by the
narration cap, including the policy values that caused the skip.

## 29. Configuration and Policy Resolver

All `*_version` strings (operation policies, cause dictionaries, timeout
tables, partition rules, protocol codepoint registry,
ranking/comparison/phase policies, profile registry, masking policy,
deployment resource profile and provider/model profile) are resolved once at
run startup into immutable handles:

```python
class ResolvedPolicy(BaseModel):
    name: str
    version: str
    schema_version: str
    sha256: str
    compatibility: list[str]
    payload: JsonValue

class ResolvedPolicySet(BaseModel):
    policies: dict[str, ResolvedPolicy]
    revision: str

class ResolvedProfileRegistry(BaseModel):
    registry_version: str
    schema_version: str
    sha256: str
    supported_releases: list[str]
    supported_deployments: list[str]
    registry: ProfileRegistry
    visibility_registry: VisibilityRegistry
```

- Resolution maps an explicit configured name/version to exactly one file
  under an allowlisted `harness/config/<kind>/` registry. It canonicalizes and
  checksums bytes, validates schema/version and declared tool compatibility,
  validates referenced child files, and rejects path traversal, duplicate
  names/versions or ambiguous aliases.
- Missing version, unreadable file, checksum mismatch, schema failure,
  incompatible tool/schema version, invalid cross-reference or corrupt child
  is a fatal startup configuration issue (`exit 2`). There is no fallback to
  latest/default after an explicit version and no lazy mid-run policy loading.
- Tools receive `ResolvedPolicy` handles via `DetectionContext.policies` or
  their request models; they never load files from bare version strings.
- T02 receives `ProtocolCodepointRegistry` and partition policy handles. T04
  receives `ResolvedProfileRegistry`; T11/T12/T13/T14/T21/T22/T23 receive
  purpose-specific `ResolvedPolicy` handles. T06-T09 read their exact handles
  from `DetectionContext.policies`. Provider setup receives
  `DeploymentResourceProfile` and model runtime handles. Payloads are
  immutable/read-only and cannot be refreshed during a run.
- The resolved set's name/version/checksum triples enter every revision
  envelope (`policy_versions`), making policy drift visible in lineage.
- `ResolvedPolicySet.revision` is the canonical digest of sorted
  name/version/schema/checksum/compatibility entries and is stored in the run
  manifest before T01 starts. Startup logs record identities only, never
  sensitive payload values.

### 29.1 Model limits and token-counter resolution

At startup the resolver combines `HarnessConfig`, the selected
provider/model profile, versioned prompts/schemas and a token-counter profile:

```python
class ResolvedModelRuntime(BaseModel):
    provider_config: ProviderConfig
    initial_budget: ResolvedTokenBudget
    final_budget: ResolvedTokenBudget
    model_profile_name: str
    model_profile_version: str
    model_profile_checksum: str
    prompt_revisions: dict[ModelPass, str]

    def budget_for(self, model_pass: ModelPass) -> ResolvedTokenBudget: ...
```

Resolution rules:

1. Resolve the provider/model context window, framing profile and maximum
   output from a schema-validated, checksummed model profile. Configuration may
   lower a limit but cannot raise the provider profile.
2. Resolve exactly one `TokenCounterSpec`. A pinned tokenizer requires exact
   tokenizer ID/version and vocabulary checksum. Missing/mismatched artifacts
   fail startup; the resolver never silently switches to fallback.
3. The deterministic fallback `utf8_bytes_v1` counts one token per byte of
   canonical UTF-8 JSON and is allowed only for model profiles whose
   conformance corpus proves it does not undercount.
4. Count each pass's exact versioned system prompt and response schema with the
   selected counter; add the profile's fixed provider-framing reserve.
5. Compute `effective_input_tokens` as the minimum of remaining context,
   `max_model_input_tokens` and the packet hard cap. Compute the soft target as
   the minimum of that value and `model_input_target_max_tokens`.
6. Validate positive limits and `target_min <= target_max <= hard_cap`.
   Non-positive remaining context or incompatible limits fail configuration.
7. Persist profile/counter/prompt identities and both resolved budgets in the
   run manifest. They enter T15 packet IDs and all T15/T16 revisions.

T15 receives the pass-specific budget directly; no tool recomputes it from
loose integers. T16 receives the matching provider config and rejects any
packet whose counter, budget, prompt revision or measured count differs. Token
usage reported by local/OpenRouter providers is retained separately for
observability and never changes deterministic trimming.

### 29.2 Deployment resource profiles

Resource profiles describe local execution constraints without making any
specific hardware model normative:

```python
class DeploymentResourceProfile(BaseModel):
    profile_name: str
    profile_version: str
    resource_class: Literal["cpu", "single_gpu", "multi_gpu", "remote"]
    max_concurrent_provider_calls: int
    recommended_model_classes: list[str]
    context_window_tokens: int | None = None
    quantization: str | None = None
    memory_floor_gb: Decimal | None = None
    benchmark_artifact: ArtifactDescriptor | None = None
```

The resolver may use a resource profile to cap local provider concurrency and
select compatible model-profile defaults. Benchmarks for particular
workstations or GPUs are retained as separate artifacts referenced by
`benchmark_artifact`; they do not change the harness contract.

## 30. Authenticated Cursor Envelope

Continuation cursors are opaque authorization-bearing references, not plain
pagination offsets. They are used by T10 timeline paging, T18 evidence lookup,
T19 context windows, T20 targeted re-decode result paging and report-side
drill-down APIs.

```python
class CursorPage(BaseModel):
    offset: int
    limit: int
    result_revision: str
    result_count_hint: int | None = None

class CursorEnvelope(BaseModel):
    cursor_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    scope: Literal[
        "attempt_timeline", "evidence_lookup", "packet_context",
        "targeted_redecode", "report_page"
    ]
    capability_id: UUID | None
    artifact_revision: str
    run_revision: str
    subject: dict[str, JsonValue]
    page: CursorPage
    issued_at: datetime
    expires_at: datetime | None
    nonce: str
    signature: str
```

The serialized cursor is `base64url(canonical_json(envelope minus signature))`
plus a detached signature. The signature is HMAC-SHA-256 with a run-local
signing key by default, or a configured asymmetric signer when cursors must
survive process boundaries. The signing key is never persisted in the run
directory.

Validation is fail-closed:

- `analysis_id`, `scope`, `capability_id`, `artifact_revision` and
  `run_revision` must match the current request and published artifact.
- Expired, tampered, cross-run, cross-scope, stale-revision and
  over-limit cursors are rejected with registered `Issue` codes.
- A cursor never grants broader access than the original capability. T10,
  T18, T19 and T20 reapply the original bounds and selectors before reading.
- Result ordering is part of `result_revision`; adding or removing records
  creates a new cursor lineage rather than rebinding an old cursor.

## 31. Run Lifecycle and Retention

The run store owns run-root allocation, writer leases, finalization,
retention and deletion. Analysis code writes only through `RunStore` helpers.

```python
class RunLease(BaseModel):
    lease_id: UUID
    owner: str
    acquired_at: datetime
    expires_at: datetime
    heartbeat_interval_seconds: int

class RetentionPolicy(BaseModel):
    retention_days: int | None
    legal_hold: bool = False
    preserve_source: bool = True
    preserve_reports: bool = True
    delete_after: datetime | None = None

class RunStoreState(BaseModel):
    analysis_id: UUID
    state: Literal[
        "allocating", "active", "finalizing", "finalized", "failed",
        "quarantined", "deleting", "deleted"
    ]
    created_at: datetime
    finalized_at: datetime | None
    retention_expires_at: datetime | None
    active_lease: RunLease | None
    retention_policy: RetentionPolicy
    state_revision: str
```

Lifecycle rules:

- `create` allocates a unique run root, creates a writer lease and writes an
  initial store-state record before any source copy.
- Only the active lease holder may publish artifacts or update `manifest.json`.
  Expired leases require explicit recovery that records the previous holder
  and validates every descriptor before continuing.
- `finalize` validates descriptors, evidence indexes, report artifacts and
  manifest lineage, then writes the final manifest last.
- `failed` and `quarantined` runs retain enough descriptors and logs for
  evidence-integrity diagnosis; they are not silently deleted.
- Deletion is legal only when no active lease exists, legal hold is false and
  retention has expired. Deletion itself is journaled and idempotent.
- Published evidence IDs, artifact revisions and cursor result revisions must
  remain resolvable for the retention lifetime unless a run is explicitly
  quarantined for integrity failure; T17 reports any retained-reference break.

## 32. Masking Policy

Masking is a versioned deterministic transform applied before evidence leaves
the local evidence boundary. Reports are masked by default; remote providers
are always masked.

```python
class MaskingPolicy(BaseModel):
    policy_version: str
    salt_ref: str
    remote_always_mask: bool = True
    local_unmasked_allowed: bool = False
    preserve_equality_within_run: bool = True
    masked_identifier_types: list[str]
    body_field_rules: dict[str, str]

class MaskingDecision(BaseModel):
    field_path: str
    action: Literal["keep", "mask", "hash", "drop", "excerpt"]
    reason_code: str
    policy_version: str
```

Identifier masking uses keyed HMAC with a per-policy salt reference and a type
prefix, for example `supi:mask_<digest>`. Equality is preserved within a run
and policy revision but masked values are not stable across unrelated salts.
SUPI, SUCI, GPSI, PEI, GUTI, UE IP addresses, subscriber-data keys,
authorization tokens, cookies and raw credentials are masked before remote
model evidence or report publication. Full retained records stay local and
are reachable only through bounded T18/T19/T20 capabilities.

`--unmasked-local-evidence` may affect local model packets only when
`provider="local"` and the resolved policy allows it. It never permits raw
secrets in persisted config, manifests, provider ledgers or reports.
`MaskingPolicy.policy_version` and its checksum enter evidence-packet,
provider-call and report revisions.

## 33. Canonical Numeric and Timestamp Semantics

All persisted deterministic artifacts use one canonical JSON profile:

```python
class CanonicalizationPolicy(BaseModel):
    policy_version: Literal["json_canonical_v2"] = "json_canonical_v2"
    decimal_mode: Literal["plain_string"] = "plain_string"
    datetime_zone: Literal["UTC"] = "UTC"
    object_key_order: Literal["lexicographic"] = "lexicographic"
```

Rules:

- `Decimal` values serialize as plain strings with no exponent, no binary
  float round-trip and no insignificant trailing zeros except the literal
  `"0"` where applicable.
- Frame numbers, byte offsets, counts and sizes are integers. Durations in
  public reports use integer milliseconds; sub-millisecond source times remain
  in event timestamps with precision metadata.
- `CanonicalEvent.timestamp` is absolute Unix-epoch decimal seconds when
  known. Source precision is recorded in `timestamp_precision`; absent or
  invalid source time leaves `timestamp=None` and ordering falls back to frame.
- Generated datetimes such as manifest, lease and cursor times are RFC 3339
  UTC values with `Z`; local timezone offsets are not persisted.
- Revision, cursor and deterministic UUID inputs use canonical JSON with
  sorted object keys, stable list order where order is semantic, and sorted
  member lists where the contract says order is not semantic.
- Golden normalization may replace generated datetimes, durations, UUIDs,
  paths and revision digests, but it must not alter source timestamps, frame
  order, candidate ordering, status values or evidence references.
