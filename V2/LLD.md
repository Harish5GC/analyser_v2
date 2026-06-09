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
  --include-nrf-success
  --include-udr-success
  --unmasked-local-evidence
  --decoder-binary PATH
  --config PATH
  --log-level LEVEL
```

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
    model_timeout_seconds: int = 120
    temperature: float = 0.1
    max_model_input_tokens: int = 12000
    max_model_output_tokens: int = 2000
    dependency_lookup_mode: Literal["model_requested"] = "model_requested"
    max_dependency_requests_per_attempt: int = 2
    dependency_context_frames_before: int = 100
    dependency_context_frames_after: int = 100
    mask_remote_evidence: bool = True
    attempt_idle_timeout_seconds: float = 30.0
    retention_days: int | None = None
    context_frames_before: int = 20
    context_frames_after: int = 20
    max_context_frames: int = 500
    max_full_record_bytes: int = 10_000_000
```

Precedence:

```text
CLI argument > environment variable > YAML config > default
```

Validation rules:

- `openrouter` requires model and populated API-key environment variable.
- `local` requires base URL and model.
- `none` ignores model settings.
- Remote evidence masking cannot be disabled for OpenRouter in V2.1.

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
    src: str | None
    dst: str | None
    direction: Literal["UE_TO_NETWORK", "NETWORK_TO_UE", "NF_TO_NF", "UNKNOWN"]
    message_type: str
    outcome: Literal["request", "success", "failure", "notification", "unknown"]
    identifiers: EventIdentifiers
    attributes: dict[str, JsonValue]
    raw_refs: list[SourceRef]
```

`timestamp` is normalized to seconds from capture epoch when available. Frame order is the deterministic fallback.

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
    confidence: float
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

Confidence thresholds:

- `>= 0.90`: automatic link.
- `0.70-0.89`: link with warning.
- `< 0.70`: candidate only; do not merge UE contexts.

### 4.5 Procedure attempt

```python
class ProcedureAttempt(BaseModel):
    attempt_id: UUID
    ue_id: UUID
    procedure: ProcedureType
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
    detector_score: float
    capture_phase: str
    relevance: Literal["attempt_related", "dependency_related", "startup_background", "concurrent_background", "post_call_background", "unresolved_infrastructure"]
    call_impact: Literal["causal", "contributing", "unrelated", "inconclusive"]
```

### 4.7 Root-cause result

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

class NFReadinessSnapshot(BaseModel):
    attempt_id: UUID
    frame: int
    instances: list[NFInstanceReadiness]
    unresolved_failures: list[UUID]

class BackgroundImpact(BaseModel):
    candidate_id: UUID
    attempt_id: UUID
    call_impact: Literal["causal", "contributing", "unrelated", "inconclusive"]
    recovery_frame: int | None
    rationale_codes: list[str]
    evidence_ids: list[UUID]
```

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

Required message maps include:

- `0x41`: Registration Request.
- `0x42`: Registration Accept.
- `0x44`: Registration Reject.
- `0x4c`: Service Request where applicable to decoder naming.
- `0x4d`: Service Reject.
- `0xc1`: PDU Session Establishment Request.
- `0xc2`: PDU Session Establishment Accept.
- `0xc3`: PDU Session Establishment Reject.
- PDU session modification and release message types.

Mappings must be table-driven and tested against fixture trees. Unknown message codes remain events with `message_type = "NAS_UNKNOWN_<code>"`.

### 6.3 NGAP normalization

NGAP normalizer emits the NGAP procedure event and invokes the NAS normalizer for every `NAS_PDU_tree` or `pDUSessionNAS_PDU_tree`. Embedded NAS events inherit the outer NGAP frame and identifiers.

### 6.4 PFCP normalization

PFCP requests and responses are initially linked by `response_to`, then by sequence number, endpoints and time when `response_to` is absent.

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

Artifact layout:

```text
source/capture.pcap
decoded/raw/<protocol>.packets.jsonl
decoded/full/http2/streams/<stream-document-uuid>.json
decoded/full/http2/stream_index.jsonl
decoded/full/ngap/messages.jsonl
decoded/full/ngap/message_index.jsonl
decoded/full/pfcp/messages.jsonl
decoded/full/pfcp/message_index.jsonl
decoded/decoder_manifest.json
normalized/events.jsonl
normalized/primary_events.jsonl
normalized/nrf_events.jsonl
normalized/udr_events.jsonl
indexes/frame_index.json
indexes/stream_index.json
indexes/nrf_index.json
indexes/udr_index.json
indexes/artifact_index.json
evidence/context/<query-id>.jsonl
evidence/redecode/<query-id>.jsonl
```

Each artifact index entry contains path, checksum, size, record count, format, creation stage and parent source checksum.

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

`RedecodeQuery` accepts structured fields only:

```python
class RedecodeQuery(BaseModel):
    start_frame: int
    end_frame: int
    display_filter: str | None
    protocol_trees: list[str]
    fields: list[str]
    decode_as: list[DecodeAsRule]
```

The implementation builds `tshark` arguments directly without a shell, limits the frame range, validates protocol/field names and enforces timeout/output-size limits.

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

Definitions are declarative:

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
class VisibilityRequirement(BaseModel):
    interface: Literal["N1", "N2", "N4", "N8", "N10", "N11", "N12", "N15", "N16", "N22", "N27", "N40", "Nnrf", "N9", "Xn"]
    evidence_matchers: list[EventMatcher]
    required_for_missing_stage_failure: bool
```

The engine derives `observed`, `not_observed` or `unknown` per interface. A missing mandatory stage becomes `inconclusive` unless its interface is observed or the scenario/capture metadata explicitly guarantees visibility.

### 10.4 Profile selection

Profile scoring uses:

1. Explicit NAS registration/request type.
2. NGAP procedure family.
3. Access type and PLMN/topology evidence.
4. Presence of handover/path-switch messages.
5. Emergency indication or emergency DNN.
6. Scenario constraints.

Observed protocol evidence has precedence over scenario wording. Profiles within `0.10` of the highest score remain alternatives until later stages disambiguate them.

### 10.5 Registration profiles

Registration attempts share a parent definition but have distinct stage sets:

- Initial: authentication/security and initial context are expected when required.
- Mobility update: old-context transfer, location update and session-context update are conditional.
- Periodic update: context validation and Registration Accept are central; full authentication is optional.
- Emergency: emergency policy and limited-service variants apply.
- Non-3GPP: access-specific context and identifiers remain separate from 3GPP access.

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
```

Home-routed profiles expect V-SMF/H-SMF and home/visited path stages only when visible. Local-breakout profiles must not flag absent H-SMF or N9 activity. Failure candidates are assigned a fault domain: `UE`, `RAN`, `VISITED_CORE`, `HOME_CORE`, `INTER_PLMN`, `UPF_PATH` or `UNKNOWN`.

### 10.9 Mobility profile correlation

Mobility attempts use identifier validity intervals. When AMF/RAN IDs change, the old and new identities are linked through context-transfer events, handover messages, PDU session IDs, security context and time proximity. An identifier reused after its validity interval must not link unrelated UEs.

PFCP tunnel changes during handover are expected. The consistency detector compares the target NGAP tunnel with resulting PFCP FAR/PDR updates rather than comparing against source tunnel values.

## 11. Detector Interfaces

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
- Request timeout: base `0.80`.
- Session/SEID inconsistency: base `0.75`.

Scores rank candidates but do not represent statistical probability.

## 12. Root-Cause Ranking Algorithm

For each candidate:

```text
rank_score = detector_score
           + explicit_failure_bonus
           + cross_protocol_explanatory_bonus
           + baseline_divergence_bonus
           - downstream_penalty
           - cleanup_penalty
           - ambiguous_correlation_penalty
           - incomplete_capture_penalty
```

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

Baseline selection:

1. Same UE.
2. Same procedure.
3. Successful outcome.
4. Highest request-signature similarity.
5. Nearest earlier attempt by frame.

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

## 14. Scenario Models

```python
class ScenarioSpec(BaseModel):
    original_text: str
    target_procedure: str | None
    expected_outcome: Literal["success", "failure"] | None
    constraints: dict[str, JsonValue]
    checkpoints: list[ScenarioCheckpoint]

class ScenarioCheckpoint(BaseModel):
    checkpoint_id: str
    description: str
    protocol: str | None
    matcher: EventMatcher | StateMatcher
    required: bool = True

class CheckpointResult(BaseModel):
    checkpoint_id: str
    status: Literal["verified", "failed", "inconclusive", "not_applicable"]
    observed: JsonValue | None
    evidence_ids: list[UUID]
    reason: str
```

The scenario parser prompt must explicitly return `null` for unspecified values. The validator, not the model, decides checkpoint status.

## 15. Evidence Packet

```python
class EvidencePacket(BaseModel):
    schema_version: Literal["2.0"]
    pass_stage: Literal["initial", "dependency_expanded"]
    analysis_id: UUID
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

The initial packet cannot contain detailed NRF or UDR events. A dependency-expanded packet may contain only validated outputs from `inspect_nrf_flow` or `inspect_udr_flow`. The final packet must still satisfy the configured token budget.

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
    api_key=config.api_key or "local-no-key",
    timeout=config.model_timeout_seconds,
)
```

The gateway first requests JSON-schema response format when supported. If rejected by the endpoint, it falls back to JSON-only prompting and local Pydantic validation.

One repair retry is allowed with only the validation errors and previous response. No protocol evidence is expanded during repair.

## 17. Model Diagnosis Contract

```python
class DependencyEvidenceRequest(BaseModel):
    tool: Literal["inspect_nrf_flow", "inspect_udr_flow"]
    attempt_id: UUID
    reason_code: Literal[
        "DISCOVERY_FAILURE_SUSPECTED",
        "NF_REGISTRATION_OR_READINESS_SUSPECTED",
        "SCP_ROUTING_OR_SELECTION_SUSPECTED",
        "SUBSCRIBER_DATA_FAILURE_SUSPECTED",
        "DEPENDENCY_TIMEOUT_SUSPECTED",
    ]
    rationale: str
    frame_start: int
    frame_end: int
    nf_type: str | None = None
    service_name: str | None = None
    nf_instance_id: str | None = None
    consumer_nf: str | None = None
    resource_or_operation: str | None = None

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
class AnalysisReport(BaseModel):
    schema_version: Literal["2.0"]
    analysis_id: UUID
    status: Literal["success", "partial", "failed"]
    capture: CaptureMetadata
    decoder: DecoderManifest
    ue_results: list[UEResult]
    scenario: ScenarioResult | None
    provider: ProviderMetadata | None
    warnings: list[str]
    timings: dict[str, float]
```

`UEResult` contains all attempts. Each failed attempt contains deterministic root cause, model diagnosis when available, timeline and evidence.

## 19. Orchestrator Pseudocode

```python
def analyze(request: AnalysisRequest) -> AnalysisReport:
    run = run_store.create(request)
    retained_pcap = run_store.retain_source(request.pcap_path, run.source_dir)
    decoder_result = decoder_runner.decode(
        DecodeCaptureRequest(
            analysis_id=run.analysis_id,
            retained_pcap_path=retained_pcap,
            run_dir=run.path,
            decoder_binary=config.decoder_binary,
            timeout_seconds=config.decoder_timeout_seconds,
        )
    )

    event_writer = PartitionedJsonlEventStore(run.normalized_dir)
    for normalizer, source in decoder_sources(decoder_result):
        for event in normalizer.iter_events(source):
            event_writer.append(partition_router.route(event))
    event_writer.finalize()

    primary_reader = event_store_factory.open_primary_reader(run.normalized_dir)
    dependency_executor = dependency_tool_factory.create_executor(
        normalized_dir=run.normalized_dir,
        evidence_repository=evidence_repository,
        config=run.config,
    )

    identities = identity_graph.build(primary_reader)
    attempts = attempt_engine.segment(primary_reader, identities)
    phases = phase_classifier.classify(primary_reader, attempts)

    failures = []
    comparisons = {}
    roots = {}
    for attempt in attempts:
        events = primary_reader.for_attempt(attempt.attempt_id)
        failures.extend(detector_registry.detect(attempt, events))
        if attempt.outcome != "succeeded":
            comparisons[attempt.attempt_id] = comparator.compare(attempt, attempts)
            roots[attempt.attempt_id] = ranker.rank(
                attempt, failures, comparisons[attempt.attempt_id]
            )

    scenario_spec = scenario_parser.parse(request.scenario) if request.scenario else None
    scenario_results = scenario_validator.validate(
        scenario_spec, attempts, primary_reader
    )

    diagnoses = {}
    for failed_attempt in selected_failed_attempts(attempts, request):
        packet = initial_evidence_builder.build(
            failed_attempt, roots, comparisons, scenario_results
        )
        if provider.enabled:
            initial = provider.generate_diagnosis(packet)
            dependency_results = dependency_executor.execute(
                requests=initial.dependency_evidence_requests,
                attempt=failed_attempt,
                initial_packet=packet,
            )

            if dependency_results:
                final_packet = expanded_evidence_builder.build(
                    packet, dependency_results
                )
                diagnoses[failed_attempt.attempt_id] = provider.generate_final_diagnosis(
                    final_packet
                )
            else:
                diagnoses[failed_attempt.attempt_id] = initial

    report = report_builder.build(...)
    run_store.write_report(report)
    return report
```

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
- HTTP `ProblemDetails`, missing response and retry detection.
- PFCP cause and request/response pairing.
- Identity graph confidence and conflict handling.
- Attempt segmentation with reused PDU session IDs.
- Retry versus new-attempt decisions.
- State transition completion and missing stages.
- Root-cause downstream/cleanup classification.
- Baseline selection and first divergence.
- Evidence token-budget trimming.
- Full-record lookup by event, frame and stream.
- Pre/post context windows containing correlated and uncorrelated packets.
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
- Interface visibility preventing false missing-stage failures.
- Capture preamble, active and postamble classification with overlapping UE attempts.
- Benign NF deregistration `404` followed by successful registration before a call.
- Unresolved NF registration failure promoted only when the call uses that NF/service.
- Concurrent unrelated NRF errors excluded despite occurring during an active call.
- NRF/UDR partitions are inaccessible to primary detectors and the initial evidence builder.
- Dependency request validation, window clamping, selector requirements and duplicate rejection.
- Final model-pass requests are rejected to prevent recursive lookup loops.

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
29. 3GPP/non-3GPP access registration and mobility kept separate.
30. Home-routed roaming registration/session success and home-network failure.
31. Local-breakout roaming session without false H-SMF/N9 missing-stage errors.
32. Roaming restriction, unsupported slice and inter-PLMN routing failure.
33. UE-initiated and network-initiated deregistration.
34. Normal context release and cleanup after an earlier failure.
35. A normalized event omits a required body field and full-record lookup recovers it.
36. Root cause requires packets before and after the explicit failure frame.
37. Initial decoder output lacks a protocol tree and targeted re-decode recovers it.
38. Retained artifact checksum mismatch causes an evidence-integrity warning/failure.
39. Capture starts before NFs; the model requests NRF inspection and recovered deregistration `404` responses remain background only.
40. NF registration fails before the call; a call-flow discovery symptom triggers NRF inspection and the unresolved state is linked to the attempt.
41. NRF startup errors exist, but the model makes no dependency request and no NRF records enter model evidence.
42. A UDM-facing subscriber-data error triggers bounded UDR inspection and reveals the causal UDR failure.
43. The model requests capture-wide NRF/UDR data and the validator rejects or clamps the request.
44. A final-pass dependency request is rejected and does not create a third model pass.

### 21.3 Golden reports

Store expected deterministic `report.json` files for fixture captures. Model prose is not golden-tested. Tests validate model schema and evidence references only.

## 22. Implementation Sequence

1. Add Go decoder output-directory support, retain the source PCAP, and emit checksummed raw/full HTTP/NAS/PFCP artifacts plus indexes.
2. Implement canonical models, partitioned JSONL store, NRF/UDR indexes and protocol normalizers.
3. Implement identity graph and attempt segmentation.
4. Add the scenario-profile registry and initial, mobility, periodic, emergency and non-3GPP registration profiles.
5. Add service request, paging, PDU lifecycle, mobility, handover, roaming, deregistration and NF-dependency profiles.
6. Implement primary protocol detectors and root-cause ranking without NRF/UDR partition access.
7. Implement the dependency request validator, NRF inspector, UDR inspector and bounded second model pass.
8. Add baseline comparison and bounded timeline.
9. Add scenario parser/validator.
10. Add evidence builder and privacy masking.
11. Add OpenAI-compatible provider and deterministic fallback.
12. Add reports, CLI, fixtures and golden integration tests.

No model integration should begin before canonical events, attempts and deterministic failure candidates are testable.
