# T08 `find_pfcp_failures` Implementation Specification

## 1. Purpose

`find_pfcp_failures` detects N4/PFCP session-programming failures correlated to one UE procedure attempt. It covers explicit response rejection, timeout/retry exhaustion, session identity inconsistency, rule-programming defects, and tunnel mismatch with NGAP/session expectations.

T08 emits candidates. It does not rank them against NAS/NGAP/HTTP candidates.

## 2. Non-Goals

T08 must not:

- Treat routine PFCP heartbeat traffic as a session failure.
- Assume a changed SEID or TEID is invalid without scope and procedure context.
- Associate PFCP solely by timestamp.
- Read NRF/UDR partitions.
- Infer a missing response when capture visibility is insufficient.
- Validate full UPF packet forwarding/data-plane traffic. T08 validates
  control-plane programming and reported path failures only.

## 3. Inputs and Boundary

- One T04 attempt and related session/context identities.
- Attempt-assigned PFCP events from `PrimaryEventReader`.
- Relevant NGAP/NAS/primary SBI event summaries for consistency checks.
- The shared attempt-scoped `DetectionContext` (`LLD.md` section 11), carrying
  capture bounds (required for `request_only_capture_boundary` and timeout
  decisions), the T21 phase reader, reference-point/SBI visibility and the resolved
  PFCP message/cause/timeout policy handles.
- A revision-pinned T08 run-scoped PFCP node-state catalog containing
  association/heartbeat/recovery observations independent of attempts.

T08 consumes T02 canonical PFCP fields/IE summaries and source references. It
does not browse full records or request broad packet context; missing nested IE
semantics make a check inconclusive and remain available for later T19/T20.

## 4. Python Tool Contract

```python
class FindPFCPFailuresRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt: ProcedureAttempt
    attempts_revision: str
    primary_reader: PrimaryEventReader
    identity_graph: IdentityGraphReader
    node_state_catalog: PFCPNodeStateCatalogReader
    pfcp_event_ids: list[UUID]
    correlated_event_ids: list[UUID]
    context: DetectionContext
    run_dir: Path
    diagnostics_dir: Path
    max_issue_samples_per_code: int = 20
    fsync_outputs: bool = True


class FindPFCPFailuresResult(BaseModel):
    schema_version: Literal["2.0"]
    analysis_id: UUID
    attempt_id: UUID
    status: Literal["success", "partial", "failed"]
    revision: str
    manifest: ArtifactDescriptor
    artifacts: list[ArtifactDescriptor]
    candidates: list[FailureCandidate]
    transactions: list[PFCPTransactionGroup]
    association_observations: list[PFCPAssociationObservation]
    association_links: list[PFCPAssociationAttemptLink]
    session_reports: list[PFCPSessionReportObservation]
    consistency_checks: list[PFCPConsistencyResult]
    inspected_event_count: int
    warning_counts: dict[str, int]
    elapsed_ms: int
    issues: list[DetectorWarning]
```

T08 validates attempt/T02/T03/T04/T21 lineage, assigned event membership,
identity/catalog/phase reader revisions, capture bounds and resolved PFCP
message/cause/timeout/scoring policies. Per-attempt outputs resolve to
`normalized/diagnostics/<attempt-id>/T08`; path escape is fatal.

### 4.1 Run-scoped node-state catalog contract

```python
class BuildPFCPNodeStateCatalogRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    normalization: NormalizeEventsResult
    primary_reader: PrimaryEventReader
    capture: CaptureMetadata
    policies: ResolvedPolicySet
    run_dir: Path


class BuildPFCPNodeStateCatalogResult(BaseModel):
    schema_version: Literal["2.0"]
    analysis_id: UUID
    revision: str
    manifest: ArtifactDescriptor
    observations: ArtifactDescriptor
    node_pair_index: ArtifactDescriptor


class PFCPNodeStateCatalogReader(Protocol):
    @property
    def revision(self) -> str: ...
    def for_node_pair(self, node_pair_id: UUID, start: int, end: int) -> list[PFCPAssociationObservation]: ...
```

The orchestrator/T08 adapter ensures this catalog once after T02 and before
parallel per-attempt T08 calls. It scans primary PFCP Association Setup/Update/
Release and heartbeat/recovery events only, publishes under
`normalized/diagnostics/pfcp_node_state/`, and indexes node-pair availability
independently of UE attempts. Observation IDs are global to the run/catalog
revision; per-attempt T08 results reference them rather than duplicating a
node-level candidate across attempts.

## 5. PFCP Transaction Model

```python
class PFCPTransactionGroup(BaseModel):
    transaction_id: UUID
    message_family: str
    request_event_id: UUID | None
    response_event_id: UUID | None
    retransmission_event_ids: list[UUID]
    sequence_number: int | None
    request_frame: int | None
    response_frame: int | None
    local_node: str | None
    remote_node: str | None
    cp_seid: str | None
    up_seid: str | None
    outcome: Literal[
        "accepted", "rejected", "timed_out", "reset_or_transport_error",
        "request_only_capture_boundary", "unpaired", "unknown"
    ]
    pairing_confidence: Literal["high", "medium", "low"]
    pairing_reasons: list[str]

class PFCPAssociationObservation(BaseModel):
    observation_id: UUID
    node_pair_id: UUID
    local_node: str | None
    remote_node: str | None
    message_family: Literal[
        "association_setup", "association_update", "association_release",
        "heartbeat"
    ]
    request_event_id: UUID | None
    response_event_id: UUID | None
    outcome: Literal[
        "accepted", "rejected", "timed_out", "released",
        "restart_detected", "recovered", "unknown"
    ]
    recovery_timestamp_before: Decimal | None
    recovery_timestamp_after: Decimal | None
    availability: Literal["available", "unavailable", "degraded", "unknown"]
    evidence_ids: list[UUID]

class PFCPAssociationAttemptLink(BaseModel):
    link_id: UUID
    observation_id: UUID
    attempt_id: UUID
    affected_session_ids: list[UUID]
    relation: Literal[
        "selected_node_pair", "used_session", "supporting_only", "unrelated", "unknown"
    ]
    causal_status: Literal["causally_reachable", "recovered_before_attempt", "not_reachable", "inconclusive"]
    evidence_ids: list[UUID]

class PFCPSessionReportObservation(BaseModel):
    report_id: UUID
    request_event_id: UUID
    response_event_id: UUID | None
    report_type: Literal[
        "error_indication", "user_plane_path_failure", "downlink_data",
        "usage", "session_report", "unknown"
    ]
    seid: str | None
    f_teids: list[str]
    mapped_attempt_id: UUID | None
    relevance: Literal["attempt_failure_evidence", "observation", "unrelated", "inconclusive"]
    evidence_ids: list[UUID]
```

Resolved PFCP policy payloads define request/response family pairs, accepted /
retryable causes, timeout/retry bounds, association/report classifications,
rule-programming requirements, tunnel-role checks, severity and score terms.
Validation rejects duplicate/ambiguous keys, invalid message/cause ranges,
negative timeouts, unknown profile facts, executable predicates and
incompatible checksums. T08 never loads the YAML paths named later in this
document directly.

## 6. Transaction Pairing Algorithm

Pair in descending evidence strength:

1. T01/T02 explicit `response_to` frame/reference.
2. Same endpoint pair, PFCP sequence, and request/response message family.
3. Same scoped SEID/session plus sequence and bounded time.
4. Endpoint/message family/time fallback with low confidence.

Pairing rules must account for:

- Sequence reuse after validity window.
- Requests before a UP SEID exists.
- Responses carrying newly allocated UP SEID.
- Retransmissions with same sequence.
- Direction reversal.
- Node restart/recovery timestamp changing validity.

Ambiguous pairing remains explicit; T08 must not force the nearest response.

Pairing implementation:

1. Sort PFCP events by `(frame,event_id)` and partition by canonical endpoint
   pair, direction and message family.
2. Apply explicit response links first, validating family and direction.
3. Group retransmissions with equal scoped sequence/request semantics before
   looking for a response.
4. Evaluate remaining candidate responses by the four evidence tiers above,
   then frame distance, response frame and event UUID.
5. Accept only a unique highest tier. Equal best candidates produce an
   `unpaired` low-confidence group plus `T08_PAIRING_AMBIGUOUS`.
6. Derive outcome from response cause, reset metadata, timeout policy and
   capture visibility. PFCP observed `unknown` remains `outcome="unknown"` and
   is never renamed diagnostic `inconclusive`.

Transaction IDs use T08 revision, endpoint-pair alias, sequence/family,
request event or first response event and validity epoch. Sequence reuse after
restart/deletion creates a new epoch.

## 7. Association and Node-State Observations

Association Setup, Update, Release and heartbeat/recovery evidence is indexed
by PFCP node pair independently of UE attempts. T08 records rejection,
timeout, explicit release, restart/recovery timestamp discontinuity and
availability as `PFCPAssociationObservation`.

An association observation emits an attempt-scoped candidate only when the
attempt selected or used that node pair through a strong T03/T04/T08 link and
the node observation is causally reachable before the failed PFCP/session
stage. Otherwise it remains a node observation or supporting evidence. T08
must not create one node-level candidate shared directly by multiple attempts;
each affected attempt gets its own candidate only after association evidence
passes that attempt's association rules.

Association candidate scoring uses `relevance="unresolved_infrastructure"` and
records whether availability was unavailable, degraded or unknown at the
attempt stage. Recovery before the attempt suppresses a failure candidate and
is retained as recovery evidence.

Catalog construction groups events by normalized unordered node-pair identity,
tracks recovery-timestamp epochs and derives availability intervals in frame
order. A discontinuity closes prior active associations/sessions and opens a
new epoch; it does not by itself create an attempt candidate. Per-attempt T08
queries only node pairs linked through T03 PFCP sessions/selected endpoints,
persists `PFCPAssociationAttemptLink`, and creates a candidate only for
`causally_reachable` unavailable/degraded evidence before the affected stage.

## 8. Explicit Rejection Detection

Emit a candidate when response Cause is not accepted for the message family. Preserve:

- Numeric cause and standardized label.
- Offending IE when present.
- Request/response frames.
- Session/node identity.
- Failed rule IDs and relevant IE paths.

Unknown cause values remain usable and produce a dictionary warning.

## 9. Timeout and Retransmission Detection

- Group retransmissions into one transaction.
- Use message-family timeout policy and capture timestamps.
- `timed_out` requires visible interval beyond timeout and no accepted/rejected response.
- Capture end before timeout yields `request_only_capture_boundary`, not failure.
- Repeated request followed by accepted response is recovered retry evidence.
- Retry exhaustion emits one candidate with all retry frames.

## 10. Session and SEID Validation

Detect:

- Unknown session response/cause.
- Response SEID incompatible with request/session state.
- Modification/deletion before establishment without capture-boundary explanation.
- Same active SEID mapped to incompatible session identities.
- Old SEID used after explicit deletion/recovery restart.

SEID value changes during new establishment, relocation, or node restart may be valid and require profile/state context.

## 11. Rule Programming Validation

For establishment/modification, check semantic presence/consistency when applicable:

- PDR and FAR references resolve.
- QER/URR references resolve when required.
- Apply Action is compatible with forwarding/buffering intent.
- Outer Header Creation/Removal has required endpoint/tunnel fields.
- UE IP and network instance/DNN are present when required.
- QFI and QoS rule mapping is internally consistent.
- Created/updated/removed rule IDs do not contradict session state.

These are targeted semantic checks, not complete PFCP specification validation.

## 12. PFCP Session Report Handling

Session Report Request/Response is UPF-initiated evidence. T08 classifies
reports by report type and mapped session:

- Error Indication and user-plane path failure become potential
  attempt-scoped candidates only when reported SEID, F-TEID, UE IP/session
  identity or linked PFCP session maps to the attempt.
- Downlink Data, Usage and other routine reports are observations unless a
  profile/cause policy explicitly declares them failure-relevant for the
  stage.
- Request without response follows report-specific timeout policy; capture
  boundary yields an inconclusive observation, not an inferred failure.
- Report acceptance/rejection is recorded separately from whether the report
  proves user-plane failure.

Reports may support reachability-loss and mobile-terminated delivery findings
when profile timing shows paging/service response or user-plane activation was
causally reachable.

Report classification first uses explicit report-type IEs, then the resolved
message/cause policy. Mapping order is PFCP session node/SEID, directional
F-TEID plus endpoint, UE IP plus DNN/slice, then no mapping. Routine Downlink
Data/Usage stays `observation` unless one named policy rule and applicable
profile stage promotes it. An unmapped report never becomes attempt evidence
merely because its frame overlaps the attempt.

## 13. NGAP/PFCP Tunnel Consistency

```python
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

Checks include:

- NGAP downlink N3 transport address/TEID versus PFCP FAR Outer Header
  Creation for the downlink path.
- PFCP-created uplink PDR/F-TEID versus NGAP/session expectation for uplink
  user-plane path.
- QFI/resource mapping.
- UE IP/DNN/session mapping.
- Handover target tunnel versus PFCP path update.
- N9/inter-UPF intermediate tunnel roles when the selected profile declares
  them applicable.

During handover, compare against target/path-switch values only after the
profile's target-activation stage. Do not compare a new target tunnel to
obsolete source tunnel values, and do not flag source/target coexistence
during a legal transition window. Old-path deletion after target activation is
cleanup; target path programming failure before activation can still be
primary when it causes handover failure.

Consistency checks are generated from profile-declared stage/role pairs, not a
single static TEID equality rule. Normalize endpoint addresses/TEIDs with
direction and validity epoch; compare only role-compatible values active at
the check stage. Missing visibility/role facts yield `inconclusive`, false
profile conditions yield `not_applicable`, and only a contradictory visible
pair yields `inconsistent`. Check IDs use T08 revision, attempt/session, check
type, stage and sorted evidence IDs.

## 14. Mobility and Handover Handling

- Expected source/target tunnels may coexist during transition.
- Old-path deletion after successful switch is cleanup.
- Target path programming failure before Handover Failure may be primary.
- PFCP failure after radio success/path switch may explain post-handover traffic failure.
- Inter-UPF/N9 complexity is checked only when visible and profile-applicable,
  using profile-declared intermediate tunnel roles.

## 15. Heartbeat and Node Recovery

Heartbeats are routine and produce no session candidate by default. They may support a node-unavailable candidate only when:

- Heartbeat/recovery timestamp establishes restart/unavailability.
- Same PFCP node/session is used by the attempt.
- A session operation fails or times out consistently.

T08 must not diagnose node failure from a single missing heartbeat without
policy and correlation evidence. Heartbeat/recovery evidence should update the
node-pair association observation and only become an attempt candidate through
the association rules in section 7.

## 16. Candidate Categories and Scoring Inputs

Suggested bases:

- Explicit non-accepted response: `0.95`.
- Association rejection or unrecovered association timeout for a selected
  node pair: `0.90`.
- Session Report Error Indication or user-plane path failure mapped to the
  attempt: `0.85`.
- Request timeout after visible window: `0.80`.
- Strong SEID/session inconsistency: `0.75`.
- Directional tunnel/rule inconsistency: `0.75-0.90` based on explicitness,
  profile stage and source/target/N9 role.
- Recovered retry: penalty/no terminal candidate.
- Downlink Data, Usage or other non-failure Session Reports: observation only
  unless profile/cause policy promotes them.
- Low pairing confidence or capture boundary: penalty.
- Cleanup operation after terminal attempt: cleanup penalty in T12.

Store all score terms and rule IDs. Per `LLD.md` section 4.6, T08 assigns
`severity` from its rule table, resolves `capture_phase` through
`context.phase_reader`, publishes `call_impact="inconclusive"`, and mints
cited evidence through the evidence registry (`LLD.md` section 24). Published
candidates are immutable.

For every explicit detector hit T08 mints `pfcp_transaction`,
`pfcp_association_state`, `pfcp_session_report` or `pfcp_consistency_check`
evidence from sorted primary source events/refs and T08 revision. Candidate
score is the canonical-decimal sum of one base plus named cause, pairing,
retry, mapping, stage, visibility, assignment, capture and cleanup terms,
clamped to `[0,1]`. Severity/phase/relevance are detector-owned and call impact
is always inconclusive. Candidate IDs use T08 revision, attempt ID, rule ID,
transaction/report/check or association-link ID and failed semantic item.

## 17. Attempt Association

Association requires at least one strong session signal:

- T03 PFCP session node linked to attempt session.
- CP/UP SEID within validity interval.
- SBI SM context to PFCP correlation.
- UE IP/DNN/slice plus stage-compatible transaction and endpoint.
- NGAP tunnel match plus session identity.
- Selected/used PFCP association node pair for node-state candidates.
- Session Report SEID/F-TEID/UE-IP mapping for report candidates.

Timestamp proximity alone is insufficient.

## 18. Persistence and Deterministic IDs

The run-scoped catalog publishes:

```text
normalized/diagnostics/pfcp_node_state/
  association_observations.jsonl
  node_pair_index.jsonl
  pfcp_node_state_manifest.json
```

Each per-attempt detector publishes:

```text
normalized/diagnostics/<attempt-id>/T08/
  failure_candidates.jsonl
  pfcp_transactions.jsonl
  pfcp_association_links.jsonl
  pfcp_session_reports.jsonl
  pfcp_consistency.jsonl
  pfcp_failures_manifest.json
staging/T08-<scope>-<uuid>/
```

Per-attempt `association_observations` in the result are the referenced catalog
records; they are not rewritten into the attempt directory. The common
diagnostic aggregator consumes T08 descriptors after T06-T08 finish.

Catalog revision inputs are T02 revision/source checksum, PFCP
message/cause/association/timeout policy checksums, capture bounds and
tool/schema version. Per-attempt T08 revision inputs add T03/T04/attempt/event
identity, node-state catalog revision, T21 phase revision, visibility /
assignment confidence, scoring/tunnel/profile policy identities and
output-affecting config.

Shared descriptors provide verifiable counts, parent checksums and the owning
catalog/T08 revision. Empty files publish. Manifests record lineage/policies,
counts by outcome/cause/report/check/link/relevance, artifacts, sampled issues
and timing/resource metrics.

### 18.1 Runner and publication invariants

The catalog runner validates T02/policies/paths, returns an identical existing
revision, streams all primary PFCP node-state events, derives epochs/intervals,
mints evidence, builds the node-pair index/descriptors/manifest and publishes
manifest last. Per-attempt T08 validates all lineage/readers, loads assigned
PFCP plus correlated assigned primary summaries, pairs transactions, queries
linked catalog node pairs, classifies reports, evaluates state/rules/tunnels,
mints candidates/evidence, writes descriptors/manifest and publishes last.

Validation proves unique IDs; no event appears in incompatible transactions;
explicit links outrank inferred pairing; `unknown` remains observed outcome;
catalog observations are attempt-independent; every attempt association has a
strong link and causal status; routine reports/heartbeats produce no candidate
without named promotion/correlation; tunnel roles are directional/stage-aware;
scores equal terms; evidence resolves; sensitive identifiers are masked;
indexes/descriptors/counts/checksums/revisions agree.

## 19. Failure Semantics

- Unknown attempt/event: validation error.
- Mixed/stale T02-T04/T21/catalog lineage, incompatible policy or path escape:
  fatal with no manifest.
- Ambiguous pairing: retain unpaired/ambiguous group, warn, lower confidence.
- Missing IE tree: explicit outer cause remains usable; semantic checks become inconclusive.
- Association observation cannot be linked to the attempt: retain as node
  observation, no candidate.
- Session Report cannot be mapped to attempt SEID/F-TEID: retain as
  observation/inconclusive, no candidate.
- Unknown cause/message: preserve raw value and continue.
- Capture boundary before timeout: no timeout candidate.
- Source/evidence checksum mismatch: evidence-integrity failure for the
  affected check and fatal when consistent evidence identity cannot be kept.
- Rule exception: quarantine affected transaction and mark partial.

Ambiguous pairing, observed `unknown`, unmapped reports, inconclusive checks
and unrelated node observations are represented outcomes, not partial status.
Partial means a transaction/item was skipped or evidence lost. Fatal errors
preserve prior catalog/attempt revisions.

## 20. Performance and Resource Requirements

- O(PFCP events + scoped consistency checks).
- Index by endpoint pair, node pair, sequence, SEID, F-TEID and session node.
- Keep only active/unpaired transactions in memory.
- Avoid all-pairs tunnel comparisons.
- Record events/sec, active transactions, pairing ambiguity, retries,
  consistency checks, catalog lookups and latency.

## 21. Security and Privacy

- Primary capability only.
- Do not log UE IP, DNN, SEID, TEID, or raw IEs; log hashed/scoped IDs.
- Full PFCP records remain local.
- Treat IE text/values as untrusted.
- Bound nested IE materialization.
- T08 has no dependency/evidence-browsing capability; evidence references only
  T02 primary events and catalog records derived from primary PFCP events.

## 22. Observability

Logs include attempt, transaction, association observation, session report,
message family, pairing rule/confidence, outcome, candidate/check ID, cause
category, tunnel role and warning code.

Metrics include rejected/timed-out transactions, association failures,
restart discontinuities, session reports by relevance, retry
recovery/exhaustion, pairing ambiguity, directional tunnel inconsistencies,
heartbeat-supported node failures, and detector latency.

Minimum registered codes are `T08_PAIRING_AMBIGUOUS`, `T08_UNKNOWN_CAUSE`,
`T08_PARTIAL_IE_SUMMARY`, `T08_TRANSACTION_QUARANTINED`,
`T08_ASSOCIATION_LINK_INCONCLUSIVE`, `T08_REPORT_UNMAPPED`,
`T08_TUNNEL_CHECK_INCONCLUSIVE` and `T08_OUTPUT_INVARIANT_FAILED`; shared
access/evidence violations use `RUN_ACCESS_BOUNDARY` and
`RUN_EVIDENCE_INTEGRITY`.

## 23. Proposed Python Code Structure

```text
V2/harness/analysis/
  pfcp.py
  pfcp_pairing.py
  pfcp_timeouts.py
  pfcp_session_state.py
  pfcp_association.py
  pfcp_session_reports.py
  pfcp_rules.py
  pfcp_consistency.py
  pfcp_mobility.py
V2/harness/config/
  pfcp_messages.yaml
  pfcp_causes.yaml
  pfcp_timeouts.yaml
V2/harness/models/
  pfcp.py
  failures.py
```

## 24. Implementation Sequence

1. Define transaction/consistency schemas and cause tables.
2. Implement explicit response pairing and rejection detection.
3. Add retransmission/timeout handling.
4. Add association/node-state observation indexing.
5. Add Session Report classification and attempt mapping.
6. Add SEID/session-state validation.
7. Add rule programming checks.
8. Add directional NGAP/PFCP tunnel consistency and mobility branches.
9. Add heartbeat/recovery support and performance tests.
10. Add run-scoped catalog and per-attempt revision/descriptor publication.

## 25. Tests

### 25.1 Unit tests

- Explicit, sequence-based, and ambiguous pairing.
- Sequence/SEID reuse and validity intervals.
- Accepted/rejected/unknown causes.
- Association Setup/Update/Release accepted/rejected/timed-out/recovered and
  recovery timestamp discontinuity.
- Session Report Error Indication/user-plane path failure mapping and
  non-failure report preservation.
- Timeout, capture boundary, retry recovery/exhaustion.
- PDR/FAR/QER/URR reference checks.
- Directional tunnel/QFI/UE-IP consistency, including uplink/downlink roles.
- Deterministic IDs and score terms.
- Catalog epoch/availability derivation and attempt-link causality.
- Policy validation and PFCP unknown-versus-diagnostic-inconclusive boundary.
- Descriptor/manifest/evidence resolution determinism.

### 25.2 Integration tests

- PDU establishment rejected by PFCP then NAS reject.
- PFCP timeout with and without sufficient capture.
- Association failure before an attempt and during an attempt.
- Modification unknown session.
- Session Report path failure after establishment.
- Downlink Data/Usage report without failure promotion.
- Handover target PFCP path update failure.
- Successful path switch followed by old-path cleanup.
- N9/inter-UPF directional tunnel variant.
- Node restart/recovery timestamp and session failure.
- Multiple concurrent PFCP sessions with reused sequence values.
- T18 resolves every catalog/check/candidate evidence ID before T15.
- Identical catalog/attempt reruns return the same revisions; policy/context
  changes create siblings.

### 25.3 Negative tests

- Heartbeat traffic alone does not create call failure.
- Node association observation does not create a shared multi-attempt candidate.
- Expected handover TEID change is not inconsistency.
- Source/target handover coexistence before cleanup is not inconsistency.
- Timestamp proximity alone does not associate PFCP.
- Session Report with unmapped SEID/F-TEID is not attempt evidence.
- T08 cannot access NRF/UDR partitions.
- Unmapped node/report evidence cannot create an attempt candidate through
  timestamp overlap.
- Stale catalog/T04/T21 revisions, unassigned events, corrupt descriptors,
  executable policies and symlink escape publish no manifest.
- Clear UE IP/DNN/SEID/TEID/raw IE values do not appear in logs/issues/manifests.

### 25.4 Golden tests

- Stable catalog observations/epochs/index and per-attempt transactions,
  association links, reports, checks, candidates, evidence and manifests.
- Golden fixtures cover association reject/recovery, timeout boundary, report
  failure/routine report, SEID reuse, directional N3/N9 roles and handover
  source/target coexistence.

## 26. Acceptance Criteria

T08 is complete when:

1. PFCP requests/responses/retries are paired with explicit confidence.
2. Explicit rejection and timeout semantics respect capture visibility.
3. Association/node-state observations are indexed independently and derive
   attempt candidates only through selected/used node-pair evidence.
4. Session Reports are classified and only failure-relevant mapped reports
   become candidates.
5. SEID and rule-programming checks are scoped to valid session state.
6. NGAP/PFCP consistency uses the correct directional role, procedure stage
   and target/source/N9 path.
7. Heartbeat/recovery evidence is supporting, not automatically causal.
8. Every candidate/check cites exact PFCP and correlated evidence.
9. Candidate score terms are available to T12.
10. Primary-only access is enforced.
11. PFCP observed `unknown` remains distinct from diagnostic `inconclusive`.
12. Run-scoped catalog and per-attempt artifacts pass section 18.1 and are
    immutable/parallel-safe.

## 27. Mechanical Implementation Checklist

1. Define catalog/request/result/transaction/association/report/check models.
2. Register T08 issue and evidence record types.
3. Validate resolved PFCP message/cause/timeout/association/report/tunnel
   policy payloads and checksums.
4. Build catalog revision from T02/capture/policies and return an identical
   generation when present.
5. Stream primary association/heartbeat events and derive node-pair epochs,
   availability and recovery discontinuities.
6. Mint catalog evidence, build node-pair index/descriptors/manifest and
   publish manifest last.
7. Validate per-attempt T02/T03/T04/T21/catalog lineage and assignments.
8. Build per-attempt T08 revision and staging path.
9. Load assigned PFCP and correlated primary summaries only.
10. Pair requests/responses/retransmissions by section 6 without nearest-match
    forcing.
11. Derive accepted/rejected/timeout/reset/boundary/unpaired/unknown outcomes.
12. Query only strongly linked catalog node pairs and build causal attempt links.
13. Detect explicit rejection, timeout/retry exhaustion and SEID state errors.
14. Validate PDR/FAR/QER/URR/programming summaries when visible.
15. Classify/map Session Reports and preserve routine/unmapped observations.
16. Build profile/stage/direction-aware N3/N9 tunnel consistency checks.
17. Apply handover activation/coexistence/cleanup rules.
18. Build canonical score terms, candidates, phase/relevance and evidence.
19. Write every per-attempt JSONL output including empty files.
20. Validate section 18.1 IDs, pairing, mapping, role, privacy, evidence,
    descriptor and count invariants.
21. Build/publish per-attempt manifest last and preserve siblings.
22. Add unit/integration/negative/security/golden tests from section 25.
