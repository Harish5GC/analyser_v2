# T07 `find_nas_ngap_failures` Implementation Specification

## 1. Purpose

`find_nas_ngap_failures` detects explicit UE-facing NAS failures and NGAP access/resource/mobility failures for one attempt. It also identifies terminal UE effects that may be downstream of an earlier SBI, PFCP, or access failure.

T07 emits candidates and terminal-effect metadata. T12 performs final root-cause ranking.

## 2. Non-Goals

T07 must not:

- Treat every NAS reject as the primary root cause.
- Emit implicit missing-transition or missing-response candidates. T09 is the
  sole owner of implicit absence detection (including its `0.65`
  missing-response base score). T07 records an initiating message whose
  expected outcome is absent as a request-only observation/terminal-effect
  input for T09, never as its own candidate.
- Read NRF/UDR partitions.
- Decode encrypted NAS beyond fields exposed by T02.
- Apply user scenario expectations.
- Rank cross-protocol candidates.

## 3. Inputs and Boundary

Inputs:

- One T04 `ProcedureAttempt`.
- Attempt-assigned NAS and NGAP events from `PrimaryEventReader`.
- The applicable procedure profile.
- The shared attempt-scoped `DetectionContext` (`LLD.md` section 11), carrying
  capture bounds, the T21 phase reader, reference-point/SBI visibility, assignment
  confidence and the resolved NAS/NGAP cause-dictionary handles.

T07 consumes canonical T02 fields and source references only. It does not open
retained decoder trees, perform broad context lookup or invoke T18/T20 during
detection. Missing transfer/container semantics remain explicit partial
evidence that T19/T20 may inspect later under their own capabilities.

## 4. Python Tool Contract

```python
class FindNASNGAPFailuresRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt: ProcedureAttempt
    attempts_revision: str
    primary_reader: PrimaryEventReader
    event_ids: list[UUID]
    profile: ProcedureProfile
    context: DetectionContext
    run_dir: Path
    diagnostics_dir: Path
    max_issue_samples_per_code: int = 20
    fsync_outputs: bool = True


class FindNASNGAPFailuresResult(BaseModel):
    schema_version: Literal["2.0"]
    analysis_id: UUID
    attempt_id: UUID
    status: Literal["success", "partial", "failed"]
    revision: str
    manifest: ArtifactDescriptor
    artifacts: list[ArtifactDescriptor]
    candidates: list[FailureCandidate]
    terminal_effects: list[TerminalEffect]
    request_only_observations: list[RequestOnlyObservation]
    inspected_event_count: int
    warning_counts: dict[str, int]
    elapsed_ms: int
    issues: list[DetectorWarning]
```

T07 validates analysis/attempt/profile identity, T04 revision, assigned event
membership, `DetectionContext` IDs/bounds/phase revision and resolved cause /
scoring policy checksums. The injected primary reader must be the T02 ancestor
of the attempt. Output paths resolve to
`normalized/diagnostics/<attempt-id>/T07`; traversal/symlink escape is fatal.

```python
class RequestOnlyObservation(BaseModel):
    observation_id: UUID
    attempt_id: UUID
    event_id: UUID
    expected_stage_ids: list[str]
    frame: int
    reason_codes: list[str]
    evidence_ids: list[UUID]
```

These records carry initiating explicit evidence to T09. They are not failure
candidates and never receive T09's implicit-absence score.

## 5. NAS Failure Observation

```python
class NASFailureObserved(BaseModel):
    domain: Literal["5GMM", "5GSM"]
    message_type: str
    cause_code: int | None
    cause_name: str | None
    cause_category: str | None
    pdu_session_id: int | None
    pti: int | None
    registration_type: str | None
    service_type: str | None
    frame: int
    encrypted_or_partial: bool
```

Cause dictionaries preserve numeric code, standardized label, standards release/profile, and source field path. Unknown causes remain numeric with `cause_name=UNKNOWN_<code>`.

The resolved cause payload maps `(domain,message/procedure,cause)` to label,
category, severity, detector base score, compatibility and source citation.
Validation rejects duplicate/overlapping keys without explicit precedence,
invalid code ranges, executable predicates and incompatible release/schema
checksums. Unknown values use a registered generic rule without modifying the
resolved dictionary.

## 6. NGAP Failure Observation

```python
class NGAPFailureObserved(BaseModel):
    procedure_code: int | None
    procedure_name: str
    outcome_type: Literal["unsuccessful", "error_indication", "non_delivery", "other"]
    cause_category: str | None
    cause_value: str | int | None
    failed_pdu_session_ids: list[int]
    failed_qfis: list[int]
    transport_or_radio_details: dict[str, JsonValue]
    frame: int
```

## 7. NAS Detection Rules

### 7.1 Registration and mobility management

Detect:

- Registration Reject.
- Service Reject.
- Deregistration Request/Accept patterns that unexpectedly terminate an active attempt.
- Configuration Update/Notification failures when profile-defined.
- Authentication Failure/Reject.
- Security Mode Reject or failed security establishment.
- Identity response failure/missing identity only when explicit failure is represented.
- UL/DL NAS Transport failure indications.

### 7.2 Session management

Detect:

- PDU Session Establishment Reject.
- PDU Session Modification Reject/Command failure.
- PDU Session Release Reject or unexpected network release during active establishment.
- 5GSM Status indicating protocol/state error.

### 7.3 Cause interpretation

Cause categories include subscription/policy restriction, authentication/security, slice/DNN/service not supported, congestion/resources, protocol/state, mobility/roaming restriction, and unspecified.

Interpretation is descriptive; ownership is not inferred solely from category.

## 8. NGAP Detection Rules

Detect:

- Unsuccessful outcomes for applicable NGAP procedures.
- Error Indication with correlated UE/session/procedure.
- NAS Non Delivery Indication.
- Initial Context Setup Failure.
- UE Context Modification Failure.
- PDU Session Resource Setup/Modify/Release unsuccessful transfer/list items.
- Handover Preparation Failure, Handover Failure, unsuccessful Path Switch, and failed rollback/cancel.
- Context transfer or AMF relocation failures when explicit.
- Transport/network/radio cause details relevant to the failed resource.

One NGAP message may contain successes and failures for different PDU sessions. Emit candidates scoped to failed item/session, not the whole UE attempt indiscriminately.

### 8.1 Detection algorithm

1. Load only assigned NAS/NGAP primary events in `(frame,event_id)` order and
   validate their T02/T04 lineage.
2. Project each event into the typed NAS or NGAP observation. Invalid optional
   fields emit an issue; an explicit outer failure remains usable.
3. Evaluate registered explicit detector rules in rule-ID order. T07 never
   creates a candidate solely because a response/stage is absent.
4. For NGAP list/transfer outcomes, expand one semantic item per failed
   session/resource in source order, then sort by PDU session ID, QFI and
   ordinal. Success items remain observations but create no failure candidate.
5. Validate T03/T04 access/session association and profile stage. Reject hard
   mismatches; apply a score penalty to low-confidence assignment.
6. Build terminal effects and request-only observations independently from
   candidate creation.
7. Mint evidence, score terms and deterministic IDs, then classify phase,
   relevance, cleanup and initial downstream metadata.

Candidate IDs use T07 revision, attempt ID, rule ID, source event ID, failed
item/session key and semantic ordinal. Item expansion never treats one failed
resource as failure of every session in the message.

## 9. Resource Item Scoping

For NGAP lists/transfers:

- Extract each PDU session ID and result independently.
- Link failure to T04 session context.
- Preserve transfer-container decode warnings.
- If only one session failed while another succeeded, emit one scoped candidate and a mixed-outcome warning.

QFI/resource failures are associated only when the source IE explicitly links them.

## 10. Terminal Effect Model

```python
class TerminalEffect(BaseModel):
    terminal_effect_id: UUID
    event_id: UUID
    candidate_id: UUID | None
    effect_type: Literal[
        "UE_REJECT", "NGAP_UNSUCCESSFUL", "CONTEXT_RELEASE", "DEREGISTRATION"
    ]
    terminal_for_attempt: bool
    frame: int
    downstream_possible: bool
    correlation_keys: dict[str, str]
    evidence_ids: list[UUID]
```

Correlation keys contain only masked/scoped aliases. Request-only observations
may have terminal metadata without a candidate ID; terminal effects tied to an
explicit failure reference that candidate.

NAS reject and NGAP unsuccessful outcome are strong terminal evidence. They remain eligible candidates but are tagged so T12 can demote them when an earlier supported cause explains them.

## 11. Upstream and Downstream Rules

T07 marks a terminal event `downstream_possible=true` when:

- It follows a correlated primary SBI/PFCP/NGAP candidate.
- It rejects/releases the same session/context.
- Cause/category is compatible with the earlier failure.
- Profile stage ordering supports propagation.

T07 does not require an upstream candidate to exist and does not perform final downstream classification; T12 evaluates all candidates.

## 12. Context Release and Deregistration

- Normal release after successful procedure: no candidate.
- Release after an already failed procedure: cleanup/downstream candidate only when abnormal.
- Unexpected release during active establishment/service/handover: candidate.
- Network deregistration caused by subscription/security failure may be terminal; cite initiating cause.
- Implicit deregistration/context expiry requires explicit evidence; absence alone belongs to T09.

## 13. Mobility and Handover Rules

- Distinguish preparation, execution, path-switch, and rollback stages.
- Successful rollback after failed target preparation is recovery evidence, not another primary failure.
- Failed rollback/cancel is a secondary severe candidate.
- Xn handover may be visible only at Path Switch Request; missing preparation is not a failure when N2 preparation was not expected/visible.
- Inter-AMF IDs must use T03 validity/mapping evidence.
- Handover cause applies to the appropriate source/target fault domain when inferable.

## 14. Visibility and Encryption

Visibility states:

- `visible`: message family and required fields decoded.
- `partial`: protocol visible but cause/container missing.
- `encrypted_or_unparsed`: NAS present but not semantically decoded.
- `not_captured`.

Explicit outer NGAP failure remains usable when embedded NAS is encrypted. Missing NAS reject cannot be inferred from encrypted traffic.

## 15. Attempt Association

Validate supplied events using:

- AMF/RAN UE IDs and validity intervals.
- PDU session ID/PTI.
- Profile stage and parent/child attempt.
- Explicit NGAP response/request relation.

Low-confidence T04 assignment produces a candidate ambiguity penalty. Timestamp proximity alone is insufficient.

## 16. Candidate Categories and Scoring Inputs

Suggested base values:

- NGAP unsuccessful outcome with cause: `0.95`.
- Explicit NAS reject with cause: `0.90`.
- NAS Non Delivery/Error Indication: `0.85`.
- Explicit 5GMM/5GSM Status protocol/state failure: `0.80`.
- Cause missing/partial: confidence penalty.
- Terminal event after supported upstream cause: downstream penalty applied by T12.
- Capture/interface ambiguity: penalty.

T07 has no missing-response base score: the `0.65` implicit-absence base
belongs exclusively to T09, which consumes T07's request-only observations.

Store each score term and rule ID. Scores are ranking inputs, not
probabilities. Per `LLD.md` section 4.6, T07 assigns `severity` from its rule
table, resolves `capture_phase` through `context.phase_reader`, publishes
`call_impact="inconclusive"`, and mints cited evidence through the evidence
registry (`LLD.md` section 24). Published candidates are immutable.

For each explicit rule hit, T07 mints a `nas_failure`, `ngap_failure`,
`ngap_resource_failure` or `terminal_effect` evidence record from sorted source
events/refs and T07 revision. Score is the canonical-decimal sum of one base
term and named cause/explicitness/assignment/visibility/capture/downstream /
cleanup terms, clamped to `[0,1]`. Candidate order is frame, profile stage
order, failed item key, rule priority and UUID. Every evidence ID must resolve
through T18 before T15 in provider-none runs.

## 17. Cause Dictionary Management

Cause tables are resolver-owned data files, not detector-loaded switches:

```text
V2/harness/config/causes/
  nas_5gmm.yaml
  nas_5gsm.yaml
  ngap.yaml
```

Each entry records code/value, label, category, applicable message/procedure, standards release/source note, and whether vendor overrides are allowed.

Unknown values must not fail detection.

T07 reads immutable cause handles from `context.policies`; it never opens these
paths or refreshes dictionaries mid-run.

## 18. Persistence and IDs

T07 publishes one immutable per-attempt detector generation:

```text
normalized/diagnostics/<attempt-id>/T07/
  failure_candidates.jsonl
  terminal_effects.jsonl
  request_only_observations.jsonl
  nas_ngap_failures_manifest.json
staging/T07-<attempt-id>-<uuid>/
```

The common diagnostic aggregator consumes descriptors after T06-T08 finish;
parallel detectors never append to shared files.

T07 revision inputs are T04/attempt payload revision, assigned event IDs/T02
revision, profile ID/checksum, T21 phase revision, detection visibility /
assignment confidence, cause/scoring policy checksums, tool/schema version and
output-affecting limits. Descriptors have types `nas_ngap_failure_candidates`,
`terminal_effects`, `request_only_observations` and
`nas_ngap_failures_manifest`, verifiable counts, T04 parent checksum and T07
revision. Empty JSONL files are published.

### 18.1 Runner and publication invariants

The runner validates lineage/policies/paths, returns an existing identical
revision when present, stages under `staging/T07-*`, loads assigned events,
projects observations, expands failed resource items, evaluates explicit
rules, mints evidence, writes outputs/descriptors/manifest, validates, and
publishes the manifest last.

Before publication prove unique candidate/effect/request-observation IDs;
assigned-primary membership; one failed-item candidate per semantic item;
terminal references and masked correlation keys; no implicit-absence candidate;
score=sum(terms), phase/severity/relevance ownership and inconclusive call
impact; evidence resolution; canonical ordering; descriptor/count/checksum
agreement; and no clear identity/location/payload data.

## 19. Failure Semantics

- Unknown attempt/event: validation error.
- Event outside primary partition: reject.
- Mixed/stale T02/T04/T21 lineage, incompatible profile/cause policy or path
  escape: fatal with no T07 manifest.
- Unsupported NAS/NGAP message: warn and continue.
- Unknown cause: preserve numeric/raw cause and continue.
- Transfer/container decode missing: partial candidate if outer failure is explicit.
- Missing/corrupt source reference: evidence-integrity warning and lower
  confidence when explicit normalized evidence remains; fatal when evidence
  identity cannot be resolved consistently.
- Rule exception for one event: quarantine event and mark detector partial.

Unknown causes, encrypted NAS with usable outer NGAP failure, request-only
observations and represented ambiguity are valid results. Partial means an
event/item was skipped or evidence was lost. Fatal errors preserve prior
revisions and publish no manifest.

## 20. Performance and Resource Requirements

- O(NAS+NGAP events in attempt).
- No full-capture scans.
- Decode cause tables once per process/version.
- Do not materialize full containers. Preserve partial outer evidence and
  source refs for later authorized T19/T20 inspection.
- Record events/sec, candidates, item-level failures, unknown causes, partial
  containers and elapsed time.

## 21. Security and Privacy

- Primary events only.
- Do not log NAS identities, payloads, or location values.
- Candidate summaries use masked UE/session identifiers.
- Treat cause/detail strings as untrusted.
- Full NAS trees remain local and are not automatically model evidence.
- T07 has no evidence-browsing or dependency capability; emitted evidence can
  cite only assigned primary source events/refs.

## 22. Observability

Logs include attempt, profile, event/candidate ID, message/procedure, cause code category, terminal-effect flag, and warning code.

Metrics include NAS rejects by type/category, NGAP unsuccessful outcomes, resource-item failures, terminal effects, encrypted/partial NAS, unknown causes, and latency.

Minimum registered codes are `T07_UNSUPPORTED_MESSAGE`, `T07_UNKNOWN_CAUSE`,
`T07_PARTIAL_CONTAINER`, `T07_MIXED_RESOURCE_OUTCOME`,
`T07_ASSIGNMENT_AMBIGUOUS`, `T07_EVENT_QUARANTINED` and
`T07_OUTPUT_INVARIANT_FAILED`; shared access/evidence violations use
`RUN_ACCESS_BOUNDARY` and `RUN_EVIDENCE_INTEGRITY`.

## 23. Proposed Python Code Structure

```text
V2/harness/analysis/
  nas_ngap.py
  nas_failures.py
  ngap_failures.py
  ngap_resource_items.py
  terminal_effects.py
  mobility_failures.py
  cause_dictionary.py
V2/harness/config/causes/
  nas_5gmm.yaml
  nas_5gsm.yaml
  ngap.yaml
V2/harness/models/
  failures.py
  nas.py
  ngap.py
```

## 24. Implementation Sequence

1. Define observation and terminal-effect models.
2. Implement NAS reject/status rules and cause tables.
3. Implement NGAP unsuccessful/error/non-delivery rules.
4. Add item-level PDU resource extraction.
5. Add release/deregistration and downstream metadata.
6. Add mobility/handover branches and visibility handling.
7. Add deterministic evidence/persistence, compatibility and security fixtures.

## 25. Tests

### 25.1 Unit tests

- 5GMM/5GSM reject messages and known/unknown causes.
- Authentication/security/status failures.
- NGAP unsuccessful, Error Indication, and NAS Non Delivery.
- Mixed successful/failed PDU resource items.
- Terminal-effect tagging and deterministic candidate IDs.
- Visibility/encryption behavior.
- Cause dictionary versioning.
- Item expansion ordering/deduplication and request-only observation behavior.
- Score/evidence/candidate/effect/revision determinism.
- Resolved cause-policy rejection and descriptor/manifest validation.

### 25.2 Integration tests

- SBI/PFCP cause followed by NAS reject.
- Explicit NAS reject with no upstream visibility.
- Initial context/PDU resource failure.
- Network deregistration during active call.
- Xn path-switch-only visibility.
- N2 preparation/execution failure and successful rollback.
- Inter-AMF context mapping and failure.
- Encrypted NAS with explicit NGAP failure.
- T09 consumes request-only observations without duplicate T07 candidates.
- T18 resolves every emitted evidence ID before T15 in provider-none mode.
- Identical rerun returns the same revision; cause/profile/context change
  creates a sibling.

### 25.3 Negative tests

- Normal context release after success is not a failure.
- Successful rollback is not primary failure.
- Failure for one PDU session does not mark another failed session.
- T07 cannot access NRF/UDR partitions.
- Missing expected response/stage alone never creates a T07 candidate.
- Stale attempt/phase revision, unassigned event, corrupt descriptor,
  executable cause policy and symlink escape publish no manifest.
- Clear identities/location/container payloads do not appear in outputs/issues/logs.

### 25.4 Golden tests

- Byte-stable candidates, effects, request-only observations, evidence IDs,
  descriptors and manifest for NAS reject, NGAP item failure, handover failure,
  encrypted NAS/outer failure and mixed-resource fixtures.
- Golden normalization removes generated timings only, preserving frames,
  causes, item scope, scores, phase/relevance and evidence IDs.

## 26. Acceptance Criteria

T07 is complete when:

1. Explicit NAS and NGAP failure families are detected with exact cause/frame evidence.
2. Item-level NGAP failures are scoped to the correct PDU session/resource.
3. Terminal UE effects are explicitly tagged for T12.
4. Upstream-versus-downstream metadata is preserved without premature ranking.
5. Encryption and reference-point/SBI visibility prevent false conclusions.
6. Mobility preparation, execution, path switch, and rollback are distinguished.
7. Cause dictionaries are versioned and unknown values remain usable.
8. Primary-only access is enforced.
9. T07 emits no implicit-absence candidate and provides deterministic
   request-only observations for T09.
10. Every evidence/artifact passes section 18.1 and per-attempt output is safe
    under parallel T06-T08 execution.

## 27. Mechanical Implementation Checklist

1. Define request/result/NAS/NGAP/effect/request-only models with shared types.
2. Register T07 issue and evidence record types.
3. Validate attempt/profile/context IDs, T02/T04/T21 lineage and assignments.
4. Validate per-attempt T07 paths and create staging only.
5. Validate resolved NAS 5GMM/5GSM, NGAP and scoring policy payloads.
6. Build T07 revision and return an existing identical generation when valid.
7. Load only assigned primary NAS/NGAP events in deterministic order.
8. Project typed observations while preserving unknown numeric causes.
9. Evaluate explicit NAS rules only; create request-only rows for absent-outcome
   inputs rather than failure candidates.
10. Evaluate explicit NGAP unsuccessful/error/non-delivery rules.
11. Expand resource lists into correctly scoped failed items.
12. Validate T03/T04 identity/session/access/profile-stage association.
13. Build terminal effects and initial downstream/cleanup metadata.
14. Build canonical score terms, severity, phase, relevance and call impact.
15. Mint deterministic candidates/evidence/effects/request observations.
16. Write all JSONL files including empty outputs.
17. Validate membership, item scoping, no implicit candidates, privacy,
   evidence, descriptors and counts.
18. Build manifest with lineage/policy identities and sampled issues.
19. Publish evidence/data then manifest last; preserve sibling generations.
20. Add unit/integration/negative/security/golden tests from section 25.
