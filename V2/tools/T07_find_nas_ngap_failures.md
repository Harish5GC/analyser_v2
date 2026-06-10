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
- Decode encrypted NAS beyond fields exposed by T02/T18.
- Apply user scenario expectations.
- Rank cross-protocol candidates.

## 3. Inputs and Boundary

Inputs:

- One T04 `ProcedureAttempt`.
- Attempt-assigned NAS and NGAP events from `PrimaryEventReader`.
- The applicable procedure profile.
- The shared attempt-scoped `DetectionContext` (`LLD.md` section 11), carrying
  capture bounds, the T21 phase reader, interface visibility, assignment
  confidence and the resolved NAS/NGAP cause-dictionary handles.

The detector may read exact full evidence through T18 for fields already referenced by assigned events, but cannot perform broad context lookup or re-decode.

## 4. Python Tool Contract

```python
class FindNASNGAPFailuresRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt: ProcedureAttempt
    event_ids: list[UUID]
    profile: ProcedureProfile
    context: DetectionContext


class FindNASNGAPFailuresResult(BaseModel):
    schema_version: Literal["2.0"]
    attempt_id: UUID
    candidates: list[FailureCandidate]
    terminal_effects: list[TerminalEffect]
    inspected_event_count: int
    warnings: list[DetectorWarning]
```

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
    event_id: UUID
    candidate_id: UUID
    effect_type: Literal[
        "UE_REJECT", "NGAP_UNSUCCESSFUL", "CONTEXT_RELEASE", "DEREGISTRATION"
    ]
    terminal_for_attempt: bool
    frame: int
    downstream_possible: bool
    correlation_keys: dict[str, str]
```

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

## 17. Cause Dictionary Management

Cause tables are data files, not hard-coded switch statements where avoidable:

```text
V2/harness/config/causes/
  nas_5gmm.yaml
  nas_5gsm.yaml
  ngap.yaml
```

Each entry records code/value, label, category, applicable message/procedure, standards release/source note, and whether vendor overrides are allowed.

Unknown values must not fail detection.

## 18. Persistence and IDs

Candidates use deterministic UUIDv5 from attempt ID + detector rule + source event + failed item/session ordinal.

Common candidate storage is used:

```text
normalized/diagnostics/failure_candidates.jsonl
normalized/diagnostics/terminal_effects.jsonl
```

## 19. Failure Semantics

- Unknown attempt/event: validation error.
- Event outside primary partition: reject.
- Unsupported NAS/NGAP message: warn and continue.
- Unknown cause: preserve numeric/raw cause and continue.
- Transfer/container decode missing: partial candidate if outer failure is explicit.
- Missing full evidence reference: evidence-integrity warning and lower confidence.
- Rule exception for one event: quarantine event and mark detector partial.

## 20. Performance and Resource Requirements

- O(NAS+NGAP events in attempt).
- No full-capture scans.
- Decode cause tables once per process/version.
- Materialize full containers only through bounded T18 lookup.
- Record events/sec, candidates, item-level failures, unknown causes, full lookups, and elapsed time.

## 21. Security and Privacy

- Primary events only.
- Do not log NAS identities, payloads, or location values.
- Candidate summaries use masked UE/session identifiers.
- Treat cause/detail strings as untrusted.
- Full NAS trees remain local and are not automatically model evidence.

## 22. Observability

Logs include attempt, profile, event/candidate ID, message/procedure, cause code category, terminal-effect flag, and warning code.

Metrics include NAS rejects by type/category, NGAP unsuccessful outcomes, resource-item failures, terminal effects, encrypted/partial NAS, unknown causes, and latency.

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
7. Add full-evidence fallback and compatibility fixtures.

## 25. Tests

### 25.1 Unit tests

- 5GMM/5GSM reject messages and known/unknown causes.
- Authentication/security/status failures.
- NGAP unsuccessful, Error Indication, and NAS Non Delivery.
- Mixed successful/failed PDU resource items.
- Terminal-effect tagging and deterministic candidate IDs.
- Visibility/encryption behavior.
- Cause dictionary versioning.

### 25.2 Integration tests

- SBI/PFCP cause followed by NAS reject.
- Explicit NAS reject with no upstream visibility.
- Initial context/PDU resource failure.
- Network deregistration during active call.
- Xn path-switch-only visibility.
- N2 preparation/execution failure and successful rollback.
- Inter-AMF context mapping and failure.
- Encrypted NAS with explicit NGAP failure.

### 25.3 Negative tests

- Normal context release after success is not a failure.
- Successful rollback is not primary failure.
- Failure for one PDU session does not mark another failed session.
- T07 cannot access NRF/UDR partitions.

## 26. Acceptance Criteria

T07 is complete when:

1. Explicit NAS and NGAP failure families are detected with exact cause/frame evidence.
2. Item-level NGAP failures are scoped to the correct PDU session/resource.
3. Terminal UE effects are explicitly tagged for T12.
4. Upstream-versus-downstream metadata is preserved without premature ranking.
5. Encryption and interface visibility prevent false conclusions.
6. Mobility preparation, execution, path switch, and rollback are distinguished.
7. Cause dictionaries are versioned and unknown values remain usable.
8. Primary-only access is enforced.
