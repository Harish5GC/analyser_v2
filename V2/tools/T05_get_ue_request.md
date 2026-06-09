# T05 `get_ue_request` Implementation Specification

## 1. Purpose

`get_ue_request` produces an evidence-backed description of what the UE or network requested for one selected attempt. This output directly answers the report question "what was the UE requesting?" and forms mandatory model evidence.

The tool must distinguish an explicitly requested value from a value later selected, modified, defaulted, or inferred by the network.

## 2. Non-Goals

T05 must not:

- Decide whether the request succeeded or failed.
- Infer omitted request values from later network behavior.
- Read NRF/UDR partitions.
- Return complete raw NAS, NGAP, HTTP, or subscription bodies.
- Expose clear subscriber identity to model/report consumers.
- Resolve scenario expectations; T14 performs that comparison.

## 3. Ownership Boundary

Inputs:

- One persisted `ProcedureAttempt` from T04.
- `PrimaryEventReader` limited to the attempt's assigned events.
- `IdentityGraphReader` for masked UE aliases.
- Full evidence lookup capability only for locally resolving fields referenced by assigned events.

Output is a persisted `UERequestResult` consumed by T10, T11, T15, and T17.

## 4. Python Tool Contract

```python
class GetUERequestRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt_id: UUID
    include_masked_identity: bool = True
    include_conflicts: bool = True


class RequestedField(BaseModel):
    name: str
    value: JsonValue | None
    status: Literal["explicit", "derived_from_request", "conflicting", "unknown"]
    source_event_ids: list[UUID]
    source_frames: list[int]
    source_paths: list[str]
    confidence: Literal["high", "medium", "low", "inconclusive"]
    notes: list[str] = Field(default_factory=list)


class UERequestResult(BaseModel):
    schema_version: Literal["2.0"]
    analysis_id: UUID
    attempt_id: UUID
    status: Literal["decoded", "partial", "unknown"]
    procedure: str
    procedure_subtype: str | None
    initiator: Literal["UE", "NETWORK", "UNKNOWN"]
    fields: dict[str, RequestedField]
    masked_ue_ids: dict[str, str]
    trigger_event_ids: list[UUID]
    trigger_frames: list[int]
    missing_fields: list[MissingField]
    conflicts: list[RequestFieldConflict]
    warnings: list[str]
```

## 5. Field Provenance Rules

Every populated field must identify:

- Source event ID and frame.
- Exact normalized attribute or source JSON path.
- Whether it was explicit or derived from request encoding.
- Confidence and any conversion note.

T05 may dereference T18 locally when a required request field was not materialized by T02 but is present in the retained source. Such recovery is recorded in provenance. T05 does not invoke T20 automatically; it records the missing field so the orchestrator may request targeted evidence later.

## 6. Source Precedence

When multiple sources describe the same requested field:

1. Initiating NAS request IE.
2. NAS PDU transported inside the initiating NGAP message.
3. Initiating NGAP resource item carrying the UE request.
4. Directly correlated primary SBI request generated from that UE request.
5. Profile label only for procedure naming, never for request values.

A lower-precedence source cannot silently overwrite a higher-precedence explicit value. Differences become `RequestFieldConflict` records.

## 7. Common Output Fields

All attempts should attempt to populate:

- Procedure and subtype.
- Initiator.
- Access type.
- Emergency indication.
- Serving/home PLMN context when explicitly part of the request.
- Masked UE alias.
- Request trigger frames.

Unknown fields remain present with `status=unknown`; consumers should not infer them from absence.

## 8. Registration Request Extraction

Fields:

- Registration type: initial, mobility, periodic, emergency, unknown.
- Follow-on request flag.
- 5GS registration/access type.
- Requested NSSAI and each S-NSSAI.
- UE security capability and network capability summaries.
- Last visited registered TAI when explicitly included.
- Requested DRX or MICO-related indicators where relevant.
- UE identity type, represented through masked aliases.

Do not treat the network-assigned allowed NSSAI, GUTI, or TAI list as UE-requested values.

## 9. Service Request and Paging Extraction

For UE-triggered service request:

- Service type.
- Uplink data/paging-response indication.
- PDU session status/uplink data status when visible.
- Access type and emergency service indication.

For network-triggered paging:

- Initiator `NETWORK`.
- Paging identity alias.
- Paging reason/priority when explicitly present.
- Requested/targeted access area.

Do not claim a UE request before the UE responds to paging; represent paging and service response separately according to T04 profile relationships.

## 10. PDU Session Request Extraction

Fields:

- PDU session ID.
- Procedure transaction identity.
- Request type: initial, existing PDU session, emergency, modification, release.
- DNN.
- Requested S-NSSAI.
- PDU session type: IPv4, IPv6, IPv4v6, Ethernet, unstructured.
- SSC mode.
- 5GSM capability.
- QoS rules/flow descriptions requested by the UE.
- Always-on indication.
- Integrity protection maximum data rate.
- Multi-access/emergency/access-type indicators when present.

Network-selected DNN, assigned IP address, accepted PDU type, authorized QoS, or selected slice are not reported as UE-requested unless the request explicitly contained the same value. They may be added later as outcome fields by other tools.

## 11. Mobility and Handover Request Extraction

Depending on profile and initiator:

- Source/target access type and target identity.
- Handover type.
- PDU sessions/resources requested for transfer.
- Source/target TAI/CGI/PLMN.
- Direct/indirect forwarding request.
- Path-switch session list.

For network-initiated handover, label initiator `NETWORK`; do not describe it as a UE request even though UE context is affected.

## 12. Deregistration and Release Extraction

- UE-initiated or network-initiated.
- Deregistration type/access scope.
- Switch-off indication.
- Re-registration required indicator.
- PDU session/resource/context scope.
- Cause when part of the initiating request.

Later cleanup causes are not request fields.

## 13. Request Field Conflicts

```python
class RequestFieldConflict(BaseModel):
    field_name: str
    values: list[JsonValue]
    source_event_ids: list[UUID]
    source_frames: list[int]
    resolution: Literal[
        "prefer_explicit_nas", "prefer_earlier_trigger", "unresolved"
    ]
    reason: str
```

Conflict examples:

- NAS requests DNN `internet`, SBI uses `ims`.
- NAS requested PDU type differs from SBI/network-selected type.
- Two initiating messages assigned to one attempt contain different PTIs.

T05 reports both values and resolution; it never silently chooses network-selected values as UE intent.

## 14. Unknown and Partial Results

`unknown` is required when no initiating request semantics can be decoded. Reasons include:

- Capture starts after the request.
- NAS encrypted or absent.
- Unsupported/unknown NAS message.
- T02 omitted a needed semantic field and full source lacks it.
- Attempt is network-internal without a UE/network request represented in captured interfaces.

`partial` means the procedure/trigger is known but one or more expected descriptive fields are unavailable.

Each `MissingField` records name, reason code, visibility, source events checked, and whether T18/T20 could potentially recover it.

## 15. Identity Masking

- Map the internal UE node to stable analysis aliases such as `UE-1`.
- Optionally include masked forms like `imsi-***1234` only under local report policy.
- Model evidence uses non-reversible analysis aliases by default.
- Never expose SUCI concealment material, authentication vectors, keys, or clear SUPI/GPSI.

## 16. Output Layout and Caching

```text
normalized/requests/
  ue_requests.jsonl
  ue_request_manifest.json
indexes/
  attempt_request_index.jsonl
```

Results are cacheable by attempt revision checksum + request-extractor version. Re-running with identical inputs returns the same field values and provenance.

## 17. Failure Semantics

- Unknown attempt ID: request validation error.
- Attempt references missing event: partial result with evidence-integrity warning; fatal if trigger evidence is missing entirely.
- Unsupported procedure: generic request extraction plus warning.
- Conflicting values: nonfatal; persist conflict.
- Full-evidence checksum mismatch: fail result for that attempt and raise evidence-integrity error.
- Output publication failure: fatal for T05 artifact revision.

## 18. Performance and Resource Requirements

- Read only events assigned to the selected attempt.
- Use T18 only for specific missing fields, never retrieve complete capture ranges.
- Cache results when processing multiple report/model stages.
- Typical attempt should complete in milliseconds; record p50/p95 latency and full-evidence lookup count.
- Bound request-body/tree materialization.

## 19. Security and Privacy

- T05 receives primary events only.
- Clear identifiers and complete request bodies stay local.
- Treat all text values as untrusted data.
- Do not log field values for sensitive kinds.
- Provider-facing consumers must use the masked result created by T15.

## 20. Observability

Structured logs:

- `analysis_id`, `tool=T05`, `attempt_id`, `procedure`.
- Extraction rule, field name, source protocol, status/conflict code.
- Missing-field reason and lookup count without sensitive values.

Metrics:

- Results by decoded/partial/unknown.
- Missing fields by reason.
- Conflict rate by field.
- Full-evidence recovery count and latency.

## 21. Proposed Python Code Structure

```text
V2/harness/analysis/
  ue_request.py
  request_sources.py
  request_conflicts.py
  request_extractors/
    base.py
    registration.py
    service_request.py
    pdu_session.py
    mobility.py
    deregistration.py
V2/harness/storage/
  request_store.py
V2/harness/models/
  requests.py
```

## 22. Implementation Sequence

1. Define `RequestedField`, conflict, missing-field, and result schemas.
2. Implement generic trigger/provenance extraction.
3. Implement registration and PDU session extractors.
4. Implement service/paging, mobility/handover, and deregistration extractors.
5. Add local full-evidence field recovery.
6. Add caching, masking policy, manifest, and report fixtures.

## 23. Tests

### 23.1 Unit tests

- Source precedence and conflict generation.
- Explicit versus network-selected values.
- Missing-field reason classification.
- Deterministic masked aliases.
- Provenance paths and frame lists.
- Cache key stability.

### 23.2 Procedure fixtures

- Initial, mobility, periodic, emergency, and non-3GPP registration.
- UE service request and network paging.
- PDU establishment/modification/release with every supported PDU type.
- Emergency PDU session.
- Xn/N2/inter-AMF mobility.
- UE/network deregistration.
- Encrypted NAS and capture starting after request.

### 23.3 Negative tests

- Accepted DNN differs from requested DNN.
- Assigned IP is not reported as requested.
- Later SBI value cannot overwrite explicit NAS request silently.
- T05 cannot read NRF/UDR partitions.

## 24. Acceptance Criteria

T05 is complete when:

1. Every populated request field cites exact source events, frames, and paths.
2. Explicit UE intent is distinguished from network selection/outcome.
3. Registration, service, PDU, mobility, and deregistration families are covered.
4. Conflicting request representations remain explicit.
5. Unknown and partial results contain actionable missing-field reasons.
6. Clear subscriber identities and sensitive material never cross the trusted boundary.
7. Output is deterministic for an attempt revision.
8. Only assigned primary evidence is read by default.
