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
    attempts_revision: str
    attempt: ProcedureAttempt
    primary_reader: PrimaryEventReader
    identity_graph: IdentityGraphReader
    evidence_repository: EvidenceRepository
    primary_internal: EvidenceCapability
    masking_policy: ResolvedPolicy
    run_dir: Path
    requests_dir: Path
    indexes_dir: Path
    include_masked_identity: bool = True
    include_conflicts: bool = True
    max_full_evidence_lookups: int = 20
    max_materialized_field_bytes: int = 65536
    max_issue_samples_per_code: int = 20
    fsync_outputs: bool = True


class RequestedField(BaseModel):
    name: str
    value: JsonValue | None
    status: Literal["explicit", "derived_from_request", "conflicting", "unknown"]
    source_event_ids: list[UUID]
    source_frames: list[int]
    raw_refs: list[SourceRef]
    field_paths: list[str]
    evidence_ids: list[UUID]
    confidence: Literal["high", "medium", "low", "inconclusive"]
    notes: list[str] = Field(default_factory=list)


class UERequestResult(BaseModel):
    schema_version: Literal["2.0"]
    analysis_id: UUID
    attempt_id: UUID
    revision: str
    status: Literal["decoded", "partial", "unknown"]
    procedure: str
    procedure_subtype: str | None
    initiator: Literal["UE", "NETWORK", "UNKNOWN"]
    fields: dict[str, RequestedField]
    ue: MaskedUEIdentity | None
    trigger_event_ids: list[UUID]
    trigger_frames: list[int]
    missing_fields: list[MissingField]
    conflicts: list[RequestFieldConflict]
    stage_timings: list[StageTimingObservation]
    artifact: ArtifactDescriptor
    manifest: ArtifactDescriptor
    issues: list[Issue]
```

The request is dependency-injected by the orchestrator; the public CLI/model
cannot supply arbitrary readers, repositories or capabilities. T05 validates
that `attempt_id`, attempt analysis ID and T04 revision match, and that the
primary/identity readers are pinned to the T02/T03 ancestors of that T04
revision.

`primary_internal` must have holder `T05`, this analysis/attempt, partition
allowlist exactly `primary`, the T02/T04 artifact revision binding and frame
bounds no wider than the attempt. T18 validates the capability after every ID,
index, cursor and selector expansion. Any expansion to NRF/UDR is
`RUN_ACCESS_BOUNDARY`; it is not a missing-field fallback.

`masking_policy.payload` validates as shared `MaskingPolicy`. Paths must remain
inside the run root with `requests_dir=normalized/requests`; traversal and
symlink escape are fatal. Lookup/materialization/sample limits are positive.

## 5. Field Provenance Rules

Every populated field must identify:

- Source event ID and frame.
- Exact normalized attribute or source JSON path.
- Whether it was explicit or derived from request encoding.
- Confidence and any conversion note.

T05 may dereference T18 locally when a required request field was not materialized by T02 but is present in the retained source. Such recovery is recorded in provenance. T05 does not invoke T20 automatically; it records the missing field so the orchestrator may request targeted evidence later.

T05 mints shared `request_field` evidence records for every populated or
conflicting field. Evidence IDs are UUIDv5 over sorted source event IDs,
semantic field name and T05 revision scope. T15 selects these records later;
it does not recreate provenance.

### 5.1 Extraction algorithm

1. Validate the attempt/revisions/capability and load exactly the accepted
   T04 assignments in `(frame,event_id)` order.
2. Fetch events through `PrimaryEventReader.get`; reject unassigned,
   non-primary, quarantined, out-of-attempt or wrong-revision events.
3. Choose the profile-family extractor from the persisted T04 profile ID. An
   unsupported family uses the generic initiating-message extractor and emits
   `T05_UNSUPPORTED_PROCEDURE`.
4. Enumerate the extractor's fixed field definitions. For each definition,
   inspect normalized event fields/attributes in declared source-precedence
   order and validate type/size.
5. When normalized semantics are absent, issue a field-specific T18 lookup
   bounded to the assigned event IDs/raw refs and remaining lookup budget.
6. Convert explicit request encoding through named deterministic converters;
   never infer from later selected/outcome values.
7. Persist all distinct candidate values with provenance, then apply section 6
   precedence. Equal canonical values merge provenance; unequal values create
   a conflict.
8. Create a `MissingField` for every declared field without a valid value and
   classify recovery as T18, T20 or none.
9. Build masked UE identity, T05-owned request timing, revision, artifact and
   manifest; validate before publication.

Field definitions are code/validated policy data with allowlisted typed paths,
not arbitrary JSONPath, regex or executable predicates. Source records may be
read only for the named field path; T05 does not materialize or return the
whole request tree/body.

## 6. Source Precedence

When multiple sources describe the same requested field:

1. Initiating NAS request IE.
2. NAS PDU transported inside the initiating NGAP message.
3. Initiating NGAP resource item carrying the UE request.
4. Directly correlated primary SBI request generated from that UE request.
5. Profile label only for procedure naming, never for request values.

A lower-precedence source cannot silently overwrite a higher-precedence explicit value. Differences become `RequestFieldConflict` records.

Within one precedence level, candidates sort by initiating-event order,
field-path priority and event UUID. A lower-precedence value identical after
canonical conversion adds provenance but does not create a conflict.

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
    conflict_id: UUID
    field_name: str
    values: list[JsonValue]
    source_event_ids: list[UUID]
    source_frames: list[int]
    resolution: Literal[
        "prefer_explicit_nas", "prefer_earlier_trigger", "unresolved"
    ]
    reason_codes: list[str]
    evidence_ids: list[UUID]
```

Conflict examples:

- NAS requests DNN `internet`, SBI uses `ims`.
- NAS requested PDU type differs from SBI/network-selected type.
- Two initiating messages assigned to one attempt contain different PTIs.

T05 reports both values and resolution; it never silently chooses network-selected values as UE intent.

Conflict values use canonical JSON ordering and masking rules. Resolution is
`prefer_explicit_nas` only when the higher-precedence NAS source is explicit
request intent; `prefer_earlier_trigger` applies only to profile-declared
retransmission-equivalent initiating messages. Otherwise the field status is
`conflicting`, its selected value is `None`, and all candidates remain in the
conflict record.

## 14. Unknown and Partial Results

`unknown` is required when no initiating request semantics can be decoded. Reasons include:

- Capture starts after the request.
- NAS encrypted or absent.
- Unsupported/unknown NAS message.
- T02 omitted a needed semantic field and full source lacks it.
- Attempt is network-internal without a UE/network request represented in captured interfaces.

`partial` means the procedure/trigger is known but one or more expected descriptive fields are unavailable.

Each `MissingField` records name, reason code, visibility, source events checked, and whether T18/T20 could potentially recover it.

Result status is `decoded` when every procedure-required descriptive field is
explicit/derived and there is decodable initiating semantics; `partial` when
the procedure is known but one or more required fields are missing/conflicting;
and `unknown` when no initiating request semantics can be decoded. Optional
unknown fields do not alone make a decoded result partial.

## 15. Identity Masking

- Map the internal UE node to stable analysis aliases such as `UE-1`.
- Optionally include masked forms like `imsi-***1234` only under local report policy.
- Model evidence uses non-reversible analysis aliases by default.
- Never expose SUCI concealment material, authentication vectors, keys, or clear SUPI/GPSI.

`include_masked_identity=false` sets `ue=None`; it does not alter field
provenance or permit clear identity. Local display masks are included only when
the resolved policy allows that surface. Remote/provider packets always use
the analysis alias and are remasked by T15.

## 16. Output Layout and Caching

```text
normalized/requests/
  <attempt-id>/
    request.json
    request_manifest.json
indexes/
  attempt_request_index.jsonl
staging/T05-<attempt-id>-<uuid>/
```

Each attempt directory is an immutable T05 generation target. The shared
attempt-request index is updated by the run-store artifact/index registrar in
deterministic attempt-ID order; parallel T05 invocations never append directly
to one JSONL file.

`request.json` is the validated `UERequestResult` without recursive artifact /
manifest descriptor fields; the returned result attaches those descriptors.
The manifest records T04/T03/T02 revisions, attempt ID and canonical attempt
payload hash, extractor/tool/schema version, masking policy checksum,
capability selector hash, lookup limits/counts, status, field/conflict/missing
counts, artifacts, sampled issues and timing.

T05 revision inputs are the T04 revision and attempt payload hash, assigned
event IDs and parent checksums, T03 revision, extractor version, masking policy
checksum, output-affecting request flags/limits and schema/tool version.
Capability ID/expiry and runtime timings are not identity inputs; its immutable
scope/selector hash and artifact revision are.

Results are cacheable by T05 revision. Re-running identical inputs validates
and returns the existing artifacts; changed inputs create a sibling generation
without overwriting the first.

### 16.1 Descriptor and publication invariants

- `request.json` descriptor type `ue_request_result`, media
  `application/json`, record count 1, parent source T04 manifest checksum and
  T05 revision.
- `request_manifest.json` descriptor type `ue_request_manifest` with record
  count 1. The index entry records attempt ID, T05/T04 revisions, status,
  request artifact descriptor ID/path/checksum and byte offset where relevant.
- Every populated/conflicting field has nonempty source events/frames/raw refs,
  field paths and resolvable T05 evidence IDs.
- Trigger events equal the T04 trigger projection and all checked/recovered
  events are assigned primary events inside capability bounds.
- Field dictionaries are ordered by registered field order; source/evidence
  lists and conflict values are deterministic and duplicate-free.
- Missing fields use registered reason codes and legal recovery values.
- No clear sensitive value appears in result, evidence observed values,
  manifest, descriptor, index, issue or log.
- Manifest counts/checksums match staged bytes. Publish request first, index
  registration second and manifest last.

### 16.2 Runner blueprint

```python
def get_ue_request(req: GetUERequestRequest) -> UERequestResult:
    lineage = validate_attempt_and_readers(req)
    capability = validate_primary_internal_capability(req, lineage)
    masking = validate_and_resolve_masking(req.masking_policy)
    revision = build_t05_revision(req, lineage, capability, masking)
    if existing := find_existing_request(req.run_dir, req.attempt_id, revision):
        return load_validated_result(existing)

    staging = make_attempt_staging(req.run_dir, req.attempt_id)
    events = load_assigned_primary_events(req, lineage)
    extraction = extractor_for(req.attempt.profile_id).extract(events, req, capability)
    result = finalize_fields_conflicts_missing(extraction, req, masking, revision)
    evidence = stage_request_evidence(result, extraction, revision)
    descriptors = write_validate_descriptors(staging, result, evidence, lineage)
    manifest = build_validate_manifest(req, result, descriptors, revision)
    publish_request_generation(staging, descriptors, evidence, manifest_last=True)
    return attach_descriptors(result, descriptors, manifest)
```

## 17. Failure Semantics

- Unknown attempt ID: request validation error.
- Mixed/stale T02-T04 lineage, wrong capability holder/scope, path escape or
  incompatible masking policy: fatal with no T05 manifest.
- Attempt references missing event: partial result with evidence-integrity warning; fatal if trigger evidence is missing entirely.
- Unsupported procedure: generic request extraction plus warning.
- Conflicting values: nonfatal; persist conflict.
- Full-evidence checksum mismatch: fail result for that attempt and raise evidence-integrity error.
- Output publication failure: fatal for T05 artifact revision.

Lookup-budget exhaustion produces a `MissingField` with recoverability and
marks a known procedure partial; it never broadens the capability. Conflicts,
unknown optional fields and a legitimate `unknown` result are represented
outcomes, not execution failures.

## 18. Performance and Resource Requirements

- Read only events assigned to the selected attempt.
- Use T18 only for specific missing fields, never retrieve complete capture ranges.
- Cache results when processing multiple report/model stages.
- Typical attempt should complete in milliseconds; record p50/p95 latency and full-evidence lookup count.
- Bound request-body/tree materialization.

## 19. Security and Privacy

- T05 receives primary events only.
- T05's `primary_internal` capability resolves only fields from events already
  assigned to this attempt. It is not a partition bypass, generic evidence
  browser or authority to widen frame/event selectors.
- T18 rechecks authorization after direct ID, index, cursor and selector
  expansion and denies any NRF/UDR result.
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

Minimum registered issue codes are `T05_UNKNOWN_ATTEMPT`,
`T05_UNSUPPORTED_PROCEDURE`, `T05_FIELD_MISSING`, `T05_FIELD_CONFLICT`,
`T05_FULL_EVIDENCE_LOOKUP_LIMIT`, `T05_SOURCE_FIELD_INVALID`, and
`T05_OUTPUT_INVARIANT_FAILED`; shared capability/integrity violations use
`RUN_ACCESS_BOUNDARY` and `RUN_EVIDENCE_INTEGRITY`.

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
7. Add revision-pinned per-attempt publication and shared index registration.

## 23. Tests

### 23.1 Unit tests

- Source precedence and conflict generation.
- Explicit versus network-selected values.
- Missing-field reason classification.
- Deterministic masked aliases.
- Provenance paths and frame lists.
- Cache key stability.
- Capability validation after selector expansion.
- Field converter size/type bounds and canonical equality.
- Revision, evidence ID, descriptor and manifest determinism.

### 23.2 Procedure fixtures

- Initial, mobility, periodic, emergency, and non-3GPP registration.
- UE service request and network paging.
- PDU establishment/modification/release with every supported PDU type.
- Emergency PDU session.
- Xn/N2/inter-AMF mobility.
- UE/network deregistration.
- Encrypted NAS and capture starting after request.
- Primary-internal recovery of one omitted semantic field with complete
  provenance and T18 resolution.

### 23.3 Negative tests

- Accepted DNN differs from requested DNN.
- Assigned IP is not reported as requested.
- Later SBI value cannot overwrite explicit NAS request silently.
- T05 cannot read NRF/UDR partitions.
- Direct NRF/UDR evidence IDs, indexes, cursors and broadened selectors fail
  after expansion under `primary_internal`.
- Unassigned event, stale attempt revision, trigger-integrity loss, corrupt
  source descriptor, masking failure and symlink escape publish no result.
- Clear SUPI/GPSI/SUCI/UE-IP or complete bodies do not appear in artifacts,
  evidence, indexes, issues or logs.

### 23.4 Golden tests

- Stable request JSON, provenance, conflicts, missing fields, evidence IDs,
  manifest and index entry for fixed registration, paging, session and
  mobility fixtures after generated timing normalization only.
- Identical rerun returns the same revision; extractor/masking/attempt change
  creates a sibling generation.

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
9. `primary_internal` is enforced after selector expansion and cannot resolve
   NRF/UDR evidence by any lookup form.
10. Every request artifact/evidence/index/manifest satisfies section 16.1 and
    is published atomically with manifest last.

## 25. Mechanical Implementation Checklist

1. Define request/result/field/conflict models using shared support models.
2. Register T05 and shared RUN issue/evidence record types.
3. Validate attempt ID/payload, T04 revision and T02/T03 reader lineage.
4. Validate the `primary_internal` holder, attempt, partition, frame, selector
   and artifact-revision bounds.
5. Validate/resolve masking policy and run-relative output paths.
6. Build the deterministic T05 revision and return an existing identical
   generation when present.
7. Load only accepted T04 event assignments via the primary reader.
8. Implement fixed profile-family field definitions and typed converters.
9. Apply source precedence and merge equal canonical values/provenance.
10. Create explicit conflicts for unequal candidates without inferring intent.
11. Perform field-specific T18 recovery within lookup/materialization budgets.
12. Revalidate capability after every selector expansion; reject NRF/UDR.
13. Build `MissingField` rows with registered reasons and recoverability.
14. Determine decoded/partial/unknown from required field semantics.
15. Build policy-compliant `MaskedUEIdentity` or omit it when requested.
16. Mint revision-scoped `request_field` evidence for populated/conflicting
    fields.
17. Emit T05-owned request timing from the first initiating message.
18. Write per-attempt request JSON and manifest in staging.
19. Validate every section 16.1 provenance/privacy/count/checksum invariant.
20. Build descriptors and register the ordered attempt-request index entry.
21. Publish request/evidence/index transaction and manifest last.
22. Preserve prior siblings and remove only this staging tree on failure.
23. Add unit/procedure/negative/security/golden tests from section 23.
