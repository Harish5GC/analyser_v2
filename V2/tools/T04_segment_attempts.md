# T04 `segment_attempts` Implementation Specification

## 1. Purpose

`segment_attempts` divides primary UE/session timelines into independent, typed procedure attempts. Attempts are the unit used for request extraction, diagnostics, comparison, model evidence, and reporting.

The tool must distinguish retries from new attempts and must handle repeated establishment/release cycles, overlapping procedures, mobility context changes, network-triggered procedures, and capture boundaries.

## 2. Non-Goals

T04 must not:

- Diagnose a root cause.
- Treat every missing terminal as a network failure.
- Use NRF/UDR hidden partitions.
- Merge attempts solely because they share a PDU session ID, PTI, SEID, stream, or endpoint.
- Apply scenario success/failure expectations; T14 handles scenario validation.
- Compare attempts; T11 handles baseline comparison.

## 3. Ownership Boundary

Inputs:

- Read-only `PrimaryEventReader`.
- T03 `IdentityGraphReader`.
- Versioned procedure-profile registry.
- Capture metadata and timeout configuration.

Outputs:

- Persisted attempts and event assignments.
- Retry and parent/child relationships.
- Ambiguous/unassigned event records.
- Attempt indexes and manifest.

## 4. Python Tool Contract

```python
class SegmentAttemptsRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    normalization: NormalizeEventsResult
    identity_result: BuildIdentityGraphResult
    primary_reader: PrimaryEventReader
    identity_graph: IdentityGraphReader
    capture: CaptureMetadata
    profile_registry: ResolvedProfileRegistry
    run_dir: Path
    attempts_dir: Path
    indexes_dir: Path
    enabled_capabilities: set[CapabilityName] = Field(default_factory=set)
    policy_versions: dict[str, str]
    config: AttemptSegmentationConfig


class AttemptSegmentationConfig(BaseModel):
    default_idle_timeout_seconds: Decimal = Decimal("30")
    default_response_timeout_seconds: Decimal = Decimal("10")
    max_open_attempts_per_ue: int = 100
    minimum_assignment_confidence: Decimal = Decimal("0.70")
    profile_alternative_margin: Decimal = Decimal("0.10")
    max_profile_candidates_per_trigger: int = 20
    max_assignment_candidates_per_event: int = 20
    max_issue_samples_per_code: int = 20
    persist_unassigned_events: bool = True
    fsync_outputs: bool = True


class SegmentAttemptsResult(BaseModel):
    schema_version: Literal["2.0"]
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
    issues: list[AttemptWarning]
```

`revision` is the section 25 (`LLD.md`) revision envelope digest for this
attempt generation; downstream consumers (T10/T11/T21 and lineage validation)
reference attempts by this value.

`AttemptWarning` is a type alias of shared `Issue`. T04 validates that the T02
result/manifest/reader revision agree, the T03 result/manifest/reader revision
agree, and the T03 parent revision is the same T02 generation supplied here.
It rejects mixed analysis IDs, unsupported schemas and stale sibling readers.

`capture` must match the T01/T02 source checksum and frame bounds. The resolved
profile registry checksum, selected release/deployment overlays and visibility
registry checksum must match `policy_versions`; T04 never loads profile YAML
or selects a latest version itself.

Paths must resolve inside the run root with `attempts_dir` at
`normalized/attempts`. Absolute paths, traversal, symlink escape and staging /
published aliases are fatal. Configuration requires positive timeouts/caps,
thresholds in `[0,1]`, and a nonnegative alternative margin.

## 5. Procedure Attempt Model

```python
class ProcedureAttempt(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    attempt_id: UUID
    analysis_id: UUID
    ue_id: UUID | None
    session_node_id: UUID | None
    access_context_id: UUID | None
    access_family: Literal["3gpp", "non_3gpp_untrusted", "non_3gpp_trusted", "unknown"]
    access_anchor_type: Literal["GNB", "N3IWF", "TNGF", "UNKNOWN"]
    profile_id: str
    profile_alternatives: list[ProfileSelectionAlternative] = Field(default_factory=list)
    procedure_type: str
    subtype: str | None
    sequence_number: int
    initiator: Literal["UE", "NETWORK", "UNKNOWN"]
    parent_attempt_id: UUID | None
    child_attempt_ids: list[UUID] = Field(default_factory=list)
    start_frame: int
    end_frame: int
    start_timestamp: Decimal | None
    end_timestamp: Decimal | None
    incomplete_history: bool = False
    trigger_event_ids: list[UUID]
    event_ids: list[UUID]
    correlation_identifiers: EventIdentifiers
    request_signature: dict[str, JsonValue]
    transitions: list[StateTransition]
    retries: list[RetryRecord]
    stage_timings: list[StageTimingObservation] = Field(default_factory=list)
    outcome: Literal[
        "succeeded", "failed", "aborted", "timed_out", "incomplete_capture"
    ]
    completion_reason: str
    assignment_confidence: Literal["high", "medium", "low"]
    visibility: InterfaceVisibility
    roaming_topology: RoamingTopologyInterval | None
    issue_codes: list[str] = Field(default_factory=list)
```

Open attempts are internal transient objects. A completed T04 artifact must not contain `outcome=open`.
Persisted `issue_codes` contain registered issue codes only; human messages live
in manifest/result `Issue` records. `event_ids`, trigger IDs, child IDs,
transitions, retries, alternatives and timing rows have deterministic ordering
and no duplicates.

### 5.1 Assignment and relationship records

```python
class AttemptEventAssignment(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    assignment_id: UUID
    event_id: UUID
    attempt_id: UUID
    confidence: Decimal
    strength: Literal["exact", "strong", "supporting"]
    reason_codes: list[str]
    profile_stage_ids: list[str]
    shared_by_nesting_rule: bool = False


class AttemptRelationship(BaseModel):
    relationship_id: UUID
    left_attempt_id: UUID
    right_attempt_id: UUID
    relation: Literal["parent_child", "retry_of", "supersedes", "access_transfer"]
    evidence_event_ids: list[UUID]
    profile_rule_id: str
```

Every accepted event assignment has one record. A shared event has one record
per legal owner and the same profile nesting rule. Ambiguous candidates use
the section 17 model and never appear in an attempt's `event_ids` unless later
accepted by deterministic disambiguation.

## 6. Procedure Profile Contract

```python
class ProcedureProfile(BaseModel):
    profile_id: str
    version: str
    release: str
    deployment_profile: str
    procedure_type: str
    trigger_matchers: list[EventMatcher]
    correlation_keys: list[CorrelationKeyRule]
    stages: list[StageDefinition]
    success_terminals: list[EventMatcher]
    failure_terminals: list[EventMatcher]
    abort_terminals: list[EventMatcher]
    retry_rules: list[RetryRule]
    timeout_rules: list[TimeoutRule]
    nesting_rules: list[NestingRule]
    visibility_requirements: list[VisibilityRequirement]
```

Every stage declares `mandatory`, `conditional`, `optional`, or `repeatable`. Conditional stages include a machine-evaluable applicability predicate.

This model is the profile *schema* only. The normative registry contract —
file format, authoring/review process, release/deployment overlays,
conditional grammar, versioning/checksums and the traceability mapping from
every `requirement.md` section-8 flow to profile IDs and fixtures — is
`profiles/README.md`. T04 loads profiles exclusively through that registry via
the configuration resolver (`LLD.md` section 29).

## 7. Supported Profile Families

### 7.1 Registration

- Initial registration.
- Mobility registration update.
- Periodic registration update.
- Emergency registration.
- Registration over 3GPP/non-3GPP access.
- Registration retry and re-authentication branches.

### 7.2 Session and service

- UE service request.
- Network paging and service restoration.
- PDU session establishment, modification, and release.
- Emergency PDU session.
- UE/network initiated deregistration.

### 7.3 Access and mobility

- Initial context setup and release.
- PDU session resource setup/modify/release.
- Xn handover visible from path switch.
- N2 handover.
- Inter-AMF handover/context transfer.
- Inter-system and 3GPP/non-3GPP mobility.

## 8. Attempt Triggering

An attempt opens only from a profile trigger with sufficient identity context. Trigger examples:

- NAS Registration Request.
- NAS Service Request.
- NAS PDU Session Establishment Request.
- NGAP Handover Required/Path Switch Request.
- Network paging for a new paging attempt.
- Network-initiated deregistration request.

If the capture starts mid-procedure, a profile may define a `mid_capture_trigger` such as a response or path-switch message. Such attempts are marked `incomplete_history=true` and cannot claim missing earlier stages.

### 8.1 Profile candidate selection algorithm

For each primary event in `(frame,event_id)` order:

1. Resolve active T03 UE, access, session and topology intervals at the frame.
2. Query
   `profile_registry.candidates(message_type, procedure, access_family, release, deployment)`;
   do not scan every profile.
3. Evaluate trigger matchers and allowlisted condition facts. Unknown facts
   remain unknown and cannot satisfy a required boolean condition.
4. Build shared `ScoreTerm` rows from trigger specificity, identity/context
   completeness, access-family match, release/deployment compatibility,
   mid-capture penalty and conflicts. Clamp canonical-decimal confidence to
   `[0,1]`.
5. Sort by confidence descending, trigger specificity descending, profile ID
   and profile checksum. Retain at most
   `max_profile_candidates_per_trigger`; overflow of equal viable candidates
   is persisted and marks partial rather than selecting by iteration order.
6. Select the highest candidate. Candidates within
   `profile_alternative_margin` remain `alternative`; impossible candidates
   with useful audit evidence are `rejected`. Later terminal/stage evidence may
   mark one `disambiguated`, but no record is deleted.
7. Open an attempt only when the selected trigger is genuine and has a stable
   UE/access/session context or a profile-authorized provisional mid-capture
   basis.

Selected profile identity is an attempt-ID input. Later disambiguation updates
the alternatives/status evidence but does not silently change the selected
profile or attempt ID; a materially different selected profile requires a new
T04 revision.

## 9. Event Assignment

Assignment order:

1. Exact identity and transaction match.
2. Explicit parent/child protocol reference.
3. Strong session/context graph link.
4. Profile stage compatibility within validity/time bounds.
5. Supporting time/endpoint evidence only after one stronger match.

Each assignment stores confidence and reason codes. An event may be shared between a parent and child attempt only when the profile nesting rule permits it; otherwise it has one owning attempt plus ambiguous candidates.

T04 persists selected, alternative, rejected and disambiguated profile
candidates for the same trigger window. Each `ProfileSelectionAlternative`
records profile ID, confidence, score terms, evidence and rationale codes.
These records explain procedure ambiguity only; T17 renders them separately
from T12 root-cause alternatives. Disambiguation never rewrites the attempt ID
or silently removes rejected alternatives from the artifact.

### 9.1 Deterministic assignment algorithm

For each event, build candidates only from open attempts indexed by T03 node
IDs, protocol transaction identifiers and profile stage matchers:

1. Reject attempts whose access/context/session validity cannot overlap the
   event, except an explicit profile access-transfer/nesting rule.
2. Score exact identity/transaction links, explicit parent references and
   strong graph associations. Add bounded profile-stage/time/endpoint support
   only after one stronger term exists.
3. Reject a candidate with a hard transaction, access-family, closed-terminal
   or identity conflict.
4. Sort by confidence descending, strength, stage-order compatibility, attempt
   start frame, profile ID and attempt UUID.
5. Accept the top candidate when confidence is at least
   `minimum_assignment_confidence` and either it is the sole top candidate or
   all tied owners are permitted by one nesting rule.
6. Persist other plausible candidates as ambiguous. Persist no-candidate or
   below-threshold events as unassigned when configured.
7. Cap only weak candidates deterministically. Explicit candidate overflow is
   fatal; weak truncation emits `T04_ASSIGNMENT_CANDIDATES_TRUNCATED` and marks
   the result partial.

Assignment IDs are UUIDv5 over T04 revision, event ID, attempt ID and accepted
rule IDs. Timestamp proximity alone never creates a candidate.

### 9.2 Access-scoped registration and non-merge rules

T04 reads the T03 `AccessContextKey` and `AccessRegistrationState` active at
each event. Registration, service, deregistration and mobility state is keyed
by `(ue_id, access_context_id, access_family)`, never by UE alone.

- Concurrent 3GPP and non-3GPP Registration Requests always create separate
  attempts even when subscriber identity, registration type and timing match.
- N3IWF and TNGF registrations are separate attempts and state machines.
- An event attaches to an attempt only when its access context matches or a
  selected access-mobility profile contains an explicit context-transfer edge.
- Access transfer links source and target attempts as parent/child or related
  attempts according to the profile; it does not merge their event lists,
  attempt IDs or registration states.
- A deregistration scoped to 3GPP, non-3GPP or both closes exactly the declared
  access states. Ambiguous scope is recorded and cannot close all contexts by
  assumption.
- A PDU session retained across access change preserves its session node but
  opens a new access-leg/mobility attempt with source/target context evidence.

## 10. Retry Versus New Attempt

A retry belongs to an open attempt when all required conditions hold:

- Same profile/procedure family.
- Compatible UE/session context.
- Same transaction identity when the protocol provides one.
- No prior terminal completion.
- Retry occurs within the profile retry window.
- Request signature is compatible under profile rules.

A new attempt is required when any decisive condition holds:

- Prior attempt reached a terminal state.
- New PTI/transaction identity indicates a fresh procedure.
- Explicit new registration/session trigger after completion.
- Retry/idle window expired.
- Identity validity interval changed.
- Access family, anchor type or access-context validity interval changed,
  except that an explicit profile-defined mobility relation links the old/new
  attempts without merging them.
- Profile defines the message as a new attempt rather than retransmission.

Repeated requests with ambiguous transaction information remain assignment candidates and lower attempt confidence; they are not blindly merged.

### 10.1 Retry decision algorithm

When a trigger matches an open attempt and could also start a new attempt,
evaluate the profile retry rules before opening either path:

1. Compare only the profile-declared stable request-signature fields.
2. Require compatible T03 node validity and access context.
3. Require the transaction identity relation declared by the retry rule
   (`same`, `may_change`, or `must_change`).
4. Compute frame/time distance using frame order as authoritative and valid
   timestamps only as an additional bound.
5. Reject retry classification after any terminal, superseding trigger,
   context expiry or incompatible request field.
6. If exactly one retry rule matches, append a deterministic `RetryRecord` and
   assignment to the existing attempt. If multiple rules tie, persist the
   ambiguity and open a new low-confidence attempt rather than merging.

The retry record ID uses T04 revision, attempt ID, previous trigger event ID,
new trigger event ID and retry rule ID. Retry classification never changes a
closed attempt.

## 11. Parent and Child Attempts

Nested examples:

- Registration parent with authentication/security child procedures.
- PDU session establishment parent with SM context and PFCP subprocedures represented as linked stages/events rather than separate UE attempts unless separately reportable.
- Handover parent with path-switch and old-context release child procedures.
- Paging parent followed by UE service request child/continuation according to profile.

Parent failure does not automatically mark every child failed; outcome propagation is profile-specific.

## 12. State Transition Construction

For each assigned event:

1. Match applicable stage definitions.
2. Check ordering constraints and repeatability.
3. Record transition from prior attempt state.
4. Mark out-of-order but legal optional/retry events.
5. Record unexpected events without immediately failing the attempt.

T04 records observed transitions. T09 later determines whether a missing transition is a diagnostic failure.

Transition IDs are UUIDv5 over T04 revision, attempt ID, stage ID, occurrence,
source event IDs and resulting state. For one attempt, transitions sort by
frame, profile stage order, occurrence and transition ID. Repeatable stages
increment occurrence; duplicate matching of the same event/stage is collapsed.
An event that matches mutually exclusive branches produces a profile conflict
issue and keeps both profile alternatives rather than choosing by matcher
iteration order.

## 13. Attempt Closure

Closure evaluation occurs after all events in a frame are assigned. For an
attempt with several same-frame terminal matches, profile terminal precedence
is `failure`, `abort`, then `success`, unless the profile declares an explicit
rollback/supersession rule. Ties within one class sort by matcher ID and event
ID. T04 persists all terminal evidence even when one terminal determines the
outcome.

### 13.1 Success

Close on a profile success terminal after required visible stages are satisfied or explicitly bypassed by a legal branch.

### 13.2 Explicit failure

Close on NAS reject, NGAP unsuccessful terminal, explicit abort/cancel, or other profile failure terminal. T04 records terminal outcome but does not choose root cause.

### 13.3 Abort

Use `aborted` for explicit cancellation, supersession, successful rollback, or replacement by a profile-defined new procedure.

### 13.4 Timeout

Use `timed_out` only when:

- Required reference-point, SBI service or SBI API visibility reaches the
  profile requirement's `minimum_state`.
- Expected timeout elapsed inside the capture.
- No terminal response was observed.

### 13.5 Incomplete capture

Use `incomplete_capture` when the capture starts after required history or ends before a reliable timeout/terminal conclusion.

### 13.6 Stage timing construction

T04 emits shared `StageTimingObservation` rows for:

- `attempt.trigger` from the accepted trigger or mid-capture basis.
- `request.first_ue_or_network_message` from the first assigned initiating
  event.
- Profile-owned observed stage anchors.
- `terminal.outcome` from the selected terminal, timeout deadline or capture
  boundary.

Frames are primary. Decimal timestamps and source precision are copied only
from validated events; generated deadlines use canonical decimal arithmetic.
`not_applicable`, `absent` and `inconclusive` follow LLD section 23.6. T04 does
not emit detector-owned dependency/PFCP/missing/recovery timings.

## 14. Visibility Model

Per attempt, persist `InterfaceVisibility` from `LLD.md` section 23.1 using
the selected release/deployment visibility registry from
`profile_registry.visibility_registry`. T04 records three disjoint namespaces:

- `reference_points`: architecture reference points such as `N1`, `N2`, `N4`,
  `N7`, `N13`, `N27`, `N35`, `N36`, `N37` and profile-applicable mobility
  links such as `Xn`.
- `sbi_services`: service-based interfaces such as `Nnrf`, `Nudr`, `Npcf`,
  `Nausf`, `Namf` and `Nsmf`.
- `sbi_apis`: concrete API/operation families when stage applicability or
  diagnostics require finer visibility than the service name.

`Nnrf` must not be persisted as a reference point. NRF-to-NRF roaming uses
`reference_points["N27"]`; NRF service traffic visible in HTTP/SBI uses
`sbi_services["Nnrf"]`.

Profile stages whose required visibility entries are `not_captured`,
`partial` below the required minimum, or `unknown` cannot cause T04 to declare
timeout/failure. Visibility is later consumed by T09 and T14.

## 15. Request Signature

T04 stores a stable request signature for T11 baseline selection:

- Procedure/profile/subtype.
- Registration/service request type.
- DNN, S-NSSAI, PDU type, SSC mode.
- Access type, emergency flag, and the exact T03 roaming-topology interval
  revision/evidence active at the attempt trigger.
- PDU session ID only as scoped context, not global identity.

Dynamic frames, timestamps, stream IDs, sequence numbers, SEIDs, TEIDs, UUIDs, and ports are excluded.

## 16. Attempt ID and Sequence

Attempt IDs are deterministic UUIDv5 values derived from:

```text
analysis_id + t03_revision + profile_registry.sha256 + profile_id
+ stable UE/access/session context key + first trigger event ID
```

The stable context key uses the most specific available T03 node IDs in order:
UE, access context, session; a provisional mid-capture key uses the trigger
event ID and profile-authorized visible identifiers. Adding later events does
not change the attempt ID.

Sequence numbers are assigned after all attempts are materialized, partitioned
by `(ue_id or provisional_context_key, procedure_type)`, and sorted by
`start_frame`, trigger event ID and attempt UUID. Adding later events to an
existing attempt does not change its sequence. A new earlier attempt in a new
T04 revision may renumber later attempts; consumers pin the revision.

## 17. Ambiguous and Unassigned Events

```python
class AttemptAssignmentCandidate(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    candidate_id: UUID
    event_id: UUID
    candidate_attempt_id: UUID
    confidence: Decimal
    score_terms: list[ScoreTerm]
    reason_codes: list[str]
    decision: Literal["ambiguous", "rejected"]
```

Events below assignment threshold are persisted as unassigned. Ambiguous assignment must remain visible to diagnostics and reports as a limitation.

## 18. Output Layout

```text
normalized/attempts/
  attempts.jsonl
  transitions.jsonl
  retries.jsonl
  event_assignments.jsonl
  attempt_relationships.jsonl
  ambiguous_assignments.jsonl
  unassigned_events.jsonl
  profile_alternatives.jsonl
  stage_timings.jsonl
  attempts_manifest.json
indexes/
  attempt_index.jsonl
  ue_attempt_index.jsonl
  event_attempt_index.jsonl
  procedure_attempt_index.jsonl
staging/T04-<uuid>/
```

All files exist even when empty. Attempts sort by start frame, trigger event
ID and attempt UUID. Child files sort by attempt ID then their semantic frame /
occurrence/UUID order. Index entries include T04 revision and byte offsets and
must support bounded lookup by attempt, UE, access context, session, event,
procedure/profile and outcome.

### 18.1 Artifact descriptor expectations

Every listed data/index/manifest file has a shared `ArtifactDescriptor` with
run-relative path, artifact/media/schema type, SHA-256, byte size, verifiable
record count, `creation_stage="T04"`, T03 manifest checksum as parent source,
and T04 revision. Required artifact types are `procedure_attempts`,
`attempt_transitions`, `attempt_retries`, `attempt_event_assignments`,
`attempt_relationships`, `attempt_assignment_candidates`,
`attempt_unassigned_events`, `profile_selection_alternatives`,
`stage_timing_observations`, `attempt_index`, and `attempts_manifest`.

The run-store artifact registrar adds descriptors to the canonical artifact
index. T04 never overwrites the shared artifact index directly.

## 19. Manifest and Revisioning

The manifest records T02/T03 input checksums, profile registry version,
configuration hash, counts by profile/outcome/confidence,
profile-alternative counts, ambiguous/unassigned counts, timeout use,
observability timing coverage, artifacts, elapsed time, and warnings.

Changing profiles or timeout configuration creates a new immutable attempt revision.

The manifest has `schema_version`, `tool="T04"`, analysis ID, status, T04
revision, T02/T03 parent revisions and manifest checksums, profile/visibility
registry identities, selected release/deployment, config hash, counts,
artifacts/collections, sampled issues and timing/peak RSS. Counts include
attempts, transitions, retries, assignments, relationships, ambiguous and
unassigned events, alternatives by status, stage timings by status,
provisional/incomplete attempts and warning codes.

T04 revision inputs are T02/T03 revisions and manifest checksums, capture
bounds/source checksum, profile/visibility registry checksums, selected
release/deployment overlays, canonical config, enabled behavior capabilities,
tool version and schema version. Runtime timestamps, elapsed time and output
checksums are not recursive revision inputs.

### 19.1 Runner blueprint

```python
def segment_attempts(req: SegmentAttemptsRequest) -> SegmentAttemptsResult:
    parent = validate_t02_t03_lineage(req)
    profiles = validate_profile_registry(req.profile_registry, req.policy_versions)
    validate_paths_and_capture(req, parent)
    revision = build_t04_revision(req, parent, profiles)
    existing = inspect_existing_attempts(req.run_dir, revision)
    if existing:
        return result_from_manifest(existing)

    staging = make_unique_staging_dir(req.run_dir / "staging", prefix="T04-")
    state = AttemptEngineState(revision=revision, profiles=profiles, config=req.config)
    writers = open_attempt_writers(staging)
    indexes = open_attempt_indexes(staging)
    issues: list[Issue] = []

    for frame_events in iter_primary_frame_batches(req.primary_reader, req.capture):
        validate_primary_batch(frame_events, parent.t02)
        identities = req.identity_graph.resolve_batch(frame_events)
        state.close_expired_before(frame_events[0].frame, writers, issues)
        state.process_frame(frame_events, identities, writers, issues)

    state.close_at_capture_end(req.capture, writers, issues)
    attempts = state.materialize_attempts_and_sequences()
    writers.write_final_attempt_records(attempts, state)
    indexes.build(attempts, state)
    close_flush_fsync(writers, indexes, enabled=req.config.fsync_outputs)
    counters = validate_staged_attempts(staging, attempts, state)
    descriptors = build_t04_descriptors(staging, counters, revision, parent)
    manifest = build_attempts_manifest(req, parent, profiles, revision,
                                       descriptors, counters, issues)
    validate_attempts_manifest(manifest, descriptors, counters)
    publish_staged_attempts(staging, manifest_last=True)
    return result_from_manifest(manifest)
```

Frame processing order is: resolve identity/profile trigger candidates; assign
non-trigger events; classify retry/new attempts; open attempts; append stage
transitions; evaluate same-frame terminals; update visibility/state. No thread
completion order may affect persisted ordering.

### 19.2 Publication invariants

Before publication T04 proves:

- Unique attempt, assignment, relationship, transition, retry, alternative and
  timing IDs.
- Every attempt has a genuine trigger/mid-capture basis and at least one event.
- Every event ID resolves to a primary T02 event and same-lineage T03 context.
- Every accepted assignment references one existing attempt/event; sharing is
  permitted by a persisted nesting rule.
- Attempt event lists equal accepted assignment projections and are ordered /
  duplicate-free.
- Parent/child/retry/transfer references are reciprocal, acyclic where
  required, and do not cross incompatible access contexts.
- Closed attempts never absorb later events; outcomes are terminal and bounds
  cover all assigned events.
- Sequence numbers are contiguous within each partition key.
- Alternatives contain exactly one selected profile and preserve all retained
  statuses/evidence.
- Timing/status semantics and visibility namespaces validate against shared
  models and the resolved registry.
- Every index entry resolves to a same-revision record/offset; descriptors and
  manifest counts match staged bytes.

## 20. Failure Semantics

- Invalid T02/T03 manifest: fatal.
- Mixed/stale T02-T03-reader lineage, incompatible profile registry or path
  escape: fatal.
- Unknown procedure trigger: create `unknown_procedure` only when a genuine trigger exists; warn.
- Maximum open-attempt limit exceeded: stop opening low-confidence attempts, mark partial, preserve events.
- Ambiguous assignment: nonfatal, persisted.
- Profile invariant or impossible terminal transition: warn/quarantine attempt; fatal only if output consistency cannot be maintained.
- Index/data mismatch or publication failure: fatal.

Ambiguity, profile alternatives, provisional starts and incomplete capture are
represented outcomes and do not alone make status partial. Status is partial
only when information is discarded or quarantined, such as weak candidate
truncation, open-attempt cap suppression or a recoverable malformed event.
Fatal errors publish no T04 manifest and leave prior revisions unchanged.

## 21. Performance and Resource Requirements

- Process ordered timelines incrementally per UE/context.
- Maintain only active attempts plus bounded recent closed-attempt state.
- Use indexes for event-to-identity access; do not rescan all events for every attempt.
- O(events * active profile candidates), with candidate profiles pruned by trigger type.
- Record events/sec, attempts/sec, maximum simultaneous open attempts, assignment ambiguity, and peak RSS.

## 22. Security and Privacy

- T04 receives primary capability interfaces only.
- Persist UE node IDs and masked aliases, not clear subscriber values in attempt files.
- Do not log request bodies or identifiers.
- Treat profile definitions/configuration as trusted versioned application data; reject arbitrary executable predicates.

## 23. Observability

Structured logs:

- `analysis_id`, `tool=T04`, `ue_id`, `attempt_id`, `profile_id`.
- Trigger/terminal event IDs and frames.
- Assignment rule, confidence bucket, retry/new-attempt decision.
- Outcome, completion reason, warning code, duration.

Metrics include attempts by profile/outcome, retry counts, timeout/incomplete counts, ambiguous assignment rate, and open-attempt high-water mark.

Minimum registered T04 issue codes are
`T04_UNKNOWN_PROCEDURE_TRIGGER`, `T04_PROFILE_AMBIGUOUS`,
`T04_ASSIGNMENT_AMBIGUOUS`, `T04_ASSIGNMENT_CANDIDATES_TRUNCATED`,
`T04_OPEN_ATTEMPT_LIMIT`, `T04_PROFILE_INVARIANT`,
`T04_TERMINAL_CONFLICT`, `T04_EVENT_QUARANTINED` and
`T04_OUTPUT_INVARIANT_FAILED`. Shared access/evidence violations use
`RUN_ACCESS_BOUNDARY` and `RUN_EVIDENCE_INTEGRITY`. Logs/issues never include
clear identifiers or request bodies.

## 24. Proposed Python Code Structure

```text
V2/harness/analysis/
  attempt_engine.py
  attempt_runtime.py
  attempt_assignment.py
  retry_classifier.py
  attempt_ids.py
  visibility.py
  request_signature.py
  profiles/
    base.py
    registry.py
    registration.py
    authentication.py
    service_request.py
    pdu_session.py
    emergency.py
    mobility.py
    handover.py
    roaming.py
    deregistration.py
V2/harness/storage/
  attempt_store.py
V2/harness/models/
  attempts.py
```

## 25. Implementation Sequence

1. Define profile, attempt, transition, retry, and assignment schemas.
2. Implement profile registry and basic registration/PDU profiles.
3. Implement event assignment and deterministic attempt IDs.
4. Implement retry/new-attempt decisions and terminal closure.
5. Implement visibility and capture-boundary behavior.
6. Add emergency, service request, deregistration, mobility, handover, and roaming profiles.
7. Add persisted indexes, revision manifest, and performance tests.

## 26. Tests

### 26.1 Unit tests

- Trigger and terminal matcher behavior.
- Deterministic attempt IDs and sequence numbers.
- Retry versus new transaction for every supported protocol identity.
- Timeout versus incomplete-capture logic.
- Conditional/optional/repeatable stages.
- Parent/child relationship and outcome propagation.
- Assignment confidence and ambiguity.
- Request signature exclusion of dynamic values.
- Profile alternatives with selected/rejected/disambiguated status and stable
  evidence.
- Stage timing rows for trigger, terminal and profile-owned anchors.
- Profile candidate scoring/margin/cap and stable tie ordering.
- Event assignment score terms, nesting sharing and weak/explicit cap behavior.
- Same-frame trigger/assignment/terminal ordering.
- Sequence assignment after materialization.
- Revision, descriptor, manifest and issue-code validation.

### 26.2 Integration tests

- Nine successful establishment/release cycles and failed tenth establishment.
- Same PDU session ID with different PTIs.
- Two UEs and overlapping procedures.
- Registration with nested authentication/security.
- Paging followed by service request.
- Periodic, mobility, emergency, and non-3GPP registration.
- Concurrent 3GPP/N3IWF registration, concurrent 3GPP/TNGF registration and
  N3IWF-to-TNGF/3GPP access mobility without attempt merging.
- Access-scoped deregistration for 3GPP, non-3GPP and both-access values.
- Xn path switch, N2 handover, and inter-AMF handover.
- Roaming home-routed and local-breakout procedures.
- Ambiguous profile families persist alternatives until evidence
  disambiguates them.
- Capture starting/ending mid-attempt.
- Missing reference-point/SBI visibility.
- Identical rerun returns the same revision; changed profile/config creates a
  sibling generation.
- Crash before manifest publication leaves no readable T04 result and preserves
  the prior revision.

### 26.3 Negative tests

- Same session ID on different UEs does not merge attempts.
- Timestamp overlap alone does not assign an event.
- Closed attempt does not absorb a new trigger.
- Primary segmentation cannot access NRF/UDR readers.
- Mixed T02/T03 revisions, stale graph reader, corrupt descriptor, executable
  profile predicate, symlink escape and unresolved output invariant fail
  without a T04 manifest.
- Clear subscriber values do not appear in attempts, indexes, manifest, issues
  or logs.

### 26.4 Golden tests

- A fixed capture produces byte-stable attempts, assignments, alternatives,
  transitions, retries, relationships, timings and indexes after normalizing
  generated timing fields only.
- Golden coverage includes retries/new attempts, reused PDU session IDs,
  overlapping UEs, concurrent access families, one ambiguous assignment,
  timeout versus incomplete capture and roaming topology attachment.
- Reader/index lookups by attempt, UE, event, access context, session,
  procedure/profile and outcome return expected same-revision records.

## 27. Acceptance Criteria

T04 is complete when:

1. Every persisted attempt has a valid trigger or explicit mid-capture basis.
2. Repeated cycles and reused identifiers remain separate when transactions differ.
3. Retry/new-attempt decisions are reason-coded and profile-driven.
4. Every assigned event records correlation confidence and evidence.
5. Ambiguous and unassigned events remain queryable.
6. Success, failure, abort, timeout, and incomplete-capture are distinguished correctly.
7. Reference-point and SBI visibility prevents false failure closure.
8. Profile alternatives are persisted and never mixed with root-cause alternatives.
9. Stage timing observations are emitted for applicable trigger/terminal anchors.
10. Attempt IDs and sequence numbers are deterministic.
11. Supported scenario families have versioned profiles and fixture coverage.
12. Primary-only data access is enforced.
13. Every published record/index/descriptor satisfies section 19.2 and the
    manifest is published last.
14. T04 mints a deterministic immutable revision and never overwrites a
    sibling generation.

## 28. Mechanical Implementation Checklist

1. Import shared models and define the section 4/5 record schemas without
   local warning, descriptor, revision or visibility duplicates.
2. Register all T04/RUN issue codes used by the tool.
3. Validate config thresholds, positive bounds and candidate/open-attempt caps.
4. Validate run-relative paths and create `staging/T04-<uuid>/` only.
5. Validate T02/T03 manifests, reader revisions, analysis IDs and parent
   lineage.
6. Validate capture checksum/bounds and resolved profile/visibility registry
   compatibility/checksums.
7. Build the T04 revision before deterministic child IDs and return an existing
   identical generation when present.
8. Implement bounded primary frame batching and same-revision T03 batch lookup.
9. Implement indexed profile candidate lookup and section 8.1 scoring.
10. Implement trigger/mid-capture validation and deterministic attempt IDs.
11. Implement open-attempt indexes by UE/access/session/transaction/profile.
12. Implement section 9.1 assignment scoring, ambiguity and cap behavior.
13. Implement access-family separation and explicit transfer/nesting rules.
14. Implement retry/new-attempt decisions and deterministic retry records.
15. Implement stage transitions, occurrence ordering and branch conflicts.
16. Implement terminal precedence, timeout/visibility and incomplete-capture
    closure.
17. Implement parent/child/supersedes/access-transfer relationships.
18. Build stable request signatures excluding dynamic identifiers.
19. Materialize profile alternatives and deterministic disambiguation statuses.
20. Emit T04-owned stage timing rows with shared status/anchor semantics.
21. Attach the exact T03 topology interval/revision active at the trigger.
22. Close all attempts at terminal/timeout/capture end; persist no open outcome.
23. Assign deterministic per-context/procedure sequence numbers.
24. Write every data file, including empty files, in canonical order.
25. Build attempt/UE/event/procedure indexes with revision and byte offsets.
26. Flush/fsync and run every section 19.2 invariant against staged bytes.
27. Build descriptors and register them through run-store artifact ownership.
28. Build/validate the manifest with full counts and sampled issues.
29. Publish data, indexes and manifest last; clean only this staging tree on
    failure.
30. Add unit, integration, negative/access-control and golden tests from
    section 26.
