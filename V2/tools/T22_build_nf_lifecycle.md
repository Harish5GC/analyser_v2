# T22 `build_nf_lifecycle` Implementation Specification

## 1. Purpose

`build_nf_lifecycle` builds lifecycle and service-readiness history for the NF instances/services selected by an approved T24 NRF inspection. It determines whether pre-call registration/discovery/status/deregistration anomalies recovered before the selected attempt.

## 2. Invocation Boundary

T22 is not a top-level primary pipeline tool. It is an internal helper owned by `NRFInspector` and may run only after `DependencyToolExecutor` validates an initial model request for `inspect_nrf_flow`.

T22 receives a scoped `NRFEventReader`; it cannot scan the entire NRF partition without approved selectors/window.

## 3. Non-Goals

T22 must not:

- Run during ordinary primary analysis.
- Rank call root cause.
- Assume an NRF 4xx is call-related.
- Merge all instances of the same NF type.
- Infer readiness from one hostname substring.
- Read UDR/primary partitions beyond supplied attempt symptom metadata.
- Send full NF profiles to a model.

## 4. Python Tool Contract

```python
class BuildNFLifecycleRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    approved_request_id: UUID
    attempt_id: UUID
    frame_start: int
    frame_end: int
    attempt_start_frame: int
    selectors: NRFSelectors
    policy_version: str


class BuildNFLifecycleResult(BaseModel):
    schema_version: Literal["2.0"]
    approved_request_id: UUID
    attempt_id: UUID
    selected_entities: list[NFEntityRef]
    lifecycles: list[NFInstanceLifecycle]
    readiness_snapshot: NFReadinessSnapshot
    unresolved_failures: list[NFLifecycleFailure]
    recovered_failures: list[NFLifecycleFailure]
    ambiguous_events: list[NFAmbiguousEvent]
    warnings: list[str]
```

## 5. Selector Model

```python
class NRFSelectors(BaseModel):
    nf_instance_id: str | None = None
    nf_type: str | None = None
    service_name: str | None = None
    fqdn: str | None = None
    endpoint: str | None = None
    consumer_nf: str | None = None
```

At least one high-value selector is required. `nf_type` alone may be accepted only with service/consumer and a bounded window. Wildcard/capture-wide selectors are rejected by T24 validator.

## 6. NF Entity Identity

Identity confidence order:

1. Exact NF instance ID.
2. NF instance ID from registration profile linked to FQDN/endpoint.
3. FQDN + NF type + service identity.
4. Endpoint + NF type/service within bounded validity interval.
5. NF type alone: ambiguous collection, not one instance.

```python
class NFEntityRef(BaseModel):
    entity_id: UUID
    nf_instance_id: str | None
    nf_type: str | None
    fqdn: str | None
    endpoints: list[str]
    service_names: list[str]
    identity_confidence: Literal["high", "medium", "low"]
    identity_evidence_ids: list[UUID]
```

## 7. Lifecycle States

Instance states:

- `unknown`.
- `starting`.
- `registered`.
- `available`.
- `degraded`.
- `suspended`.
- `deregistering`.
- `deregistered`.
- `unavailable`.

Service readiness is tracked separately because an NF instance can be registered while one service is suspended/unavailable.

## 8. Lifecycle Event Model

```python
class NFLifecycleEvent(BaseModel):
    lifecycle_event_id: UUID
    entity_id: UUID
    service_name: str | None
    frame: int
    timestamp: Decimal | None
    operation: str
    http_status: int | None
    state_before: str
    state_after: str
    service_state_before: str | None
    service_state_after: str | None
    classification: Literal[
        "normal", "failure", "recovery", "benign_startup_cleanup",
        "discovery_observation", "ambiguous"
    ]
    evidence_ids: list[UUID]
    rationale_codes: list[str]
```

## 9. Input Event Types

Relevant scoped NRF records:

- NF registration/create/replace.
- NF profile update/patch.
- Heartbeat and status update.
- NF status subscription/notification.
- Deregistration/delete.
- NF discovery request/response.
- SCP delegated-discovery request/response exposing target selection.
- ProblemDetails/timeouts/retries for those operations.

Successful records are included when necessary to establish state/recovery, not as model noise.

## 10. Transition Rules

### Registration

- Successful create/replace -> `registered`, then service states determine `available/degraded/suspended`.
- Registration request observed without response -> `starting` plus unresolved operation, not automatically unavailable.
- Registration 4xx/5xx -> failure; prior known state remains unless response explicitly invalidates it.

### Update/heartbeat

- Successful update/heartbeat preserves registration and updates service readiness.
- Failed heartbeat/update records failure; one failure does not automatically mark unavailable unless policy/explicit state supports it.
- Repeated failures may produce degraded/unavailable according to policy and evidence.

### Deregistration

- Request -> `deregistering` when prior registration known.
- Success -> `deregistered`.
- 404 with no prior observed instance -> idempotent cleanup candidate.
- 404 followed by successful registration before attempt -> `benign_startup_cleanup`.
- Failed deregistration while instance remains healthy does not make service unavailable.

### Explicit service status

- `REGISTERED/AVAILABLE` -> available.
- `SUSPENDED` -> suspended.
- Explicit unavailable/profile removal -> unavailable/deregistered as applicable.

## 11. Recovery Linking

A failure is recovered only when a later event for the same confident entity/service restores the required state. Recovery record includes:

- Failure event/frame.
- Recovery event/frame.
- State restored.
- Whether recovery occurred before attempt start.
- Identity confidence.

A successful operation for another instance of the same NF type does not automatically recover the selected instance, though it may satisfy service availability for discovery if T24 selection analysis proves it.

## 12. Benign Startup Cleanup Pattern

Required conditions:

- Pre-attempt deregistration/delete/cleanup operation.
- Response indicates missing/stale resource such as 404.
- Same entity or intended registration identity is later successfully registered/available before attempt.
- No call-time discovery/selection symptom links the cleanup error.

If identity is low-confidence, classify as ambiguous recovered startup rather than definitively benign.

## 13. Discovery Observations

Discovery results are observations, not authoritative lifecycle transitions by themselves:

- Returned instance/service supports observed availability at that frame.
- Empty/no matching result supports absence for requested service/criteria.
- Stale endpoint selection may reveal lifecycle inconsistency.
- Discovery response cannot establish that an unreturned instance is globally unavailable without query criteria.

T24 `discovery.py` uses lifecycle output and selection chain together.

## 14. Service-Level State

Track each selected service:

```python
class NFServiceState(BaseModel):
    service_name: str
    api_versions: list[str]
    endpoints: list[str]
    status: Literal["unknown", "available", "degraded", "suspended", "unavailable"]
    valid_from_frame: int
    valid_to_frame: int | None
    evidence_ids: list[UUID]
```

Instance readiness for a call depends on requested service/version/endpoint, not just NF registration.

## 15. Readiness Snapshot

```python
class NFReadinessSnapshot(BaseModel):
    attempt_id: UUID
    frame: int
    entities: list[NFEntityReadiness]
    required_service: str | None
    available_candidates: list[UUID]
    unresolved_failure_ids: list[UUID]
    status: Literal["ready", "not_ready", "partially_ready", "unknown"]
    evidence_ids: list[UUID]
```

Use only events at or before attempt start. Later recovery is reported separately and cannot retroactively change snapshot.

## 16. Window and Pre-Call Expansion

T24 supplies approved window. T22 may request one bounded earlier extension only when:

- Selected instance registration starts before current window.
- A failure/recovery pair crosses the start boundary.
- T24 validator approves the expanded lower bound.

No automatic capture-wide scan. Expansion reason and effective bounds are persisted.

## 17. Ambiguity Handling

Ambiguity sources:

- Missing instance ID.
- Same FQDN/endpoint reused.
- Multiple instances of same NF type/service.
- Incomplete registration profile.
- Capture starts after registration.

Persist competing entity mappings and lower readiness confidence. Do not force a lifecycle merge.

## 18. Deterministic IDs and Revision

Entity/event/failure IDs derive from approved request ID, normalized identity key, operation/event ID, and policy version. Result revision includes scoped NRF event checksums, selector/effective window, phase revision, and policy.

## 19. Persistence

T22 artifacts are nested under T24 result:

```text
evidence/dependency/<request-id>/nrf/
  lifecycle_events.jsonl
  lifecycle_entities.jsonl
  readiness_snapshot.json
  lifecycle_manifest.json
```

Full NRF records remain in retained partition; lifecycle artifact contains summaries/evidence refs.

## 20. Failure Semantics

- Invocation without approved T24 request/capability: access denied.
- Missing required selector/window: validation error.
- No matching events: successful unknown lifecycle/snapshot.
- Low-confidence identity: partial/ambiguous, not fatal.
- Corrupt hidden artifact: evidence-integrity failure for inspection.
- Invalid transition sequence: preserve events, warn, keep state unknown where needed.
- Expansion denied: continue bounded result with limitation.
- Publication failure: fail T24 lifecycle stage.

## 21. Performance and Resource Requirements

- Query NRF index by approved selectors/window.
- O(selected events log entities), not full partition.
- Maintain state per selected entity/service only.
- Bound profiles/endpoints/services retained in summaries.
- Record events scanned/matched, entities/services, expansion, ambiguity, latency, and bytes read.

## 22. Security and Privacy

- Scoped `NRFEventReader` capability only.
- Full NF profiles/endpoints stay local unless T15 masking allows summaries.
- No subscriber data expected; redact tokens/cert/auth headers if present.
- Treat NF profile/body text as untrusted.
- Audit selector/window and records accessed.

## 23. Observability

Logs include approved request/attempt/entity hash/service, operation/state transition, recovery relation, readiness status, ambiguity/warning, bounds, and duration.

Metrics include lifecycle invocations, matched events/entities/services, recovered/unresolved/benign cleanup, readiness status, expansions, ambiguity, and latency.

## 24. Proposed Python Code Structure

```text
V2/harness/dependency_tools/nrf/
  lifecycle.py
  identity.py
  transitions.py
  recovery.py
  readiness.py
  models.py
V2/harness/storage/
  nrf_reader.py
  dependency_store.py
```

## 25. Implementation Sequence

1. Define selector/entity/event/service/snapshot schemas.
2. Implement scoped entity identity and transition rules.
3. Add service-level state and readiness snapshot.
4. Add recovery/benign-cleanup linking.
5. Add discovery observations and bounded expansion.
6. Add persistence/audit/performance/ambiguity tests.

## 26. Tests

### 26.1 Unit tests

- Entity identity confidence and non-merge.
- Every registration/update/status/deregistration transition.
- Service versus instance state.
- Recovery linking before/after attempt.
- Benign 404 cleanup pattern.
- Snapshot ignores later recovery.
- Deterministic IDs/revision.

### 26.2 Integration tests

- Capture starts before NFs: cleanup 404 then healthy registration.
- Registration failure remains unresolved at call start.
- Instance registered but required service suspended.
- Multiple instances, one available/one failed.
- Empty discovery despite registered profile.
- Delegated discovery and endpoint selection.
- Capture starts after registration.
- Bounded earlier expansion.

### 26.3 Negative tests

- Successful registration of another instance does not recover selected one automatically.
- Discovery result does not globally define all lifecycle state.
- T22 cannot run without approved T24 capability.
- T22 cannot scan full partition without selectors/window.

## 27. Acceptance Criteria

T22 is complete when:

1. Lifecycle state is tracked per confident instance and service.
2. Registration/readiness and service readiness are distinct.
3. Failure/recovery pairs identify exact frames and pre-attempt status.
4. Benign startup cleanup is recognized only with recovery evidence.
5. Readiness snapshot uses only evidence available at attempt start.
6. Ambiguous identities remain explicit.
7. Access remains bounded to the approved T24 request.
8. Results are auditable and suitable for T23/T24/T15.
