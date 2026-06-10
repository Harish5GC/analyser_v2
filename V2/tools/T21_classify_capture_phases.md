# T21 `classify_capture_phases` Implementation Specification

## 1. Purpose

`classify_capture_phases` builds deterministic capture-wide and per-attempt frame/time intervals that distinguish pre-call startup activity, active UE procedures, gaps between attempts, and post-call activity.

Phase is temporal context only. It never proves that an event is related or unrelated to a call.

## 2. Non-Goals

T21 must not:

- Delete, hide, or diagnose startup/background traffic.
- Treat every event during an active call as call-related.
- Read NRF/UDR partitions directly.
- Build NF lifecycle/readiness; T22 does that inside T24.
- Infer call windows solely from HTTP/PFCP when N1/N2 attempt anchors are absent.
- Override T04 attempt boundaries without recording a conflict.

## 3. Inputs and Boundary

- T04 attempt records and trigger/terminal evidence.
- Capture first/last frame/time.
- Primary event frame/time index.
- Versioned phase policy/pre/post roll.

T21 labels primary events and persists reusable intervals. T24/T25 later apply those intervals to selected hidden dependency events without giving T21 dependency-reader access.

## 4. Python Tool Contract

```python
class ClassifyCapturePhasesRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempts_revision: str
    capture: CaptureMetadata
    config: CapturePhaseConfig


class CapturePhaseConfig(BaseModel):
    phase_policy: ResolvedPolicy
    default_pre_roll_frames: int = 20
    default_post_roll_frames: int = 20
    default_pre_roll_seconds: Decimal | None = None
    default_post_roll_seconds: Decimal | None = None
    max_roll_frames: int = 500
    max_roll_seconds: Decimal = Decimal("30")


class ClassifyCapturePhasesResult(BaseModel):
    schema_version: Literal["2.0"]
    status: Literal["success", "partial", "unknown"]
    intervals: list[CapturePhaseInterval]
    primary_event_labels_artifact: ArtifactDescriptor
    manifest: ArtifactDescriptor
    visibility: Literal["anchored", "partial", "unknown"]
    warnings: list[str]
```

## 5. Phase Interval Model

```python
class CapturePhaseInterval(BaseModel):
    interval_id: UUID
    phase: Literal[
        "capture_preamble", "attempt_active", "between_attempts",
        "capture_postamble", "unknown"
    ]
    start_frame: int
    end_frame: int
    start_timestamp: Decimal | None
    end_timestamp: Decimal | None
    attempt_ids: list[UUID]
    core_start_frames: dict[UUID, int]
    core_end_frames: dict[UUID, int]
    roll_applied: dict[UUID, PhaseRoll]
    confidence: Literal["high", "medium", "low"]
    reason_codes: list[str]
```

Intervals cover the capture frame range without gaps. Overlapping active attempts share an interval with multiple attempt IDs.

## 6. Anchor Selection

Preferred start anchors:

- T04 trigger event from NAS/NGAP.
- Explicit mid-capture profile trigger.

Preferred end anchors:

- Terminal success/failure/abort event.
- Valid timeout deadline within capture.
- Last assigned event for incomplete capture, marked lower confidence.

T21 uses T04 boundaries as authoritative unless they are invalid/outside capture; conflicts are warnings and produce partial status.

## 7. Core and Expanded Attempt Windows

For each attempt:

- Core window: T04 start/end.
- Expanded window: configurable pre/post roll clamped to capture bounds and policy maximum.

Pre-roll exists to include immediately preceding primary dependency messages that may belong to the call. Post-roll includes terminal cleanup/effects. Roll does not assign events to attempts; it only creates temporal context.

Profile-specific roll may override defaults, for example longer pre-roll for paging/handover context transfer.

## 8. Phase Construction Algorithm

1. Validate capture bounds and attempt intervals.
2. Create core/expanded interval edges for every attempt.
3. Sweep sorted frame edges to build non-overlapping phase segments.
4. Segments covered by expanded attempts -> `attempt_active` with all IDs.
5. Before first anchored attempt -> `capture_preamble`.
6. Gaps between anchored attempts -> `between_attempts`.
7. After final anchored attempt -> `capture_postamble`.
8. Regions lacking reliable anchor/timestamp/frame basis -> `unknown`.
9. Merge adjacent intervals only when phase, attempt set, confidence, and roll metadata are equivalent.

## 9. No N1/N2 Visibility

If no reliable NAS/NGAP attempt trigger exists:

- Do not classify entire capture as preamble.
- Set visibility `unknown`.
- Produce one or more `unknown` intervals covering the capture.
- Preserve any T04 provisional mid-capture attempts as low-confidence active intervals only if profile rules support them.

Primary HTTP/PFCP activity cannot independently define UE call start in T21.

## 10. Overlapping Attempts

- Multiple UEs may overlap.
- One UE may have nested/parallel attempts.
- Active interval retains all attempt IDs.
- Per-event phase label can contain multiple active attempt IDs.
- Attempt relevance remains determined by T03/T04/detectors.

No event is duplicated in persisted primary event storage; labels reference intervals/attempt IDs.

## 11. Frame and Time Handling

Frame range is authoritative for coverage. Timestamps add roll/deadline precision and validation.

- Missing timestamp: use frame roll and mark limitation.
- Non-monotonic timestamp: preserve frame ordering, warn.
- Multiple packets same timestamp: frame disambiguates.
- Capture metadata bounds must contain all attempt anchors.

## 12. Event Label Model

```python
class CapturePhaseLabel(BaseModel):
    event_id: UUID
    interval_id: UUID
    phase: str
    active_attempt_ids: list[UUID]
    inside_core_attempt_ids: list[UUID]
    inside_roll_only_attempt_ids: list[UUID]
```

Labels contain no relevance/call-impact conclusion.

## 13. Applying Intervals to Dependency Events

T24/T25 may call a pure helper:

```python
def label_frame(interval_reader: CapturePhaseReader, frame: int) -> CapturePhaseLabel
```

The helper reads persisted intervals only and does not expose hidden records to T21. Dependency inspectors combine phase with their own correlation/impact analysis.

## 14. Startup Scenario Handling

Example:

```text
frame 100  NRF deregistration -> 404
frame 140  NF registration -> 201
frame 1000 UE Registration Request
```

Frames 100/140 are `capture_preamble`. T21 does not decide whether 404 is benign/causal. If T24 is later requested, T22/T23 use the phase plus recovery evidence.

## 15. Output Layout

```text
normalized/phases/
  capture_phase_intervals.jsonl
  primary_event_phase_labels.jsonl
  capture_phase_manifest.json
indexes/
  frame_phase_index.jsonl
  attempt_phase_index.jsonl
```

Frame-phase index supports logarithmic interval lookup.

## 16. Deterministic Revision

Revision hash includes capture bounds, attempts revision, profile/phase policy, and roll configuration. Same inputs produce identical interval IDs:

```text
UUIDv5(analysis_id + phase + bounds + sorted attempt IDs + phase_policy.sha256)
```

Changed attempt boundaries/policy create a new immutable revision.

## 17. Failure Semantics

- Invalid capture bounds: fatal.
- Attempt outside capture: clamp only if evidence supports boundary; otherwise reject attempt from phase build and mark partial.
- Overlapping contradictory intervals: supported if attempts differ; same-attempt inverted/invalid bounds are errors.
- No reliable anchors: successful unknown result.
- Missing timestamp: nonfatal frame-based result.
- Index/data publication failure: fatal.

## 18. Performance and Resource Requirements

- O(A log A + E) for attempts/labels using sweep and interval index.
- Do not compare every event with every attempt.
- Stream event labels using frame-phase lookup.
- Record attempts/intervals/events labelled, overlap high-water mark, unknown coverage, roll sizes, and latency.

## 19. Security and Privacy

- Primary artifacts only.
- Phase files contain internal attempt/event IDs and frames, no subscriber values/bodies.
- Treat attempt artifacts as validated inputs.
- Path-safe atomic publication.

## 20. Observability

Logs include attempt/interval IDs, bounds, roll, confidence, conflict/warning code, overlap count, visibility, and duration.

Metrics include interval counts by phase, preamble/postamble sizes, overlap distribution, unknown coverage, missing timestamps, and latency.

## 21. Proposed Python Code Structure

```text
V2/harness/analysis/
  capture_phases.py
  phase_sweep.py
  phase_labels.py
  phase_policy.py
V2/harness/storage/
  phase_store.py
  frame_phase_index.py
V2/harness/models/
  phases.py
```

## 22. Implementation Sequence

1. Define interval/label/config/manifest schemas.
2. Implement anchor/bounds validation and roll calculation.
3. Implement interval sweep/merge.
4. Add frame-phase index and streaming event labels.
5. Add no-anchor/overlap/capture-boundary behavior.
6. Add revision/persistence/performance tests.

## 23. Tests

### 23.1 Unit tests

- Core/expanded window and clamping.
- Sweep interval construction/merge.
- Multiple overlap sets and same-frame boundaries.
- Missing/non-monotonic timestamps.
- Deterministic interval IDs/revision.
- Frame-phase lookup.

### 23.2 Integration tests

- Capture before NF startup and first UE.
- Two overlapping UEs.
- Nested registration/authentication attempts.
- Back-to-back attempts and between-attempt gap.
- Capture starts/ends mid-attempt.
- No NAS/NGAP visibility.
- Path-switch-only provisional attempt.

### 23.3 Negative tests

- Active phase does not change T04 event assignment.
- Entire no-anchor capture is not labelled preamble.
- T21 cannot read NRF/UDR partitions.

## 24. Acceptance Criteria

T21 is complete when:

1. Capture frame coverage has deterministic non-overlapping phase intervals.
2. Overlapping attempts retain every active attempt ID.
3. Core versus roll-only membership is explicit.
4. Missing N1/N2 anchors produce unknown, not false preamble.
5. Phase never implies attempt relevance or causality.
6. Dependency inspectors can apply intervals without exposing hidden readers to T21.
7. Results are immutable, indexed, and reproducible.
