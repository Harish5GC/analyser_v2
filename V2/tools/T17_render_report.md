# T17 `render_report` Implementation Specification

## 1. Purpose

`render_report` produces the authoritative machine-readable `report.json` and human-readable `report.md` for an analysis run. It combines deterministic attempt/request/diagnostic/scenario results with optional model narrative while preserving evidence provenance and limitations.

## 2. Non-Goals

T17 must not:

- Recompute or change deterministic results.
- Accept model claims without valid references.
- Embed unbounded raw protocol data.
- Hide partial decoder/provider/evidence failures.
- Expose clear subscriber identities or secrets.
- Delete/modify source artifacts.

## 3. Inputs and Boundary

- Run/capture/decoder/normalization manifests.
- T03-T14 deterministic artifacts.
- Optional T16 validated diagnoses.
- Optional T24/T25 inspection results and dependency-expanded T12/T14 revisions.
- Reporting/privacy policy.

T17 reads validated result objects and evidence metadata, not raw partitions.

For each attempt with dependency inspection, T17 receives and preserves:

- primary T12 result and optional dependency-expanded child result;
- primary T14 validation and optional dependency-expanded child validation;
- every requested T24/T25 outcome, including `empty`, `partial`, `failed` and excluded integrity-invalid results;
- initial T16 result and optional final T16 result with packet lineage;
- a deterministic change summary for primary candidate, alternatives, confidence and scenario checkpoint statuses.

T17 must not present an initial model diagnosis as final after a valid expanded result exists, and must not hide a failed inspection merely because another inspection produced usable evidence.

## 4. Python Tool Contract

```python
class RenderReportRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    analysis_state: AnalysisState
    report_policy: ReportPolicy


class RenderReportResult(BaseModel):
    schema_version: Literal["2.0"]
    analysis_id: UUID
    status: Literal["success", "partial", "failed"]
    report_json: ArtifactDescriptor
    report_markdown: ArtifactDescriptor
    report_manifest: ArtifactDescriptor
    warnings: list[str]
```

## 5. Authoritative Report Model

```python
class AnalysisReport(BaseModel):
    schema_version: Literal["2.0"]
    analysis_id: UUID
    status: Literal["success", "partial", "failed"]
    generated_at: datetime
    capture: CaptureReport
    pipeline: PipelineReport
    ue_results: list[UEResult]
    scenario: ScenarioReport | None
    dependency_inspections: list[DependencyInspectionReport]
    provider: ProviderReport | None
    warnings: list[ReportWarning]
    timings: dict[str, int]
    evidence_integrity: EvidenceIntegrityReport
```

`report.md` is rendered from this validated object. JSON is authoritative.

## 6. UE and Attempt Result

Each attempt report includes:

- Attempt ID, sequence, procedure/profile/subtype.
- Masked UE/session aliases.
- T05 UE request and missing/conflicting fields.
- Outcome/completion reason and visibility.
- Deterministic primary/alternative/downstream candidates.
- Confidence, rationale codes, limitations.
- Key timeline and baseline comparison.
- Scenario checkpoints scoped to the attempt.
- Dependency inspection summaries when performed.
- Model explanation and deterministic conflicts, clearly labeled advisory.
- Evidence references/frames.
- Roaming topology, confidence, evidence terms and competing alternatives from
  T03, rendered separately from each failure candidate's independently mapped
  fault domain.

Successful attempts may be summarized more compactly but remain listed.

Every failed/incomplete attempt that was analyzed deterministically but
skipped by the model-narration policy (`LLD.md` section 28) is explicitly
disclosed: the attempt carries a `model_narration: "skipped_by_policy"`
marker with the cap and ordering values that caused the skip, taken from the
run manifest's `skipped_model_attempt_ids`. Absence of model narrative is
never presented as absence of analysis.

## 7. Required Answer Order

For each failed attempt, report in this order:

1. What the UE/network requested.
2. Where the procedure failed.
3. Deterministic root cause and confidence.
4. Exact evidence frames/IDs.
5. Advisory model explanation.
6. Alternatives/downstream effects.
7. Timeline/comparison/scenario/dependency details.
8. Limitations and warnings.

This order is stable for machine and human consumers.

## 8. Deterministic Versus Model Authority

- Deterministic observed values/ranking/checkpoints are authoritative.
- Model text appears under `model_diagnosis`.
- A model-selected candidate differing from T12 appears as `deterministic_conflict`, not replacement.
- Invalid/unvalidated model output is omitted and provider warning included.
- Deterministic-only reports are first-class outputs.

## 9. Evidence References

```python
class ReportEvidenceRef(BaseModel):
    evidence_id: UUID
    event_ids: list[UUID]
    frames: list[int]
    protocol: str
    summary: str
    source_available: bool
```

Every major request/root cause/scenario claim must cite evidence. Reports do not expose filesystem absolute paths or full raw data. Local tools use IDs with T18.

## 10. Status Aggregation

Run status rules:

- `failed`: no usable analysis/report due to fatal decode/evidence/report publication.
- `partial`: usable report with protocol absence/failure, evidence integrity warning, detector partial, or provider issue.
- `success`: required deterministic stages complete; individual attempts may still have failed calls.

A failed UE call does not make the analysis run status `failed`.

## 11. Warning Model

Warnings include code, severity, stage/tool, affected attempt/evidence, message, and remediation. Categories:

- Capture/decode/normalization.
- Identity/attempt ambiguity.
- Visibility/truncation.
- Evidence integrity.
- Scenario/parser.
- Provider/model.
- Dependency inspection rejected/inconclusive.
- Report masking/truncation.

## 12. Timeline and Comparison Rendering

- Markdown timeline defaults to bounded key events; JSON may include configured larger bounded list.
- Use frame/time/protocol/stage/label/message/evidence IDs.
- Comparison shows selected baseline and first divergence, not raw diff/all previous attempts.
- Repetitive retries are grouped.

## 13. Dependency Inspection Rendering

Report:

- Why inspection was requested.
- Validated query scope.
- NRF/UDR tool used.
- Causal/contributing/unrelated/inconclusive result.
- Recovery/readiness/transaction summary.
- Evidence IDs and frames.

If no inspection occurred, do not imply NRF/UDR was healthy; state it was not inspected when relevant to limitations.

## 14. Privacy and Redaction

Report policy controls:

- UE aliases and optional last digits.
- IP/FQDN masking.
- Location/PLMN treatment.
- Body/detail excerpts.
- Scenario text masking.

Never include authorization headers, authentication vectors/keys, API keys, full subscription payloads, or unbounded bodies. Redaction is applied before both JSON and Markdown rendering.

## 15. Markdown Rendering

Markdown sections:

- Executive summary.
- Capture/pipeline status.
- Per-UE/per-attempt findings.
- Scenario validation.
- Dependency investigations.
- Warnings/limitations.
- Evidence index.

Tables must remain readable for bounded values. Large nested structures use concise bullet/code summaries, not raw JSON dumps.

## 16. JSON Schema and Compatibility

- Persist `report.schema.json` with semantic version.
- New optional fields may be added in minor versions.
- Breaking changes require schema major change/migration note.
- Consumer-facing enum values are stable/versioned.
- Report includes input artifact schema/revision metadata for audit.

## 17. Atomic Publication

1. Build in-memory/bounded report model.
2. Validate Pydantic/JSON schema.
3. Render JSON to staging, flush/fsync/close.
4. Render Markdown from validated model, flush/fsync/close.
5. Compute checksums/sizes.
6. Publish JSON, Markdown, then report manifest atomically.
7. Update run manifest only after all report artifacts exist.

Never publish Markdown based on an invalid/unpublished JSON model.

## 18. Report Manifest

Records:

- Report schema/version and policy hash.
- Input artifact/revision checksums.
- Included UE/attempt counts.
- Model/provider/dependency revisions.
- Redaction/truncation counts.
- Output descriptors/checksums.
- Generation timing/status/warnings.

## 19. Failure Semantics

- Invalid deterministic input: fail report build with stage/error reference.
- Invalid model result: omit model section, mark partial.
- Missing evidence for major conclusion: evidence-integrity warning; fail only if no auditable conclusion remains.
- Markdown rendering failure: report publication partial/failure according to policy; JSON remains authoritative only if safely published with manifest state.
- Masking failure: fatal.
- Disk/fsync/rename failure: fatal publication.

## 20. Performance and Resource Requirements

- Stream/limit large attempt/timeline lists where possible.
- Do not load raw evidence artifacts.
- Report size limits configurable; evidence index remains bounded with IDs.
- Record build/render/write latency, JSON/Markdown sizes, attempts, evidence refs, redactions, and peak memory.

## 21. Security

- Escape Markdown/control characters from untrusted protocol/model text.
- Avoid rendering HTML from evidence/model output or sanitize if enabled.
- No absolute paths or secrets.
- Validate all evidence/model strings and length bounds.
- Reports default local permissions no broader than T01 run policy.

## 22. Observability

Logs include analysis/report revision, status, counts, warning categories, redactions, model inclusion, output sizes/checksums, and duration.

Metrics include report success/partial/failure, size, render latency, warning counts, model-conflict count, evidence integrity issues, and redactions.

## 23. Proposed Python Code Structure

```text
V2/harness/reporting/
  builder.py
  status.py
  evidence_refs.py
  privacy.py
  markdown.py
  manifest.py
  validation.py
V2/harness/models/
  reports.py
V2/harness/schemas/
  report.schema.json
```

## 24. Implementation Sequence

1. Define report/warning/evidence/provider schemas.
2. Implement deterministic per-attempt report builder.
3. Add scenario/dependency/model sections and authority checks.
4. Add privacy/redaction and Markdown renderer.
5. Add atomic publication/manifest/schema validation.
6. Add compatibility/golden/security tests.

## 25. Tests

### 25.1 Unit tests

- Run status aggregation.
- Deterministic/model conflict.
- Required evidence references.
- Warning aggregation.
- Privacy/redaction and Markdown escaping.
- Atomic publication ordering.
- Schema compatibility.

### 25.2 Golden reports

- Successful call.
- Explicit HTTP/PFCP/NAS/NGAP failures.
- Inconclusive truncated capture.
- Multiple UEs and repeated attempts.
- Scenario success/failure.
- Local/OpenRouter failure fallback.
- NRF/UDR inspection causal/unrelated/not performed.
- Empty/partial/failed dependency inspections with admitted-versus-excluded status.
- Primary ranking preserved beside a dependency-expanded ranking that changes the primary candidate.
- Primary scenario validation preserved beside an expanded validation that changes only dependency-aware checkpoints.
- Initial and final model results linked to their exact packet generations.
- Model conflict with deterministic ranking.

### 25.3 Negative tests

- Secret values never appear in JSON/Markdown.
- Invalid evidence/model IDs rejected/omitted.
- Untrusted HTML/Markdown injection escaped.
- No absolute filesystem paths.
- Expanded result with missing/stale parent or dependency revision is rejected rather than rendered as authoritative.

## 26. Acceptance Criteria

T17 is complete when:

1. `report.json` validates and is authoritative.
2. `report.md` is generated from the same validated model.
3. Every major request/root-cause/checkpoint claim cites evidence.
4. Deterministic results cannot be silently overwritten by model narrative.
5. Partial capture/provider/evidence conditions are visible.
6. Dependency inspection status is explicit and does not imply uninspected health.
7. Primary and dependency-expanded T12/T14 generations and their deterministic differences remain auditable.
8. Initial/final model results are labeled by packet/pass lineage, and a failed inspection is never hidden by another successful inspection.
7. Sensitive data and absolute paths are excluded.
8. Publication is atomic and auditable.
