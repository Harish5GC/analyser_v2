# Handover — V2 Review-Backlog Implementation

**Date:** 2026-06-10. **Resumed; P0 is complete.**
**Task:** implement the consolidated review backlog in `reviews/TODO.md`
(authoritative; the root `TODO.md` is a stale earlier copy — do not work from
it). Backlog items are V2-001..V2-062 in priority groups P0-P4.

## 1. State at handover

- **V2-001, V2-002** — done previously by the user (orchestration contract:
  `requirement.md` §7.1, `architecture.md` §3.2, `LLD.md` §19 + §21
  orchestration tests, plus T12/T14/T15/T16/T17/T24/T25 lineage contracts).
  Checked `[x]` in `reviews/TODO.md`.
- **P0 (V2-003..V2-017, V2-061)** — complete. The resume added the normative
  `profiles/README.md`, reconciled release/deployment fields in T04/LLD,
  added the LLD/tools index pointers, replaced T14's duplicate stage literals
  with shared `EvidenceStage`, updated `reviews/TODO.md`, and synchronized the
  root `TODO.md`.
- **P1 (V2-018..034)** — not started, with one exception: `LLD.md` §29
  (Configuration and Policy Resolver) was written early because P0's
  `DetectionContext` depends on it. That covers the LLD half of **V2-021**;
  residual V2-021 work: reference the resolver from T11/T12/T21 (replace
  their bare `policy_version` strings the way T06-T09 now do) and add a
  reliability bullet to `requirement.md` §11.
- **P2/P3/P4** — not started. Note: several P3 items are already partially
  satisfied by P0 side effects (see §5).

## 2. P0 changes made this session (by file)

### LLD.md
- §2 CLI: added `--max-model-attempts`, `--model-attempt-order` + explanation
  (V2-003).
- §3 `HarnessConfig`: added `max_model_attempts_per_run: int = 5`,
  `model_attempt_order` enum (V2-003).
- §4.4: `IdentityLinkThresholds` named bands (auto `0.90` / warn `0.70`),
  band semantics, validation rule; `IdentityEdge.confidence` → `Decimal`
  (V2-016).
- §4.6 `FailureCandidate`: added `score_terms: list[ScoreTerm]`,
  `detector_score` → `Decimal`, plus the field-ownership table
  (severity/capture_phase/relevance owned by detectors; `call_impact` owned
  by T23, default `"inconclusive"`; T12 never mutates) (V2-006).
- **New §4.10**: `EvidenceStage = Literal["primary","dependency_expanded"]`
  and `ModelPass = Literal["initial","final"]`, mapping + legal transitions.
  Decision: the T15 packet stage value `"initial"` was renamed to
  `"primary"`; the phrase "initial packet" remains as defined prose alias for
  the primary-stage packet (V2-004).
- §11: `DetectionContext` model (capture bounds, phase reader, visibility,
  assignment confidence, `ResolvedPolicySet`) (V2-007).
- §12: canonical 13-term score model with term table, old→new name mapping
  (`detector_score→detector_base` etc.), `ScoreTerm` definition (V2-014).
- §13: lexicographic baseline selection (eligibility filters, then
  similarity-band → nearest-earlier-frame → UUID), numeric score demoted to
  audit-only (V2-015).
- §14: scenario models now defer to T13 §5a / T14 as owners (V2-010).
- §15: `pass_stage: EvidenceStage`; initial-packet naming note (V2-004).
- §17: canonical `DependencyReasonCode`, extended `DependencyEvidenceRequest`
  (`initial_evidence_ids`, `fqdn`, `masked_correlation_key`), executor
  adaptation rules (routing on `tool` only),
  `DependencyInspectionResult = NRFInspectionResult | UDRInspectionResult`
  union with derived (not stored) discriminator (V2-005).
- §19.2 rows renamed (`T15 primary / T16 initial`, `T15 dependency-expanded /
  T16 final`); §19.4 manifest key `"T15:initial"` → `"T15:primary"` (V2-004).
- §21.1: 12 new test bullets covering threshold boundaries, stage-enum
  legality, request adaptation, evidence registry, candidate ownership,
  narration policy, resolver failures, revision determinism, lexicographic
  baselines, issue-code lint.
- §22: new step 1 (build shared foundations first), renumbered.
- **New sections (appended):** §23 Shared Model Registry (owner table +
  definitions: `StateTransition`, `RetryRecord`, `InterfaceVisibility`,
  `CaptureMetadata`, `FrameWindow`, `PhaseRoll`, `ArtifactDescriptor`,
  `CollectionDescriptor`, `EventMatcher`, `ConditionExpression`,
  `DependencyEventSummary`, `DependencyBaselineComparison` +
  `UDRBaselineComparison` (merged hierarchy), `ServiceRequirement`,
  `NFEntityReadiness`, `MaskedUEIdentity`, `ProblemDetailsSummary`,
  `MissingField`, `FieldDifference`, `StageAlignment`; warning aliases
  declared type aliases of `Issue`) (V2-009);
  §24 Evidence Registry (minting at detection time, UUIDv5 identity with
  `revision_scope`, storage/index, dedup/collision, T15 selects-never-mints)
  (V2-008); §25 Revision Model (`RevisionEnvelope`, sha256-prefixed digest,
  per-tool minting, T01 rerun rejection) (V2-011); §26 Issue Registry
  (`Issue` model, namespaced codes, `issue_registry.yaml`) (V2-012); §27 Run
  Manifest and Analysis State (`StageInvocation`, `RunManifest`,
  `AnalysisState`, run-status aggregation pointer to T17 §10) (V2-013);
  §28 Model Narration Policy (selector precedence, ordering modes, cap,
  disclosure) (V2-003); §29 Configuration and Policy Resolver (V2-021, LLD
  half).

### requirement.md
- §3.2: added `max_model_attempts_per_run`, `model_attempt_order` (V2-003).
- §4 report contents: skipped-narration disclosure bullet (V2-003).
- §7 T07 bullet: "initiating message without an expected outcome" is a
  request-only observation for T09; T09 solely owns implicit candidates
  (V2-061).

### architecture.md
- §3.2 "Optional model pass" row: narration policy + disclosure (V2-003).

### tools/
- **T01**: §14 rejects re-decode into a published run dir (V2-011).
- **T02**: §7 re-run wording — T02 mints its own sibling revision (V2-011).
- **T03**: config `auto_link_threshold`/`warning_link_threshold` replace
  `minimum_auto_link_confidence`; §9 band semantics; boundary tests (V2-016).
- **T04**: result gains `revision: str`; §6 points to `profiles/README.md`
  as the normative registry contract (V2-011/V2-017).
- **T06**: request takes `context: DetectionContext` (replaces
  `capture_phases` + `operation_policy_version`); §5 ownership/evidence-
  registry note; §6 resolver note (V2-006/007/008).
- **T07**: non-goals state T09's sole ownership of implicit absence + the
  `0.65` base; inputs/request take `context` (replace `visibility` +
  `cause_dictionary_version`); §16 ownership note (V2-006/007/061).
- **T08**: inputs/request take `context` (replaces `policy_version`); §14
  ownership note (V2-006/007).
- **T09**: inputs/request take `context` (replace `visibility`/`capture`/
  `timeout_policy_version`); sole-owner statement; profile-registry pointer;
  §15 ownership note (V2-006/007/017/061).
- **T11**: §5 eligibility now uses deferred `population_baselines` capability
  wording (no behavioral "V2.1"); §7 rewritten lexicographic with audit-only
  score; §12/§24.3 "V2.1" phrases replaced (V2-015, partial V2-045).
- **T12**: `pass_stage: EvidenceStage`; §8 notes LLD §12 is canonical +
  immutable-candidate consumption (V2-004/006/014).
- **T13**: new §5a defines `ScenarioSelectors`, `ExpectedRequest`,
  `ScenarioTimeScope`, `ScenarioTextSpan`, `ScenarioConflict`,
  `ScenarioMatcher`, `ScenarioCondition`, `CheckpointOrdering`, validation
  limits, local/remote masking modes (V2-010).
- **T15**: `pass_stage: EvidenceStage`, initial packet = `primary` stage;
  §8 renamed packet model to `PacketEvidenceRecord` — a projection of the
  registry record; T15 never mints evidence IDs (V2-004/008).
- **T16**: `pass_stage: ModelPass` + pairing note; §8 mirrors canonical LLD
  §17 request (added `fqdn`) and notes executor adaptation (V2-004/005).
- **T17**: §6 discloses `model_narration: "skipped_by_policy"` attempts from
  the manifest (V2-003).
- **T18**: §7 resolution chain references the §24 evidence registry; note
  that evidence resolves in `provider=none` runs (V2-008).
- **T24/T25**: §4 preambles describe construction from the canonical request
  via the executor; no redundant dependency-type field (V2-005).

## 3. Completed resume steps

1. **Created `profiles/README.md`** (V2-017) with:
   - Profile file format: YAML realization of T04 §6 `ProcedureProfile` +
     T09 §5 `StageDefinition`; one file per `profile_id`; UTF-8; schema
     validated via the §29 resolver. Add the missing `release` and
     `deployment_profile` dimensions (LLD §10 `ProcedureDefinition` has
     `release`; T04's model lacks it — reconcile by adding overlay fields).
   - Release/deployment overlays: base profile + overlay patches keyed by
     release/deployment; overlays may change stage applicability, never stage
     identity.
   - Conditional grammar: the allowlisted `ConditionExpression` facts —
     publish the fact vocabulary table here (LLD §23.3 and T13 §5a already
     point at this document for it).
   - Ordering semantics, version/checksum rules (per §25), compatibility and
     migration notes, authoring/review process.
   - Traceability table: every `requirement.md` §8 flow (8.1-8.10) and
     acceptance criteria 13-18 → profile ID(s) → fixture(s). Mark not-yet-
     authored profiles explicitly so V2-054's completeness CI can key off it.
2. Added the two pointers: `LLD.md` section 10 and `tools/README.md`.
3. Marked V2-003..V2-017 and V2-061 complete in `reviews/TODO.md`; V2-021
   remains open. Synchronized root `TODO.md` from the authoritative copy.

## 4. Key decisions already made (do not re-litigate)

- `EvidenceStage` values are `primary|dependency_expanded`; T15's former
  `initial` stage value was renamed to `primary`; "initial packet" survives
  as defined prose only. `ModelPass` stays `initial|final`.
- Tool specs are normative where they were richer; LLD was back-ported to
  match (T12 score terms, T11 lexicographic intent, T16 request fields).
- Evidence records are minted at detection/extraction time by the first
  citing tool through `evidence/registry.py`; T15 only selects.
- Warning aliases (`DecodeWarning` etc.) are type aliases of `Issue`, not
  classes; codes namespaced `T##_`/`RUN_`.
- Each tool mints its own revision; callers never mint (T02 wording fixed).
- New LLD sections are appended (§23-§29) to avoid renumbering §1-§22.
  Planned future sections from the P2 plan: §30 Authenticated Cursor
  Envelope (V2-039), §31 Run Lifecycle and Retention (V2-037), masking
  policy section (V2-038). The §23 registry table already forward-references
  "section 30" for the cursor envelope — keep that number when implementing.

## 5. Notes for P1-P4 (not started)

- P1 sketches from this session: V2-018 (T20 editcap pre-slice + honest scan
  cost + optional T01 packet-offset index), V2-027 (visibility registry is
  release/profile-aware; add N7/N13/N35/N36/N37; `InterfaceVisibility` keys
  already declared registry-driven in LLD §23.1), V2-028/029 (PFCP
  association + Session Report rules in T08), V2-032 (`ServiceRequirement`
  already defined in LLD §23.4 — T22 snapshot still needs the field change).
- P3 partials already done as side effects: V2-045 (T11's behavioral "V2.1"
  text replaced; remaining: version-vocabulary note in `requirement.md` §1
  and a repo-wide audit), V2-049/V2-050/V2-051/V2-052/V2-053 untouched.
- Useful verification greps:
  `grep -rn "minimum_auto_link_confidence\|capture_phases:\|operation_policy_version\|cause_dictionary_version\|timeout_policy_version" tools/` (should only hit T11/T12/T21 for the resolver residual);
  `grep -rn "pass_stage" tools/ LLD.md` (only `EvidenceStage`/`ModelPass`
  typed fields and `primary|dependency_expanded|initial|final` values);
  `grep -rn "V2.1" tools/ requirement.md LLD.md` (remaining hits are
  non-behavioral or P3 scope).

## 6. Session task list state

Task #1 (P0) complete. Tasks #2-#5 (P1-P4) remain pending. TODO checkbox
update and root synchronization are complete.
