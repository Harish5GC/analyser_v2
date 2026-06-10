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
- **P1 (V2-018..034)** — V2-018 through V2-027 are complete and checked.
  V2-028 through V2-034 now have completed document-level passes in
  `architecture.md` and `LLD.md`, but the remaining files are still being
  reconciled and the items remain unchecked.
- **P2 (V2-035..044)** — completed at document level in `architecture.md` and
  `LLD.md` only. Tool specs, requirements and TODO boxes remain open.
- **P3 (V2-045..053)** — completed at document level in `architecture.md`
  and `LLD.md`. Requirements/tools and TODO boxes remain open.
- **P4** — not started. Note: several P3/P4 items are already partially
  satisfied by earlier side effects (see §5).

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
- **T01**: completed P0-P3 tool-spec pass. It now uses the canonical
  `decoder/` tree, descriptor/collection validation, T01 revision minting,
  capability-gated packet-access index, canonical timestamp/revision inputs,
  shared `Issue` warning alias, PFCP unknown-vs-inconclusive boundary and
  aligned tests/acceptance. §14 rejects re-decode into a published run dir
  (V2-011).
- **T02**: completed P0-P3 tool-spec pass. It now consumes resolved
  `ProtocolCodepointRegistry` and partition policy handles, writes logical
  `CanonicalEvent` records with `timestamp_precision`, `validation_status`,
  `raw_refs` and shared `Issue` values, publishes the canonical
  `normalized/events/` plus shared `indexes/` tree with descriptors, mints its
  own revision, forces NAS/NGAP/PFCP to primary, preserves PFCP unknown as
  observed data, enforces partition-reader boundaries and aligns
  tests/acceptance. It also now includes a mechanical implementation
  blueprint, writer/counter invariants, protocol-specific normalizer
  algorithms, manifest/descriptor shapes and a small-model implementation
  checklist.
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
  wording (no behavioral milestone-label switch); §7 rewritten lexicographic
  with audit-only score; §12/§24.3 milestone-label phrases replaced
  (V2-015, partial V2-045).
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
   was completed later in P1. Synchronized root `TODO.md` from the
   authoritative copy.

## 3.1 P1 work completed before this handover

- **V2-018:** T20 now separates result, decoder and source-scan bounds; uses
  indexed or honestly accounted scan-preslice access; preserves HTTP2/HPACK,
  SCTP/NGAP and fragment context; maps slice frames to source; and records
  cleanup/provenance. T01 defines the optional packet-access index.
- **V2-019:** T15/T16 share a resolved token budget with pinned exact/fallback
  counting, explicit reserves/precedence, mandatory-first below-target
  behavior, pre-send recounting and deterministic revision inputs.
- **V2-020:** T16 owns a crash-safe per-pass call ledger: maximum three calls,
  one shared transport retry, and one mutually exclusive fallback-or-repair
  call with every outcome/terminal reason persisted.
- **V2-021:** Section 29 now resolves profiles, policies, dictionaries and
  model/tokenizer profiles at startup into immutable schema/checksum-validated
  handles. Bare policy-version request fields were removed from T04,
  T11-T14 and T21-T23.
- **V2-022:** T22/T24 share one T24-owned expansion counter and persist every
  proposal, clamp, denial, reason and original/requested/effective bound.
- **V2-023:** T23 has an executable ordered decision table for eligibility,
  links, temporal reachability, recovery, contradictions, earliest cause,
  counterfactual and terminal impact classification.
- **V2-024:** Registration Complete is conditional on a release/profile rule
  derived from Registration Accept; true/false/unknown behavior and fixtures
  are defined.
- **V2-025:** T03 produces time-bounded roaming topology alternatives and
  independent fault-domain maps for T04/T11/T12/T14/T17.
- **V2-026:** T03/T04/profile contracts now define separate gNB, N3IWF and
  TNGF access contexts, access-scoped registration state, concurrent-access
  non-merge rules, mobility relations and scoped deregistration.
- **V2-027:** Visibility is release/profile-aware and split into
  reference-point, SBI service and SBI API namespaces. The flat LLD §10.3
  enum was replaced by `VisibilityRegistry`, `VisibilityRequirement.domain`
  and `key`; `InterfaceVisibility` now persists `reference_points`,
  `sbi_services` and `sbi_apis`; N7, N13, N35, N36 and N37 are required
  release/profile reference-point entries where applicable. `Nnrf` remains an
  SBI service key, while NRF-to-NRF roaming visibility uses reference point
  `N27`. Requirements, architecture, `profiles/README.md`, T04, T09, T14 and
  detector context wording were aligned, with LLD test bullets for namespace
  validation and release/profile visibility fixtures.

Current next open item: V2-028. The user then asked to batch the rest of P1
and later asked to stop and write this handover before that batch was
finished.

## 3.2 File-by-file state after architecture and LLD passes

The current worktree contains partial multi-file markdown edits for V2-028
through V2-034 plus completed architecture/LLD document-level passes for
P1/P2. **Do not mark any V2-028..V2-034 or P2 items complete from the current
state.** The authoritative `reviews/TODO.md` and root `TODO.md` still have
only V2-027 checked; V2-028..V2-034 and all P2 items remain open until the
remaining files are reconciled.

Edits already applied in the current P1/P2 batch:

- **LLD.md**
  - LLD pass for P1/P2 is complete at the document level.
  - P1 additions cover profile alternatives, PFCP association/session-report
    observations, directional F-TEID tunnel-role contracts,
    ServiceRequirement[] readiness, reachability/MT delivery ownership and
    the observability timing checklist.
  - P2 additions cover the canonical run tree, artifact and collection
    descriptors, report `pipeline` schema, secret references, logical JSONL
    event schema, evidence/revision immutability, authenticated cursors,
    run-store lifecycle/retention, masking policy, canonical
    decimal/timestamp semantics and P2 tests.
- **requirement.md**
  - PFCP requirements now mention association fields, Session Report fields,
    directional F-TEID roles, and T08 checks for association/report handling.
  - T22 requirements now mention ServiceRequirement[] readiness aggregation.
  - §8.3 now sketches reachability-loss / mobile-terminated delivery
    ownership across T07/T08/T09.
  - §8.12 now says profile alternatives must be persisted/rendered separately
    and every attempt must publish the timing checklist.
- **architecture.md**
  - Architecture pass for P1/P2 is complete at the document level.
  - P1 additions cover the resolver, T20 targeted re-decode bounds,
    token/retry ledgers, shared T24/T22 expansion accounting, T23 impact gate,
    conditional Registration Complete, roaming/access context behavior,
    release/profile visibility, PFCP association and Session Report handling,
    directional F-TEID roles, profile alternatives, ServiceRequirement-based
    readiness, reachability/MT delivery ownership and timing checklist.
  - P2 additions cover the canonical run artifact tree, descriptors and
    collection descriptors, run-store lifecycle/retention/leases/legal hold,
    masking policy, authenticated cursor envelope, report `pipeline` schema
    and status mapping, secret references, JSONL-vs-logical event schema,
    canonical decimal/timestamp persistence and external cursor/revision
    guarantees.
- **profiles/README.md**
  - Added §8.1 with profile alternatives, reachability/MT delivery ownership
    and timing-key declarations.
  - Traceability rows now include `service.mt_delivery`, new
    reachability/MT/timing fixtures and acceptance coverage rows.
- **tools/T04_segment_attempts.md**
  - `ProcedureAttempt` model now has `profile_alternatives` and
    `stage_timings`; output layout includes `profile_alternatives.jsonl` and
    `stage_timings.jsonl`; tests/acceptance mention alternatives/timings.
- **tools/T08_find_pfcp_failures.md**
  - Large partial rewrite: result now includes `association_observations` and
    `session_reports`; new `PFCPAssociationObservation`,
    `PFCPSessionReportObservation`, `TunnelRoleExpectation` models; sections
    for association/node-state, Session Report handling, directional
    consistency, persistence, tests and acceptance.
- **V2-027 cleanup files also remain modified:** T06/T07/T09/T11/T14 wording
  from the completed V2-027 visibility work.

Known incomplete parts outside `architecture.md` and `LLD.md`:

- T08 needs a careful consistency pass after the large section renumbering:
  verify all internal section references, model imports, line wraps and
  acceptance wording.
- T22 still needs its concrete `NFReadinessSnapshot` schema updated to carry
  `requirements: list[ServiceRequirement]`, per-service aggregation details,
  missing/partial observations, tests and acceptance text. T24/T23 may need
  aligned wording because they consume T22 readiness.
- T17 still needs report-model fields and rendering rules for
  `profile_alternatives`, `stage_timings`, PFCP association/session-report
  summaries and ServiceRequirement readiness.
- T21 should point at LLD §23.6 timing anchors/precision where it owns phase
  timing rows.
- T07/T09/T05/T14 likely need smaller reachability/MT-delivery and timing
  alignment, beyond the earlier V2-027 visibility edits.
- T11/T12 may need small wording so profile alternatives are never baseline
  or root-cause alternatives.
- TODO completion state must stay unchanged until all the above are
  reconciled and consistency greps pass.

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
- New LLD sections are appended (§23-§33) to avoid renumbering §1-§22.
  §30 is Authenticated Cursor Envelope, §31 Run Lifecycle and Retention,
  §32 Masking Policy and §33 Canonical Numeric and Timestamp Semantics.

## 5. Notes for P1-P4

- P1 V2-028..V2-034 and P2 V2-035..V2-044 are complete in
  `architecture.md` and `LLD.md` only. Resume file-by-file from §3.2 and
  complete the remaining docs/tool specs before checking any of those boxes.
- P3 V2-045..V2-053 now has architecture and LLD document-level passes. They cover
  version vocabulary/capability gates, canonical NAS registry and primary
  routing, T10 timeline cap/labels, operational flags, `primary_internal`,
  shared provider abstraction, resource-profile hardware wording, T15
  mandatory-evidence guarantee and PFCP `unknown` versus diagnostic
  `inconclusive`. Remaining files and TODO boxes are still open.
- `tools/T01_decode_capture.md` and `tools/T02_normalize_events.md` now have
  P0-P3 passes. Continue tools file-by-file with T03 next unless the user
  redirects.
- Useful verification greps:
  `grep -rn "minimum_auto_link_confidence\|capture_phases:\|operation_policy_version\|cause_dictionary_version\|timeout_policy_version" tools/` (should only hit T11/T12/T21 for the resolver residual);
  `grep -rn "pass_stage" tools/ LLD.md` (only `EvidenceStage`/`ModelPass`
  typed fields and `primary|dependency_expanded|initial|final` values);
  `grep -rn "V2\\.1" tools/ requirement.md LLD.md` should return no
  behavioral milestone-gated requirements after the P3 pass.

## 6. Session task list state

Task #1 (P0) complete. P1 is in progress with V2-018 through V2-027 complete.
V2-028..V2-034 and P2 V2-035..V2-044 are complete only in architecture/LLD and
remain unchecked. P3 V2-045..V2-053 is complete only in architecture/LLD and
remains unchecked, with T01 additionally reconciled through P3. P4 remains
pending. TODO synchronization is current for
completed items.
