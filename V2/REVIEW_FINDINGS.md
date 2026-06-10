# V2 Harness — Design Review Findings

Review of the V2 5G Call Failure Analysis Harness specification set
(`requirement.md`, `architecture.md`, `LLD.md`, `tools/T01–T25`).
This repository is design-only; no source code exists yet. Findings are
refinements to a sound design, ordered by severity. Each item lists the
location, the problem, and a concrete fix.

Status legend: ☐ open · ☑ resolved

---

## Overall assessment

The design is strong and internally cross-referenced. Core ideas are sound and
structurally enforced rather than merely stated:

- Deterministic-first / model-as-explainer split — the model never sees raw
  decoder trees and cannot loop.
- Reader-capability isolation (`PrimaryEventReader` vs `NRFEventReader` /
  `UDREventReader`, owned only by `dependency_tools.executor`) makes the
  "NRF/UDR stays out of the first pass" rule impossible to violate by accident.
- Three-tier evidence retention (immutable PCAP → full decoder output →
  normalized index) with checksums and atomic publication.
- Attempt-as-first-class-object with "PDU session ID is never the sole key."
- 5G/3GPP protocol modeling judged technically accurate (NAS/NGAP/PFCP/NRF/SCP).
- Shell-injection safety in T20 (`tshark` arg-list only, AST display filters).

The findings below do not change the architecture. The HIGH items are genuine
cross-document contradictions that will cause implementer divergence if not
reconciled before coding begins.

---

## HIGH

### ☐ H1 — Ownership of `FailureCandidate.call_impact` / `relevance` on primary candidates
- **Where:** `LLD.md` §4.6; `tools/T06`–`T09`.
- **Problem:** `call_impact` and `relevance` are required model fields, but the
  primary detectors T06–T09 run *before* any NRF/UDR inspection. `call_impact`
  (causal/contributing/unrelated/inconclusive) is fundamentally a dependency
  concept produced by T23. Only T06 fully assigns `relevance`; T07/T08/T09 set
  neither. A required field is silently never produced.
- **Fix:** Declare explicit ownership. Suggested default: detectors emit
  `relevance=attempt_related` and `call_impact=inconclusive`; T12/T23 refine.

### ☐ H2 — T12 ranking formula contradicts the authoritative formula
- **Where:** `LLD.md` §12 vs `tools/T12` §8.
- **Problem:** LLD defines exactly 8 terms. T12 renames three
  (`detector_score`→`detector_base`, `baseline_divergence_bonus`→
  `first_divergence_bonus`, `ambiguous_correlation_penalty`→
  `assignment_ambiguity_penalty`) and adds five
  (`exact_attempt_link_bonus`, `terminal_explanation_bonus`,
  `inspected_dependency_impact_bonus`, `recovered_retry_penalty`,
  `contradiction_penalty`). This is the most load-bearing algorithm in the
  system.
- **Fix:** Pick the canonical term set, make both docs identical, and explicitly
  note any renamed term as the same concept.

### ☐ H3 — T11 baseline selection: weighted score vs. strict priority order
- **Where:** `LLD.md` §13 vs `tools/T11` §5/§7.
- **Problem:** Contract is lexicographic (same UE → same procedure → success →
  highest signature similarity → nearest earlier frame). T11 instead *sums*
  `temporal_nearness_weight` + `request_signature_similarity`, which can pick a
  temporally-near baseline over a higher-similarity one.
- **Fix:** Implement the lexicographic order, or have the contract bless the
  weighted model. One of them must change.

### ☐ H4 — "V2.1" used as a behavioral constraint while system is "V2" / schema "2.0"
- **Where:** `tools/T11` §5/§12/§19 and negative tests; naming is inconsistent
  across all four document tiers.
- **Problem:** T11 gates "no future-success baseline" on "V2.1". Unclear whether
  this is a real version constraint or stale text — it materially changes T11
  behavior.
- **Fix:** Establish one naming convention (product = V2, milestone = V2.1,
  schema = 2.0) and audit every behavioral "V2.1" reference.

### ☐ H5 — T20 frame/time selection re-dissects the whole capture
- **Where:** `tools/T20` §9 vs §1/§19 acceptance criteria.
- **Problem:** Selection via `tshark -Y "frame.number>=X && frame.number<=Y"`
  is a post-dissection read filter; it re-dissects the entire PCAP, defeating
  the "narrowly bounded region" performance claim.
- **Fix:** Pre-slice with `editcap -r`/`-A`/`-B` before `tshark`, or restate the
  selection semantics as dissection-time filtering with no read bound.

### ☐ H6 — T15 token-budget precedence undefined
- **Where:** `tools/T15` §10.
- **Problem:** `available_input = context − reserved − output − margin` is never
  reconciled with the contract's "target 2,000–8,000, hard 12,000 for local."
  No rule for `available_input > 12000` or `< target`.
- **Fix:** State `effective_budget = min(available_input, hard_max)` and define
  behavior when `effective_budget < target_min`.

---

## MEDIUM

### ☐ M1 — T03 auto-link threshold contradiction
- **Where:** `tools/T03` §4 (`minimum_auto_link_confidence = 0.75`) vs contract.
- **Problem:** Contract: auto-link ≥ 0.90, link+warning 0.70–0.89, candidate
  < 0.70. A 0.75 auto-link default silently lowers the auto-merge bar.
- **Fix:** Reconcile the three numbers (0.90 / 0.70 / 0.75); make the band
  structure explicit in config.

### ☐ M2 — T07 scoring omits the `0.65` missing-response base; T07/T09 boundary unclear
- **Where:** `tools/T07` §1/§2/§16 vs `LLD.md` §11.2.
- **Problem:** T07 lacks the contract's 0.65 missing-response base and adds an
  undocumented 0.80 term. T07 §1 claims "initiating msg w/o outcome / missing
  transition" in scope, but T07 §2 defers missing transitions to T09.
- **Fix:** Restore/reconcile the 0.65 base; state which tool owns "initiating
  message without outcome."

### ☐ M3 — T07/T08 receive no capture-phase / boundary input
- **Where:** `tools/T07`, `tools/T08` request models.
- **Problem:** Both must set `capture_phase` and make visibility-gated decisions
  but take no `CapturePhaseReader`/`CaptureMetadata` (T06 and T09 do).
- **Fix:** Add the capture-phase/boundary input to T07 and T08.

### ☐ M4 — Versioned config passed as bare string with no resolution mechanism
- **Where:** `tools/T06`–`T09` (`*_policy_version: str`).
- **Problem:** Algorithms need the resolved policy/cause/timeout table, not a
  version string. No spec states how it is loaded or how a missing version fails.
- **Fix:** Specify resolution of a version string to its table, and the
  missing/mismatched-version failure behavior.

### ☐ M5 — T16 retry budgets can compound past "retry malformed ONCE"
- **Where:** `tools/T16` §6/§12/§14/§15.
- **Problem:** Structured→JSON fallback, repair retry, and transport retry can
  sum to ~4 model calls per pass with no defined global ceiling.
- **Fix:** Define a per-pass total-attempts cap and precedence among the three
  retry types.

### ☐ M6 — T24/T25 request schemas lack the dependency routing field
- **Where:** `LLD.md` §17 (`tool`), `tools/T23` (`dependency_type`),
  `tools/T24`/`T25` (neither).
- **Problem:** Dispatch is "model requests `dependency_type=NRF/UDR`," and
  `DEPENDENCY_TIMEOUT_SUSPECTED` is valid for both partitions, but the T24/T25
  requests carry no routing key, and the field name differs across docs.
- **Fix:** Add one consistently-named routing field to T24/T25 requests and
  align `LLD.md` §17 / T23 / T24 / T25.

### ☐ M7 — T22 `NFReadinessSnapshot.required_service` is singular
- **Where:** `tools/T22` §15 vs §6.
- **Problem:** Cannot model an attempt needing multiple services across multiple
  NFs, which T22 §6 otherwise supports.
- **Fix:** Make readiness per-(instance, service).

### ☐ M8 — T25 masked-correlation key: unstated re-identification risk
- **Where:** `tools/T25` §5/§6/§19.
- **Problem:** Accepts `masked_correlation_key` selectors and sends "stable
  aliases" to the model without requiring the mask be salted/keyed and
  local-only. An unsalted deterministic alias is a persistent pseudonym a remote
  provider can correlate across captures.
- **Fix:** Require a salted/keyed, local-only masking transform; state it
  explicitly at the UDR remote boundary.

### ☐ M9 — T15 trimming does not encode "shorten bodies as the final fallback"
- **Where:** `tools/T15` §11.
- **Problem:** Contract: bodies shortened only before dropping mandatory
  evidence. T15 places body shortening mid-sequence rather than as the last
  resort before `EVIDENCE_BUDGET_EXCEEDED`. (The "never remove" invariant holds.)
- **Fix:** Make body-shortening the explicit final step before raising
  `EVIDENCE_BUDGET_EXCEEDED`.

### ☐ M10 — T23 `causal` vs `contributing` boundary ambiguous
- **Where:** `tools/T23` §6 vs §8.
- **Problem:** §6 strong conditions gate eligibility; §8 `causal` adds a
  counterfactual no single §6 condition establishes.
- **Fix:** State that §6 gates eligibility and §8 + §10 (earliest/ordering) +
  §13 (no hard contradiction) jointly decide causal-vs-contributing.

### ☐ M11 — T22 + T24 compounding window-expansion budgets
- **Where:** `tools/T24` §15, `tools/T22` §16.
- **Problem:** T24 permits one expansion; T22 independently grants one earlier
  extension. Neither says whether T22's counts against T24's single-expansion
  cap — risk of two effective expansions per attempt.
- **Fix:** State that all window expansions for an attempt share one budget,
  enforced by the T24 validator.

### ☐ M12 — Output-layout divergence
- **Where:** `tools/T03`/`T04`/`T05` vs `requirement.md` §4 / `LLD.md` §7.1.
- **Problem:** Specs write `normalized/identity/`, `normalized/attempts/`,
  `normalized/requests/`, none of which appear in the authoritative layout.
- **Fix:** Add these to the documented layout or relocate; ensure path
  validation accepts them.

---

## LOW

### ☐ L1 — T02 NAS message-type table not specified
`tools/T02` calls the NAS map "table-driven" but never lists codepoints
(0x41/0x42/0x44…). Also, partition routing rules cover only HTTP/2 — state that
NAS/NGAP/PFCP default to `primary` so partition assignment is total.

### ☐ L2 — T05/T18 dependency-partition leak path
`tools/T05` may dereference full evidence via T18, which could surface an
NRF/UDR-routed HTTP body. Add a constraint that T05's T18 access is restricted
to primary-partition source refs.

### ☐ L3 — `detector_score` scalar vs. stored score terms
`LLD.md` §4.6 has scalar `detector_score`, but T06–T09 each store multiple named
score terms. Add a `score_terms` field or state where the breakdown lives.

### ☐ L4 — T08 outcome enum lacks `inconclusive`
Inconsistent with the harness-wide visibility→inconclusive rule. A PFCP request
with partially-invisible N4 response should be `inconclusive`, not `unknown`.

### ☐ L5 — T17 field rename `decoder` → `pipeline`
`requirement.md`/`LLD.md` `AnalysisReport.decoder` is rendered as `pipeline` in
`tools/T17` §5. Reconcile or update the contract.

### ☐ L6 — T19 derived-artifact path shape
Contract: `evidence/context/<query-id>.jsonl` (file). T19 §13 uses a directory.
The directory form is richer but diverges; reconcile the documented path.

### ☐ L7 — T10 nits
Label set has 8 values vs. the contract's 5 (declare the contract list
non-exhaustive); model-mode `limit` should be hard-clamped at 20, not just
defaulted; §15 "fail if evidence for major conclusion unresolved" borrows
conclusion language T10 §2 forbids — reword to "evidence referenced by a primary
candidate or failed checkpoint."

### ☐ L8 — T13 undefined nested types and local-masking ambiguity
`ScenarioSelectors`, `ExpectedRequest`, `ScenarioTimeScope`, `CheckpointOrdering`,
etc. are referenced but never defined. Clarify whether masking is universal or
remote-only for the `local` provider.

### ☐ L9 — T01 `--output-dir` semantics and collection descriptor
`--output-dir` is ambiguous (run dir vs. `decoded/` subdir). The "collection
descriptor" for many HTTP stream documents has no model in
`DecodeCaptureResult.artifacts`.

### ☐ L10 — T08 §11 N3 F-TEID direction under-specified
Tunnel-consistency check lumps "FAR/PDR" together. Specify direction: DL F-TEID
(from NGAP) → FAR Outer Header Creation; UL F-TEID (from PFCP) → created PDR.

### ☐ L11 — Core-document nits
- `LLD.md` §19 pseudocode calls `detector_registry.detect(attempt, events)` but
  the `FailureDetector` protocol (§11) requires a third `context` arg.
- CLI flags `--include-nrf-success`, `--include-udr-success`,
  `--unmasked-local-evidence` (`LLD.md` §2) are not in `requirement.md` §3.2.
- `architecture.md` §1 ASCII diagram boxes are misaligned (cosmetic).

---

## Recommended reconciliation order

1. **H2, H3** — the two core algorithms (ranking, baseline selection) diverge
   from the LLD.
2. **H1** — assign ownership of `call_impact` / `relevance` on primary candidates.
3. **H4** — settle V2 / V2.1 / 2.0 naming and audit behavioral "V2.1".
4. **M1, M2, M6** — numeric/threshold/field mismatches between LLD and specs.
5. **H5, H6, M5, M8** — technically substantive (tshark bounding, token budget,
   retry compounding, UDR masking).

A short **"Contract Conformance" appendix in `LLD.md`** that pins the canonical
scoring formula, threshold bands, `call_impact` ownership, and the
dependency-routing field — then checks each Txx spec against it — would close the
bulk of the HIGH/MED items. Most LOW items are one-sentence clarifications.
