# V2 Harness — Second-Pass Review (Fable)

Independent second review of the V2 specification set (`requirement.md`,
`architecture.md`, `LLD.md`, `tools/T01–T25`). This pass did three things:

1. **Verified** the headline findings of the first review (`REVIEW_FINDINGS.md`)
   against the actual spec text.
2. **Traceability audit** — mapped requirement.md §8/§11/§12 (all 27 acceptance
   criteria) to owning tool specs, in both directions.
3. **Cross-cutting drift sweep** — checked vocabulary and shared mechanisms
   (error codes, ID spaces, revisions, cursors, masking, timestamps, tokens,
   manifests) across all 25 specs at once, which per-group review misses.

Verdict up front: the first review's findings **hold** (every spot-checked HIGH
verified verbatim, one is worse than reported), and this pass found **two new
HIGH-class structural gaps** — the §8 profile registry has no owning spec, and
`evidence_id` is an undefined ID space — plus a family of system-wide
vocabulary drift that should be fixed with shared registries rather than
per-spec edits.

---

## Part 1 — Verification of first-review findings

Each headline claim was checked against the file text:

| Finding | Status | Note |
|---|---|---|
| H2: T12 formula ≠ LLD §12 | **Confirmed** | `tools/T12` §8 (line 119) has 13 terms vs the LLD's 8; renames confirmed (`detector_base`, `first_divergence_bonus`, `assignment_ambiguity_penalty`). |
| M1: T03 auto-link 0.75 | **Confirmed — worse than reported** | `minimum_auto_link_confidence = Decimal("0.75")` (T03 line 53), and the LLD §4.4 bands (≥0.90 auto / 0.70–0.89 warn / <0.70 candidate) **do not appear in T03 at all**. The tool spec has no band structure to contradict — it simply never adopted the contract. |
| H3/H4: T11 weighted `baseline_score` + "V2.1" gating | **Confirmed** | Weighted sum at T11 line 89; behavioral "V2.1" at lines 54, 172, 310. |
| H5: T20 selection via `-Y` only | **Confirmed** | T20 line 112: `-Y <compiled-safe-filter-and-selection>`; no `editcap` pre-slice anywhere in the spec. Full-capture re-dissection stands. |
| M2: T07 missing the 0.65 base | **Confirmed** | T07 §16 has 0.95/0.90/0.85/0.80; no 0.65, no missing-response entry. |

No first-review finding was refuted. `REVIEW_FINDINGS.md` remains valid as a
work backlog; this document supplements it.

---

## Part 2 — New findings: requirements traceability

### ☐ F1 (HIGH) — The §8 profile registry content has no owning spec

`requirement.md` §8.1–§8.10 — roughly a third of the requirements document —
defines ~30 detailed procedure flows: triggers, stage diagrams, conditional
rules, failure terminals (registration variants, auth/security, service
request/paging, PDU lifecycle incl. emergency, idle mobility, Xn/N2/inter-AMF
handover, inter-system mobility, roaming topologies, deregistration).

Nobody owns authoring this data:

- `T04` §6 defines only the `ProcedureProfile` *schema* and takes the
  "versioned procedure-profile registry" as an **input**.
- `T09` likewise *consumes* profiles and validates profile files.
- `LLD.md` §10.5–10.8 sketches registration/emergency/handover/roaming and the
  PDU-establishment stage list — but the service-request/paging stages (§8.3),
  authentication family (§8.2), deregistration (§8.9), idle mobility (§8.5),
  SSC/multi-access variants (§8.4), and inter-system mobility (§8.7) exist
  **nowhere** as implementable profile data.

An implementer cannot tell where the ~30 profiles' stage data gets written,
reviewed, tested, or versioned. **Fix:** add a spec (e.g. `T26_profile_registry`
or `harness/analysis/profiles/README`) that owns profile file format, authoring
rules, per-profile acceptance fixtures, and the §8→profile-file traceability
table.

### ☐ F2 (HIGH) — Roaming topology classification (AC17) has no producer

Everything *consumes* roaming topology — T04 records it "when known", T11
matches baselines on it, T13/T14 carry it as scenario context, and `LLD.md`
§10.8 defines `RoamingContext` — but **no tool spec derives it** from PLMN /
SUCI home network / NF-domain evidence. T03 (identity graph) never mentions
roaming. Fault-domain assignment (`UE/RAN/VISITED_CORE/HOME_CORE/INTER_PLMN/
UPF_PATH`) likewise appears in no tool contract. Acceptance criterion 17 is
currently unimplementable. **Fix:** assign topology classification to a tool
(T03 extension or a small dedicated classifier) with typed I/O.

### ☐ F3 (MED) — Retention lifecycle cleanup has no owner

`retention_days` exists in requirement §3.2 and `HarnessConfig`, and §4 imposes
a real safety constraint ("never selectively remove source evidence while
keeping a report that cites it") — but zero tool specs mention retention, run
deletion, or expiry. A behavior with a safety property has no component.
**Fix:** specify the lifecycle/cleanup component (likely `storage/run_store`),
including the all-or-nothing deletion rule.

### ☐ F4 (MED) — Alternative-profile reporting (§8.11) has no carrier

"When multiple profiles remain possible, the report must show alternatives"
(Xn vs incomplete-N2, periodic vs mobility, home-routed vs LBO). T04's
`ProcedureAttempt` carries a single `profile_id`; T17's report shows
alternatives only for *failure candidates*. The LLD's "profiles within 0.10
remain alternatives" and `REGISTRATION_UNKNOWN` candidate-variant rules have no
field in any tool I/O schema. **Fix:** add `alternative_profile_ids` (+ scores)
to `ProcedureAttempt` and a carrier in T17's report model.

### ☐ F5 (MED) — Non-3GPP access requirements nearly unowned

§8.1 requires distinguishing trusted/untrusted non-3GPP access and N3IWF/TNGF
context, and keeping coexisting 3GPP + non-3GPP registrations unmerged.
"N3IWF" and "TNGF" appear in **zero** tool specs and not in the LLD. The
unmerged-coexistence rule has no home — T03's merge rules never mention
access-type separation. **Fix:** add access-type separation rules to T03 and
N3IWF/TNGF anchors to the (to-be-created) profile registry.

### ☐ F6 (LOW) — Reverse traceability: unratified design inventions

Two mechanisms exist in tool specs with no requirement backing — fine as
elaboration, but they should be ratified upward since both have cost/security
implications:
- Authenticated pagination cursors (T10/T18/T19) — see F8.
- The multi-revision immutable-artifact regime (T02/T03/T04/T05/T11/T14…) and
  its storage growth — see F9.

Also LOW: §8.5 "reachability loss / MT delivery failure" classification appears
in no spec; the eight required observability stage timings (§11) are
assemblable but never enumerated as a checklist in one place.

**Well-covered:** AC1–12, 14–16, 18–27 all trace cleanly to owning specs
(multi-UE, tenth-attempt isolation, UE request fields, explicit/implicit
failure detection, emergency conditionals, handover/rollback, path-switch
correlation, inconclusive-on-invisible, evidence retrieval/context/re-decode,
token budget, masking, NRF/UDR isolation and gated inspection, deterministic
reports, capture metadata).

---

## Part 3 — New findings: cross-cutting drift

These are best fixed with **shared registries in LLD.md**, not 25 per-spec edits.

### ☐ F7 (HIGH) — `evidence_id` is an undefined ID space with a minting paradox

`evidence_id` is demonstrably distinct from `event_id` (T18 has separate
selector lists and resolution chains; T19 anchors and T10 timeline items carry
both). But the only defined minting point is **T15's** `EvidenceRecord` —
built at model-packet time — while tools that run *before* T15 already emit
`evidence_ids: list[UUID]` (LLD `FailureCandidate`, T08, T10, T11, T12, T14,
T22, T23). No spec says what those UUIDs resolve to, who builds T18's
"evidence index", or whether evidence_ids are deterministic. The LLD references
`EvidenceRecord` but never defines the class. T17's `ReportEvidenceRef.evidence_id`
implies reports cite evidence_ids even in provider-disabled runs where T15 may
never run. **Fix:** define the evidence ID space once in LLD §4 — who mints it
(suggest: detectors mint deterministic UUIDv5 evidence records at detection
time; T15 only *selects*), what it resolves to, and the T18 index that backs it.

### ☐ F8 (HIGH) — No error/warning-code registry; three conventions in use

Only three named codes exist suite-wide (`VALUE_PARSE_FAILED`,
`AMBIGUOUS_DEPENDENCY_PARTITION` in T02; `EVIDENCE_BUDGET_EXCEEDED` in T15),
yet ~10 specs require logging a `warning_code` field whose values are never
enumerated. Casing drifts (lowercase quasi-codes in T06 vs uppercase
elsewhere). Phantom types: `DecodeWarning`/`NormalizationWarning`/
`IdentityWarning`/`AttemptWarning`/`DetectorWarning` are referenced but
**defined nowhere**, while other specs use bare `list[str]`. Recurring
cross-tool conditions ("evidence-integrity warning", "access-boundary
warning") are named only in prose, differently each time. **Fix:** one
error/warning-code registry + one `Warning` model in LLD, referenced by all
specs.

### ☐ F9 (MED) — Masking has no single owner and contradictory rules

- T01 asserts "masking occurs only when model evidence is built" — contradicted
  by T10 (timeline masking), T25 (own `masking.py`, mandatory pre-provider
  masking), and T17 (report redaction).
- Two divergent transforms: T03's non-reversible aliases (`UE-1`) vs T05's
  partial reveal (`imsi-***1234`); T17 mixes both.
- Failure semantics disagree: T15 makes masking failure fatal for remote only;
  T25 fails the inspection unconditionally; T16 requires strict masking only
  for openrouter.

**Fix:** one masking spec (owner: `evidence/masking.py`) defining the
transform(s), salting/keying (ties to first review's M8), where masking applies
(analysis-alias vs model-boundary vs report), and failure semantics per
provider class.

### ☐ F10 (MED) — Revision/idempotency: shared spirit, no shared definition

Twelve specs repeat the "immutable revision = hash of inputs + config +
versions, manifest-last" pattern, but the LLD never defines *revision* — no
value format, no compatibility statement between e.g. T11's "attempt revision"
key, T15's "input revision hashes", and T21's `attempts_revision`. T01 has no
revision model at all; T02 puts revision-creation on "the caller" while T03/T04
mint their own. **Fix:** define the revision model once in LLD (format, who
mints, cross-tool reference rules).

### ☐ F11 (MED) — Three cursor designs; "authenticated" never specified

T10, T18, and T19 each define a different cursor payload; all three say cursors
are "authenticated" (T10: "with a local key") but no document defines the
scheme — algorithm, key derivation/storage/rotation, TTL. The LLD uses a fourth
term ("continuation token"). **Fix:** one cursor mechanism spec; ratify into
requirements (see F6).

### ☐ F12 (MED) — Run-status vocabulary: six enums for one concept

`success/partial/failed` (T01–T04, T17, LLD) vs `success/partial/unknown`
(T21) vs `success/empty/failed` (T20) vs `completed/empty/partial/failed`
(T24/T25) vs `parsed/partial/empty/failed` (T13) vs `success/failed/disabled`
(T16). "completed" vs "success" and the inconsistent presence of "empty" need
a mapping or unification. Related: `LLD.md` §15.1 refers to "the run manifest"
which is never specified, and T17 takes an `AnalysisState` defined nowhere.

### ☐ F13 (MED) — Tokenizer identity undefined, breaking determinism and the budget

The entire token-budget enforcement (T15/T16) rests on "provider/model
tokenizer when available; conservative fallback estimator otherwise" — the
fallback is undefined (no chars-per-token rule), no tokenizer is named, and
T15's deterministic packet ID includes budget *config* but not tokenizer
*identity*. Identical inputs can produce different trimming depending on
tokenizer availability, contradicting the rerun-determinism requirement (§11).
**Fix:** name the fallback estimator, include tokenizer identity in the packet
revision hash, and state that budget enforcement uses the estimator
deterministically (provider tokenizer only for reporting).

### ☐ F14 (LOW) — Timestamp representation: LLD `float` vs specs `Decimal`; epoch ambiguity

Tool specs uniformly use `Decimal` (good), but the LLD uses `float` for the
same quantities (temperature, timeouts, confidence, detector_score). LLD §4.2
says timestamp is "seconds from capture epoch" (relative) while T01 shows
absolute Unix-epoch strings — absolute vs capture-relative is unresolved.
Settle both in the LLD models.

**Consistent (no action):** dependency reason codes identical everywhere
(T24/T25 correctly partition the set — minor nit: T16 references an undefined
`DependencyReasonCode` type name); `schema_version: Literal["2.0"]` uniform
across all 56 occurrences; deterministic UUIDv5 derivation is a genuinely
shared idiom across T02/T03/T04/T07/T08/T09/T10.

---

## Combined priority view

If only five things get fixed before implementation starts, fix these:

1. **F1** — create the profile-registry spec; a third of requirement.md
   currently has no implementation home.
2. **F7** — define the `evidence_id` space and its minting; every tool's
   output references it.
3. **H2/H3 + M1** (first review, all verified) — reconcile the T12 formula,
   T11 baseline selection, and T03 thresholds with the LLD.
4. **F2** — give roaming topology classification a producer (AC17 is
   unimplementable without it).
5. **F8/F9/F10/F11/F12** as a single "shared registries" change in LLD.md:
   error/warning codes, masking ownership, revision model, cursor mechanism,
   status vocabulary. One document edit, 25 specs then reference it.

The first review's recommended "Contract Conformance appendix" in LLD.md is the
right vehicle for #3 and #5 together. F1 and F2 need new spec content, not
reconciliation.
