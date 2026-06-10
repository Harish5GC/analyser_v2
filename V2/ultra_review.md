# V2 Harness — Ultra Review (Round 3, Exhaustive)

**Method.** Third and deepest review pass. Every file in the repository —
`requirement.md`, `architecture.md`, `LLD.md`, and all 25 specs in `tools/` —
was read in full within a single review context, enabling cross-document
verification that per-group reviews cannot do. Every finding from rounds 1–2
(`REVIEW_FINDINGS.md`, `review_fable.md`) was re-checked against the actual
text; several were **refuted or downgraded** (Section 1 — read it first, it
changes the backlog). New findings are labeled U1–U13. Each finding ends with
a concrete **Action** naming the file, section, and the change to make.

A multi-agent verification workflow was attempted first but hit the session
token limit; the full direct read below supersedes it and provides stronger
verification (single context, no inter-agent blind spots).

---

## 1. Corrections to earlier findings — verified against full text

These matter: fixing "findings" that are not real defects wastes effort and
erodes trust in the backlog.

**C1 — R19 / round-1 L2 (T05→T18 NRF/UDR leak path) is REFUTED.**
T18 §11 explicitly enforces: *"Primary capability cannot resolve `nrf`/`udr`
partition event/record IDs even if supplied directly … This enforcement occurs
after each selector expansion."* T05 reads only attempt-assigned primary events
and would hold `primary_internal` capability, so the leak is structurally
impossible. **Residual action (LOW):** add one sentence to T05 §3 naming the
capability level (`primary_internal`) it uses for T18 lookups.

**C2 — M6 (T24/T25 missing dependency routing field) is PARTIALLY REFUTED.**
The model-facing request *does* carry the routing key: `tool:
Literal["inspect_nrf_flow", "inspect_udr_flow"]` exists in both `LLD.md` §17
and T16 §8. The executor routes on `tool` before constructing the internal
`InspectNRFFlowRequest`/`InspectUDRFlowRequest`, so the shared
`DEPENDENCY_TIMEOUT_SUSPECTED` reason code is unambiguous. The *real* residue
is the contract drift in U3 below (LLD §17 is stale, and T23 calls the same
concept `dependency_type`).

**C3 — M9 (T15 bodies-last trimming order) is effectively SATISFIED.**
T15 §11's "Never remove" list protects all mandatory evidence, and §20
specifies `EVIDENCE_BUDGET_EXCEEDED` failure rather than silent omission. The
contract's intent (mandatory evidence never sacrificed for verbosity) is met
by a stronger guarantee. **Residual (LOW):** reorder §11 steps so text/structure
shortening is explicitly the last step before failure, for clarity only.

**C4 — M8 (T25 masked-key salting unstated) is PARTIALLY MITIGATED.**
The keyed-hash mechanism *is* specified upstream: T02 §13 ("Sensitive values
use keyed local hashes"), T02 §18 ("run-local keyed hash"), T03 §7 ("Hash keys
come from run-local secret material and are not persisted with reports"), and
T03's config carries `sensitive_hash_key_id`. T25 simply never references it.
**Reduced action (LOW-MED):** T25 §19/§23 must state that
`masked_correlation_key`/aliases are produced by the run-local keyed hash from
T02/T03, making cross-capture linkage impossible without local key material.

**C5 — H6 (T15 token-budget precedence) is SOFTENED but stands.**
T15 §10 does hint precedence: *"Hard maximum default 12,000 for local models
**or lower provider context budget after reserving output/system tokens**"* —
i.e., an implied `min()`. What remains genuinely undefined: behavior when
`available_input < target_minimum` (small models), and which component supplies
`model_context_limit` to T15 (T16's `ProviderConfig` has `max_output_tokens`
but **no input-token field**; `HarnessConfig.max_model_input_tokens` exists but
no spec wires it to T15's request). See A8.

**C6 — M3 (T07/T08 missing capture inputs) REFINED.**
T07's request *does* carry `visibility: InterfaceVisibility`, and
`ProcedureAttempt.visibility` is available to both. What is actually missing:
(a) neither T07 nor T08 receives capture first/last frame/time, which T08 §8
needs for "capture end before timeout yields `request_only_capture_boundary`";
(b) neither receives the T21 phase reader, yet both must populate the required
`FailureCandidate.capture_phase` field. Action folded into A5.

---

## 2. Critical and High actions

### A1 — Create the procedure-profile registry spec (F1, confirmed by full read) — HIGH
**Defect.** `requirement.md` §8 (~30 detailed procedure flows; one third of the
requirements) has no owning implementation spec. T04 §6 defines only the
`ProcedureProfile` *schema* and takes a "versioned procedure-profile registry"
as an **input**; T09 consumes profiles; LLD §10.5–10.8 sketches a subset
(registration, emergency, handover, roaming, PDU establishment). The
authentication family (§8.2), service-request/paging stages (§8.3), SSC/
multi-access variants (§8.4), idle mobility (§8.5), inter-system mobility
(§8.7), and deregistration (§8.9) exist nowhere as implementable stage data.
**Action.** Write `tools/T26_profile_registry.md` (and add to `tools/README.md`)
that owns: (1) the on-disk profile file format (YAML/JSON realization of T04 §6
`ProcedureProfile` + T09 §5 `StageDefinition`), (2) the authoring/versioning/
review rules per requirement §8.12 (3GPP release + deployment-profile
dimensions — note T04's `ProcedureProfile` lacks the `release` field that
LLD §10 `ProcedureDefinition` has; reconcile), (3) a traceability table mapping
every §8.x flow to a profile file, (4) per-profile fixture requirements, and
(5) the registry-loading contract that resolves the `profile_registry_version`
string (this also resolves M4 for T04/T09).

### A2 — Define the `evidence_id` space and its minting (F7, confirmed) — HIGH
**Defect.** `evidence_id` is referenced by T06 §5, T08 §11, T10 §5, T11 §14,
T12 §8, T14 §7, T22 §8, T23 §9, T24 §8, T25 §8 and resolved by T18 §7
("Evidence ID → evidence index → source event/record refs") — but the only
defined minting point is T15 §8 `EvidenceRecord`, which is built at
model-packet time, *after* all those tools have run. No spec builds T18's
"evidence index". T17 §9 `ReportEvidenceRef.evidence_id` implies reports cite
evidence_ids even in `provider=none` runs where T15 may never execute.
**Action.** Add to `LLD.md` §4 a canonical definition: an `EvidenceRecord` is
minted **at detection/extraction time** by the tool that first cites evidence
(deterministic `UUIDv5(analysis_id + source_event_ids + record_type)`), stored
in `normalized/diagnostics/evidence_records.jsonl` with an
`indexes/evidence_index.jsonl` owned by the storage layer; T15 *selects and
re-serializes* existing records rather than minting; T18 §7 resolves through
the new index. Update T06–T14 to state they mint evidence records via the
shared helper, and T17 to state report refs resolve without T15.

### A3 — Reconcile the three core-algorithm divergences (H2, H3, M1, M2 — all re-verified verbatim) — HIGH
**Defects (all confirmed by direct quote):**
- T12 §8 formula (13 terms, lines 119–132) vs `LLD.md` §12 (8 terms), with
  three silent renames.
- T11 §7 weighted `baseline_score` (line 89) vs LLD §13's strict lexicographic
  order; similarity and temporal nearness are summed, so a nearer-but-less-
  similar baseline can win.
- T03 line 53 `minimum_auto_link_confidence = Decimal("0.75")`, while the LLD
  §4.4 bands (≥0.90 auto / 0.70–0.89 warn / <0.70 candidate) appear **nowhere
  in T03** — the tool spec never adopted the band structure at all.
- T07 §16 lacks the LLD §11.2 `0.65` missing-response base and adds an
  undocumented `0.80` term; T07 §1 vs §2 contradict on who owns "initiating
  message without outcome" (T07 or T9).
**Action.** Declare the tool specs (T11/T12) the source of truth — they are
richer and internally consistent — and update `LLD.md` §12/§13 to match,
explicitly mapping renamed terms (`detector_score→detector_base`,
`baseline_divergence_bonus→first_divergence_bonus`,
`ambiguous_correlation_penalty→assignment_ambiguity_penalty`). For T11, either
encode the lexicographic contract as tiered weight constraints (similarity
weight strictly dominates temporal weight) or have LLD bless the weighted
model; state the choice. For T03, add the three-band structure to §9 with
config fields `auto_link_threshold=0.90` / `warn_link_threshold=0.70`, and
remove or rename `minimum_auto_link_confidence`. For T07, add the 0.65
missing-response base or move that detection wholly to T09 and delete it from
T07 §1's scope list — one owner, stated in both specs.

### A4 — Complete the orchestration contract (U1, NEW) — HIGH
**Defect.** Neither architecture §3.2's 15-step list nor LLD §19's pseudocode
invokes T05 (`get_ue_request`) or T10 (`get_attempt_timeline`), although T15 §3
declares both as inputs. T09's hard sequencing dependency (it consumes
`explicit_candidates` from T06–T08) is not expressed. The dependency-expanded
T12 rerank (T12 §1/§13) and T14 dependency-expanded revision (T14 §15) never
appear in the flow — the pseudocode goes straight from `dependency_executor`
to the expanded packet, so the reranked deterministic result the final report
needs is never produced. The pseudocode also passes the *whole* `failures`
list to a per-attempt `ranker.rank(...)` (T12 expects per-attempt candidates),
calls `detector_registry.detect(attempt, events)` without the `context` arg
its own §11 protocol requires, and `selected_failed_attempts(...)` is
undefined — with no per-run cap on model calls when a capture contains many
failed attempts (each costs up to 2 passes + inspections).
**Action.** Rewrite LLD §19 to: insert T05 + T10 (+T21 ordering) explicitly;
run T06→T07→T08 then T09 with their candidates; after
`dependency_executor.execute`, call `ranker.rank(..., pass_stage=
"dependency_expanded")` and `scenario_validator` revision before building the
expanded packet; filter failures per attempt; add the `context` argument.
Define `selected_failed_attempts`: default = all failed/timed-out/aborted
attempts unless `--attempt`/`--ue` selectors narrow it, bounded by a new
`HarnessConfig.max_model_attempts_per_run` (suggest default 5, deterministic
report for the rest). Add a step-to-tool table (T01–T25 → orchestrator step,
inputs, outputs) as an LLD appendix.

### A5 — Assign ownership of `call_impact`, `relevance`, `severity`, `capture_phase` on candidates (R3 + C6 + new severity gap) — HIGH
**Defect.** `FailureCandidate` (LLD §4.6) requires `severity`, `capture_phase`,
`relevance`, `call_impact`. Verified by full read: T06 covers `relevance` and
phase (it receives `CapturePhaseReader`); T07/T08/T09 set none of the four
explicitly; no detector mentions `severity`; `call_impact` is conceptually a
T23 output that primary detectors cannot know.
**Action.** In LLD §4.6 add a "field ownership" note: detectors set
`severity` (rule-table-driven), `relevance` and `capture_phase` (defaults:
`attempt_related`, phase from T21 lookup), and `call_impact=inconclusive`;
T23 overwrites `call_impact` for inspected dependency candidates; T12 consumes
but never mutates. Add `capture: CaptureMetadata` and a `CapturePhaseReader`
(or precomputed phase labels) to the T07 §4 and T08 §4 request models —
T08 §8's "capture end before timeout" decision currently has no input to
decide from.

### A6 — Settle V2 / V2.1 / 2.0 naming, audit behavioral "V2.1" (H4, confirmed) — HIGH
**Defect.** T11 gates real behavior on "V2.1" (lines 54, 172, 310: no
future-success baseline, no population analysis). Whether these constraints
apply to "V2" is undecidable from the docs.
**Action.** Add a versioning note to `requirement.md` §1: product = V2,
current milestone = V2.1, schema = 2.0. Then replace behavioral "in V2.1"
phrases with explicit capability flags (e.g., T11 §5: "future-success baselines
are not eligible (deferred capability `population_baselines`)"), so behavior is
tied to named capabilities rather than version prose.

### A7 — Fix T20's unbounded dissection (H5, confirmed: line 112 uses `-Y` only) — HIGH
**Defect.** Frame/time selection is compiled into the `-Y` display filter;
tshark still dissects the entire capture, contradicting T20 §1/§19/§25
"narrowly bounded" claims and the performance acceptance criteria.
**Action.** In T20 §9, prepend an `editcap` pre-slice step for frame
(`editcap -r <pcap> <slice> <start>-<end>`) and time (`-A`/`-B`) selections,
recording the slice file checksum in the §14 provenance manifest (slice is
staging, not retained evidence); run tshark against the slice with the
remaining `-Y` predicates. Where editcap is unavailable, the spec must
explicitly restate the cost (full-capture dissection) and drop the bounded-
read performance claim. Add a §24 test: re-decode of a 10-frame window from a
1M-frame capture completes within a bound independent of total capture size.

### A8 — Formalize the token budget end-to-end (C5 + F13 + U13) — HIGH
**Defect.** Three loose ends: (1) T15 §10 lacks the `effective_budget =
min(available_input, hard_max)` rule and small-model (`available < target_min`)
behavior; (2) no tokenizer identity — "provider/model tokenizer when available;
conservative fallback estimator otherwise" makes trimming depend on tokenizer
availability, while T15 §18's deterministic packet ID excludes tokenizer
identity, breaking the requirement §11 rerun-determinism guarantee; (3) no
component is specified to supply `model_context_limit` to T15 —
`HarnessConfig.max_model_input_tokens` exists but T16 §6 `ProviderConfig` has
no input-token field.
**Action.** T15 §10: add the `min()` rule; when `effective_budget <
target_min`, build the mandatory-only packet and warn (`TOKEN_BUDGET_BELOW_
TARGET`) rather than failing. Specify the fallback estimator concretely
(e.g., `ceil(bytes/3.5)` — conservative for UTF-8 JSON) and state that
**budget enforcement always uses the deterministic estimator**; the provider
tokenizer is used for reporting only. Include estimator version in the §18
packet ID. LLD §3/§19: state the orchestrator maps `max_model_input_tokens` →
T15 `model_context_limit`, and add `max_input_tokens` to T16 §6 for pre-send
enforcement (T16 §21).

---

## 3. Medium actions

### A9 — Canonicalize the cross-pass dependency-request contract (U3, NEW; supersedes M6)
LLD §17's `DependencyEvidenceRequest` is stale: it lacks `initial_evidence_ids`
(which T24 §5 *requires* for rationale validation: "Every cited evidence ID
exists in initial packet… Rationale text alone is insufficient") and
`masked_correlation_key` (which T25 needs); T16 §8 references an undefined
`DependencyReasonCode` type; T23 §4 names the discriminator `dependency_type`
while LLD/T16 name it `tool`. **Action:** make T16 §8 the canonical model;
update LLD §17 to match; define `DependencyReasonCode` once; rename T23's field
to align (or document the mapping). Also define `DependencyInspectionResult`
— referenced by LLD §15, T10, T12, T14, T15, T17 — as the discriminated union
of T24 `NRFInspectionResult` | T25 `UDRInspectionResult`.

### A10 — Unify pass-stage vocabulary (U2, NEW)
Three enums name the same two-pass concept: T12 `primary|dependency_expanded`,
T15 `initial|dependency_expanded`, T16 `initial|final`. **Action:** one shared
enum (`initial|dependency_expanded`) in LLD; T16's "final" prompt naming can
stay in prose but the typed field should use the shared values.

### A11 — Shared-type registry (U4, NEW; generalizes round-1 R25 and F8's phantom types)
Types referenced across specs but defined nowhere: `ArtifactDescriptor` (used
by every tool), `EventMatcher`, `StateTransition`, `RetryRecord`, `RetryRule`,
`TimeoutRule`, `NestingRule`, `CorrelationKeyRule`, `ConditionExpression`,
`InterfaceVisibility`, `CaptureMetadata`, `PhaseRoll`, `NFEntityReadiness`,
`FrameWindow`, `EvidenceCapability` (prose-only in T18 §3), `MaskedUEIdentity`,
`ProblemDetailsSummary`, `MissingField`, `FieldDifference`, `StageAlignment`,
`DependencyEventSummary`, `DependencyBaselineComparison` (T23) vs
`UDRBaselineComparison` (T25) — likely the same thing under two names —
`AnalysisState`, `ReportPolicy`, `DependencyInspectionReport`, plus the five
warning types (`DecodeWarning`, `NormalizationWarning`, `IdentityWarning`,
`AttemptWarning`, `DetectorWarning`). **Action:** add an LLD "shared models"
appendix defining each exactly once with owning module; tool specs reference
instead of re-declaring. Merge the two baseline-comparison names.

### A12 — Error/warning-code registry (F8, confirmed)
Only three named codes exist suite-wide; ~10 specs log a `warning_code` with no
enumerated vocabulary; casing drifts (T06 lowercase `request_only` vs T02/T15
uppercase). **Action:** one registry file (`harness/errors.py` + LLD appendix)
defining code namespace (`<TOOL>_<CONDITION>` uppercase), the shared `Warning`
model (code, severity, stage, message, evidence refs), and the recurring
cross-tool conditions ("evidence-integrity", "access-boundary") as single
codes.

### A13 — Masking specification with one owner (F9, downgraded but real)
The transforms are more consistent than round 2 claimed (T05 §15 already
scopes `imsi-***1234` to local report policy; aliases are default for model
evidence). What remains: T01 §9.1's "masking occurs only when model evidence is
built" contradicts report-time redaction (T17 §14) and T25's inspection-time
masking; failure semantics differ deliberately (T15: fatal for remote; T25:
fatal always) but no doc says this is intentional. **Action:** a short
"masking policy" section in LLD (owner: `evidence/masking.py`) defining: the
three masking surfaces (analysis aliases at T03; model boundary at T15/T24/T25;
report redaction at T17), the keyed-hash mechanism reference, and a table of
failure semantics per surface with rationale. Fix T01 §9.1's sentence to "full
output is never masked; masking applies at downstream boundaries."

### A14 — Revision model definition (F10, confirmed)
Twelve specs use "revision" (opaque `str`); T21 consumes `attempts_revision`
but T04's result exposes no revision field; T02 says the *caller* creates a new
revision while T03/T04 self-mint. **Action:** define in LLD: revision =
`sha256(input artifact checksums + config hash + tool version)`, computed and
exposed by every tool's result/manifest (add the field to T04 §4 result), with
cross-tool reference rules. Add the missing T01 rerun/idempotency paragraph
(re-decode into an existing run dir: reject; T01 §7 only covers staging
cleanup).

### A15 — Cursor mechanism (F11, confirmed)
T10 §11, T18 §12, T19 §15 define three cursor payloads, all "authenticated"
with no scheme. **Action:** one cursor spec in LLD (suggest HMAC-SHA256 over
the payload with a per-run key stored in the run directory with 0600
permissions; TTL; bound to analysis_id + capability + query hash). The three
specs then reference it, keeping their payload field lists.

### A16 — Status-enum mapping (F12, confirmed; low urgency)
Six result-status vocabularies exist (`success/partial/failed`,
`success/partial/unknown` (T21), `success/empty/failed` (T20),
`completed/empty/partial/failed` (T24/T25), `parsed/partial/empty/failed`
(T13), `success/failed/disabled` (T16)). Each is locally sensible; the gap is
aggregation. **Action:** add a mapping table to T17 §10 stating how each
tool-status maps into run-status (`empty`→success, `unknown`→partial, etc.),
and define the "run manifest" + `AnalysisState` that T17 §4 consumes (currently
undefined anywhere — LLD §15.1 references "the run manifest" too).

### A17 — Canonical artifact/index layout (U7, NEW; consolidates R17/M12)
Three-way drift verified: requirement §4 layout vs architecture §3.5
(`identifier_index.json`, `ue_index.json`, `session_index.json`,
`attempts.json`, `failures.json` — none exist downstream under those
names/extensions) vs LLD §7.1 vs actual tool outputs (T02 §14 `.jsonl` indexes
+ `time_index`; T03 §15 `normalized/identity/`; T04 §18 `normalized/attempts/`;
T06–T09/T12 `normalized/diagnostics/`; T21 `normalized/phases/`; T11
`normalized/comparisons/`; T05 `normalized/requests/`; T13/T14
`normalized/scenario/`; T15 `evidence/packets/`; T16 `evidence/model/`;
T24/T25 `evidence/dependency/`; T18 `evidence/lookup/`). **Action:** rewrite
LLD §7.1 as the single canonical tree (union of the tool specs, which are the
most concrete); replace architecture §3.5's file list with a pointer; mark
requirement §4's tree as the minimum contract ("non-exhaustive; canonical
layout in LLD §7.1").

### A18 — Fix the visibility-interface enum (U5, NEW — technical 3GPP gap)
LLD §10.3 `VisibilityRequirement.interface` allows N1, N2, N4, N8, N10, N11,
N12, N15, N16, N22, N27, N40, Nnrf, N9, Xn. Missing: **N7 (SMF–PCF)** — SM
policy is explicitly in scope (§8.10 "PCF AM/SM policy association"), and N15
(AM policy) is present while N7 is not; **N35/N36/N37 (UDM–UDR / PCF–UDR /
NEF–UDR)** — the entire UDR inspection subsystem has no visibility reference
point; **N13 (UDM–AUSF)** for the authentication family. Also "Nnrf" mixes a
service-based name into a reference-point enum. **Action:** add N7, N13, N35,
N36, N37; either rename Nnrf to N27-style reference points or add a parallel
service-based axis — pick one convention and state it.

### A19 — PFCP node-level procedures in T08 (U6, NEW — technical gap)
T08 covers session-level Establishment/Modification/Deletion and heartbeats,
but has no detection rules for **PFCP Association Setup/Update/Release**
failures (an association failure explains *every* session failure on that
node-pair and should rank above per-session candidates) or **Session Report
Request/Response** (UPF-initiated Error Indication Report / user-plane path
failure reports are direct evidence of data-path failure post-establishment).
**Action:** add §7-bis rules: association-level failures emit candidates with
`relevance=unresolved_infrastructure` (node-scoped, eligible for multiple
attempts via cross-protocol link), and Session Report carrying Error Indication
/ user plane path failure emits an attempt-scoped candidate when the reported
F-TEID/SEID maps to the attempt's session. Extend §11 consistency checks
accordingly.

### A20 — Remaining confirmed medium items (carried forward, re-verified)
- **F2 roaming-topology producer:** no tool computes `RoamingContext`
  (LLD §10.8) although T04/T11/T13/T14 consume it; AC17 unimplementable.
  *Action:* assign to T03 (new §: topology classification from serving/home
  PLMN, SUCI home network ID, GUAMI/TAI, NF FQDN domains) with typed output and
  fault-domain assignment rules feeding T12.
- **F3 retention owner:** `retention_days` + §4's all-or-nothing deletion rule
  have no owning component. *Action:* add a `run_store` lifecycle section to
  LLD §7 (cleanup deletes the whole run dir or nothing; verifies no newer
  artifact cites it; never selective).
- **F4 alternative-profile carrier:** add `alternative_profile_ids:
  list[tuple[str, Decimal]]` to T04 §5 and an `alternative_profiles` block to
  T17 §6, realizing LLD §10.4's 0.10-window rule and §8.11's reporting demand.
- **F5 non-3GPP:** N3IWF/TNGF appear in zero specs. *Action:* add access-type
  separation rules to T03 §8 (3GPP and non-3GPP registrations of one UE are
  distinct access-context nodes, never merged into one attempt), and non-3GPP
  anchors to the T26 registry (A1).
- **M5 T16 retry ceiling:** structured-fallback + repair + transport retries
  can compound to ~4 calls/pass. *Action:* T16 §21: `max_total_calls_per_pass
  = 3` (initial + at most one fallback-or-repair + at most one transport
  retry), with precedence order stated.
- **M7 T22 snapshot:** `required_service: str | None` is singular. *Action:*
  `required_services: list[ServiceRequirement]` with per-(instance, service)
  readiness, matching T22 §14's own service-level model.
- **M10 T23 causal-vs-contributing boundary:** state that §6 strong conditions
  gate *eligibility* and §8 + §10 ordering + §13 no-hard-contradiction jointly
  pick `causal` vs `contributing`.
- **M11 expansion budgets:** T22 §16's earlier extension and T24 §15's
  expansion must be declared one shared per-request budget enforced by the T24
  validator (likely the intent — both route through it — but unstated).
- **M4 policy-version resolution:** for each `*_policy_version` /
  `*_dictionary_version` string (T06–T09, T11, T12, T21), state the loader
  (versioned files under `harness/config/`, resolved at startup, fatal on
  missing version). A1's registry-loading contract is the template.
- **F14 numeric/time types:** change LLD §3/§4 `float` fields to `Decimal`
  (tool specs already use Decimal); resolve the epoch question: T01 §9 stores
  absolute Unix epoch strings — fix LLD §4.2's "seconds from capture epoch" to
  "absolute Unix epoch, Decimal, source precision".

---

## 4. Low actions (one line each)

1. **U8 (3GPP):** requirement §8.1 initial-registration flow marks
   `REGISTRATION_COMPLETE` unconditional; per TS 24.501 §5.5.1.2.4 it is sent
   only when the Registration Accept requires acknowledgement (new 5G-GUTI /
   SOR / NSSAI ack) — mark it `conditional` (condition: accept-requires-ack)
   to avoid rare false missing-stage findings. (NAS codepoints in LLD §6.2
   were verified correct: 0x41/0x42/0x44/0x4c/0x4d/0xc1/0xc2/0xc3.)
2. **U9:** requirement §3.2 lists input `api_key` then mandates env/secret-
   manager sourcing — rename the input to `api_key_env` (matching LLD/T16).
3. **U10:** requirement §6's canonical envelope (`{schema_version, analysis_id,
   events[]}`) is never realized — storage is JSONL with per-event metadata;
   update §6 to describe the logical schema, not a physical envelope document.
4. **U11:** LLD §21.3 golden reports — specify normalization of
   nondeterministic fields (`analysis_id`, `generated_at`, `timings`,
   `elapsed_ms`, absolute dates) before comparison.
5. **U12:** requirement §6 `raw_ref` (singular) vs LLD §4.2/T02 `raw_refs`
   list — align requirement wording.
6. **R18:** T02 — add the actual NAS message-type codepoint table (it names the
   map "table-driven" but never includes it) and one sentence: non-HTTP2
   protocols always route to `primary`.
7. **R20:** add `score_terms: list[ScoreTerm]` to `FailureCandidate` or state
   the terms live in detector result artifacts only (T12 §8 already defines
   `ScoreTerm` — reuse it).
8. **R21:** T08 §5 outcome enum — add `inconclusive` for partial N4 visibility,
   aligning with the harness-wide rule.
9. **R22:** `AnalysisReport.decoder` (requirement/LLD) vs T17 `pipeline` —
   adopt `pipeline` in LLD §18 (T17 is richer) and note the rename.
10. **R23:** requirement §4 `evidence/context/<query-id>.jsonl` vs T19 §13
    directory layout — update the requirement to the directory form.
11. **R24:** T10 — hard-clamp `limit` at 20 in `mode="model"`; declare the
    8-label set as the canonical extension of the requirement's 5; reword §15
    "major conclusion".
12. **R26:** T01 — pin `--output-dir` semantics (it receives `<run-dir>/decoded`
    per §5; §6's tree shows it *containing* `decoded/` — make §6 root at the
    arg value) and add a `CollectionDescriptor` model for the HTTP stream
    document set (§13 prose, §4 has no type for it).
13. **R27:** T08 §11 — specify F-TEID direction (gNB DL F-TEID from NGAP → FAR
    Outer Header Creation; UPF UL F-TEID from PFCP response PDR → NGAP setup).
14. **R28 residue:** CLI flags `--include-nrf-success`/`--include-udr-success`/
    `--unmasked-local-evidence` (LLD §2) are absent from requirement §3.2 and
    undefined in any tool spec — define semantics or remove; fix the
    architecture §1 ASCII alignment.
15. **C1 residue:** T05 §3 — name the `primary_internal` T18 capability.
16. **C3 residue:** T15 §11 — reorder so body-shortening is explicitly last
    before `EVIDENCE_BUDGET_EXCEEDED`.
17. **C4 residue:** T25 §19 — reference the T02/T03 run-local keyed hash for
    masked correlation keys.
18. **F6:** ratify into requirement §11: authenticated cursors (A15) and the
    revision/immutability regime (A14) — both currently spec-level inventions
    with cost/security implications.
19. **T13 §3 nit:** "T16-compatible provider interface" — name the `providers/`
    package instead of overloading "T16" (also T14 §15).
20. **T16 §21 nit:** drop "RTX 5090" from normative text; say "single local
    GPU" in a deployment note.

---

## 5. What was checked and found sound (so it is not re-litigated)

- NAS 5GMM/5GSM codepoints in LLD §6.2 (verified against TS 24.501).
- NRF/UDR reader isolation: enforced consistently at constructor level
  (LLD §1.1/§3.16), reader capability level (T18 §11, T24 §6, T25 §6), and
  test level (negative tests in T02–T14, T21).
- The lazy two-pass gate: T16 §9/§10, T24 §2/§5, T25 §2/§5 — coherent,
  including final-pass request stripping and no-third-pass.
- Prompt-injection defenses exist at all three surfaces: scenario (T13 §11),
  evidence packet (T15 §16), report rendering (T17 §21 markdown/HTML escaping).
- Shell-injection safety in T20 (AST filters, arg-array, allowlists) — strong.
- `schema_version: "2.0"` uniform; dependency reason-code values identical
  across T06/T16/T24/T25/LLD; deterministic UUIDv5 idiom shared by
  T02/T03/T04/T07/T08/T09/T10/T15.
- T01 full-fidelity retention (duplicate headers, body segments, incomplete
  streams, heartbeats) matches requirement §5 exactly.
- Benign-startup-cleanup vs unresolved-failure logic (T22 §10–§12, T23 §6–§8)
  implements requirement §8.10/§7-T22 correctly.

---

## 6. Recommended execution order

| Order | Actions | Why first |
|---|---|---|
| 1 | A3 (algorithms), A5 (field ownership), A9/A10 (cross-pass contracts) | Direct contradictions; implementers diverge immediately without them |
| 2 | A2 (evidence_id), A4 (orchestration), A11 (shared types) | Everything downstream cites these; cheap now, expensive after code exists |
| 3 | A1 (profile registry), F2 producer (A20) | Largest unowned scope; gates fixtures and AC13–18 |
| 4 | A7, A8, A19 (technical: tshark, tokens, PFCP) | Real runtime behavior, isolated edits |
| 5 | A12–A17 registries/layout + A6 naming audit | One-time LLD appendix work, 25 specs then reference it |
| 6 | Section 4 lows | Mechanical, batch in one editing pass |

Net assessment after three rounds: the architecture and its protective
boundaries are sound and verified consistent; the defects are concentrated in
**contract drift between document tiers** (the LLD lags the tool specs almost
everywhere they disagree) and **unowned scope** (profiles, evidence IDs,
roaming topology, retention). Declaring the tool specs normative where they
conflict with the LLD — and back-porting the LLD to match — resolves the
majority of HIGH/MED items in a single coordinated edit.
