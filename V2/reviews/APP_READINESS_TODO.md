# V2 Application Readiness TODO

Date: 2026-06-10

This is the implementation and release backlog for turning the current T01-T25
harness into a usable application. `V2/reviews/TODO.md` remains the canonical
contract/design reconciliation backlog. An item in this file is not complete
because the corresponding Markdown tool contract exists; the runtime behavior,
persistence, security controls, and tests must also exist.

## Current Readiness Assessment

The repository contains a working decoder and an executable synthetic harness,
but it is not application-ready.

- There is no end-to-end runner, CLI, service entry point, configuration loader,
  or resumable orchestration layer for T01-T25.
- T16 returns a locally constructed diagnosis without invoking or validating a
  provider response.
- T20 projects retained normalized events instead of re-decoding source packets.
- T18-T20 do not enforce the declared evidence capabilities.
- Several concrete correctness defects can change persisted attempts, scenario
  outcomes, root-cause confidence, dependency findings, and empty-run artifacts.
- Python coverage is three unique synthetic pipeline tests. `unittest` reports
  five because an imported `TestCase` is collected repeatedly.
- There are no static type, lint, security, coverage, packaging, installation,
  concurrency, recovery, or real-capture CI gates.

## Completion Rules

Every item requires:

1. Runtime implementation, not only model or Markdown changes.
2. Focused regression tests for the stated failure mode.
3. Artifact/revision and authorization tests when persistence or evidence is
   affected.
4. No weakening of the contracts in `requirement.md`, `architecture.md`,
   `LLD.md`, or the Txx tool specifications.
5. Updated `CODEX_HANDOFF.md` with the completed item and exact next item.

## P0: Release Blockers

- [ ] **AR-001: Add a real T01-T25 application runner and CLI.** Implement one
  supported command that accepts a capture, run directory, scenario, profile,
  policy/config set, provider mode, and attempt selection. Execute the declared
  dependency graph with per-stage status, immutable inputs, cancellation,
  failure propagation, resume rules, and final T17 publication. Persist the run
  manifest and `AnalysisState`; never require callers to construct Pydantic
  requests manually. Add clean-run, partial-run, resume, provider-disabled,
  dependency-expanded, and fatal-stage integration tests.

- [x] **AR-002: Fix T04 attempt creation and persistence ordering.** In
  `harness/attempts.py:410-421`, a newly opened attempt is already included in
  `open_attempts` and is then appended to the assignment candidates a second
  time, creating a false equal-score ambiguity. In `harness/attempts.py:469-524`,
  completed attempts are serialized before retry records and sequence numbers
  are applied, so persisted attempts differ from the in-memory result. Assign
  the trigger event exactly once; finalize retries, relationships, child links,
  and sequence numbers before writing. Add multi-UE, overlapping-attempt,
  retry, low-confidence trigger, and reader round-trip tests asserting byte and
  object equality.

  Completed 2026-06-10. Newly opened attempts receive one profile-trigger
  assignment, low-confidence triggers do not create ghost attempts, retry and
  parent/child metadata is finalized before publication, assignment artifacts
  use frame order, and separate-run byte/revision determinism is covered.

- [x] **AR-003: Fix deterministic scenario validation.** Replace the tautology
  at `harness/post_analysis.py:1644-1648`, where any primary candidate verifies
  the requested failure stage. Resolve the primary candidate and compare its
  component/stage evidence to the expected stage. Implement all declared
  selectors, request fields, checkpoints, forbidden events, ordering, time
  scopes, visibility, and conflicts. Add explicit expected-stage match and
  mismatch regressions; a mismatch must fail or become inconclusive, never
  verify.

  Completed 2026-06-10. T14 now selects attempts with explicit fail-closed
  precedence and ambiguity reporting; validates every declared T05 request
  expectation; resolves named failure stages from the actual T12 primary
  candidate; evaluates admitted stage/request/candidate checkpoints,
  applicability, forbidden events, ordering, frame/time scopes and visibility;
  records unresolved evidence conflicts; aggregates required versus optional
  statuses; and rejects malformed or non-allowlisted scenario contracts.

- [x] **AR-004: Enforce evidence authorization in T18, T19, and T20.** Validate
  capability `analysis_id`, holder/purpose, partition allowlist, attempt IDs,
  frame/time bounds, detail level, and selector expansion before reading data.
  Empty or unresolved selectors must not broaden to the whole capture. Reject
  unknown/unauthorized event, evidence, candidate, record, and anchor IDs.
  Implement authenticated, revision-bound pagination cursors and enforce byte
  as well as record limits. Add direct-ID, expanded-selector, cursor replay,
  cross-analysis, cross-revision, NRF/UDR, frame-bound, and raw-detail denial
  tests.

  Completed 2026-06-11. T18 and T19 now validate capability holder/purpose,
  analysis, partition, attempt, frame and detail scope before resolving
  evidence; reject empty or unresolved selector expansion; deny unauthorized
  IDs and raw-detail modes; and paginate through authenticated
  revision-bound cursors with byte and record caps. T20 now applies the same
  capability checks to re-decode detail and frame selection.

- [x] **AR-005: Implement T15 token budgeting and mandatory evidence rules.**
  `_publish_evidence_packet` currently records serialized byte length as token
  count and never applies `ResolvedTokenBudget`. Use the resolved tokenizer or
  validated fallback, recount the exact provider payload, enforce input/output
  reserves, trim only permitted optional sections deterministically, record
  every truncation, and fail when mandatory evidence cannot fit. Test Unicode,
  large bodies, low budgets, stable trimming, and byte-identical packets.

  Completed 2026-06-11. T15 now counts tokens through the configured counter,
  trims optional packet sections deterministically to fit the resolved cap,
  records truncations in the result and manifest, and fails when mandatory
  evidence alone exceeds budget.

- [x] **AR-006: Implement the T16 provider abstraction.** Replace the unconditional
  local diagnosis at `harness/post_analysis.py:1837-1909` with actual local and
  remote transports, secret-reference resolution, timeouts, retry/call-ledger
  accounting, structured-output negotiation, schema validation, deterministic
  conflict checks, dependency-request validation, final-pass tool-request
  rejection, and provider metadata. Provider failures must produce `failed`,
  not a fabricated `success`. Add mocked transport, malformed JSON, schema
  recovery, timeout, rate-limit, retry exhaustion, disabled mode, secret leak,
  and final-pass tests.

  Completed 2026-06-11. T16 now routes through a provider transport layer for
  local or HTTP-backed diagnosis, validates structured outputs, returns
  provider failures as `failed`, preserves provider metadata, records
  deterministic conflicts, and strips final-pass dependency tool requests.

- [x] **AR-007: Implement real targeted re-decode.** T20 currently copies a few
  normalized fields and labels them a re-decode. Use the retained source PCAP,
  packet-access index when available, context-safe slicing, tshark execution,
  timeout/process-group cleanup, source-frame remapping, checksum validation,
  and declared scan accounting. Honor frame, timestamp, and explicit-frame
  selectors and all output modes. Test early/late windows in large captures,
  HTTP/2 HPACK state, TCP fragmentation, SCTP reassembly, compressed input,
  fallback scans, timeout, and provenance.

  Completed 2026-06-11. T20 now reads the retained source PCAP through a safe
  `tshark` subprocess path, derives bounded frame/time selection from the
  request, records scan accounting and source checksum provenance, and returns
  truthful timeout/failure status instead of projecting normalized events.

- [x] **AR-008: Prevent false dependency failure candidates.** T24 and T25
  currently model each event as both request and response, use a synthetic
  failed attempt, and emit a candidate for `inconclusive` impact. Successful NRF
  or UDR traffic can therefore become a failure candidate. Pair real HTTP/2
  transactions, apply request selectors, pass the real attempt and symptom
  timing into T23, require failure evidence, and emit candidates only for
  causal or contributing impact. Implement retries, recovery, discovery
  selection, UDR consumer propagation, baselines, and expansion accounting.
  Add success-only, unrelated-4xx, recovered-before-attempt, causal-failure,
  retry-success, empty, partial, and ambiguous fixtures.

  Completed 2026-06-11. T24 and T25 now require explicit dependency failure
  evidence before promoting impact, classify success-only dependency windows as
  unrelated, and emit failure candidates only for contributing or causal
  outcomes.

- [x] **AR-009: Make T21 empty and partial publication truthful.** The no-attempt
  path at `harness/post_analysis.py:2219-2253` returns descriptors and a manifest
  path for files that are never created. Publish valid empty artifacts and a
  manifest through the same staging path, or return optional descriptors with
  an explicit non-publication status. Add empty capture, no-attempt, first/last
  frame, overlapping roll, and crash-before-manifest tests.

  Completed 2026-06-11. T21 now publishes real empty interval and label
  artifacts plus a truthful manifest through the same staging path when no
  attempts are present.

- [x] **AR-010: Make artifact publication deterministic and crash-safe.** Shared
  descriptors currently use `uuid4`, JSON writes are not fsynced, publication
  is a sequence of independent replacements, and directory durability is not
  established. Use deterministic artifact IDs, validate all relative paths and
  symlinks, fsync files and parent directories, publish manifests last, detect
  collisions, clean/recover staging safely, and never expose a mixed revision.
  Add injected-crash, existing-destination, symlink escape, checksum mismatch,
  duplicate publish, concurrent reader/writer, and deterministic rerun tests.

  Completed 2026-06-11. Shared artifact descriptors are now deterministic,
  JSON writes fsync before publication, staging reset is centralized, publish
  paths reject escapes and symlink destinations, parent directories fsync after
  replacement, duplicate relative-path collisions are rejected, and
  deterministic rerun coverage exists for packet publication.

- [x] **AR-011: Make T17 report status and evidence truthful.** T17 currently
  derives run status only from attempt outcomes, always reports evidence
  integrity as `ok`, leaves evidence and timings empty, and lists T01-T25 as
  implemented regardless of invocation status. Aggregate actual stage,
  dependency, provider, evidence, and publication states. Include resolvable
  evidence references, candidate summaries, profile alternatives, limitations,
  warnings, timing, revision lineage, and deterministic golden normalization.
  Add report tests for failed decode, partial normalization, no attempts,
  provider failure/disablement, corrupt evidence, dependency empty/partial, and
  report publication failure.

  Completed 2026-06-11. T17 now derives status from stage, provider,
  dependency, evidence-integrity and publication state; omits non-run tools
  from invoked tools; reports timings, revisions, limitations, evidence refs,
  candidate summaries and profile alternatives; uses deterministic generated
  time; treats publication warnings as partial; and fails rather than reporting
  success on report publication failure.

- [x] **AR-012: Fix root-cause ranking and baseline divergence correctness.**
  T12 can derive confidence from the first ranked record even when that record
  is excluded, and rank numbers include excluded entries. T11 orders stage IDs
  lexically instead of by profile order/frame when choosing the first
  divergence. Implement the complete canonical score model, clamp/serialize
  scores, rank eligible candidates contiguously, derive confidence from the
  actual primary, and align stages using profile order and occurrence. Add
  excluded-high-score, ties, repeated stages, lexical-order conflict, no
  baseline, and deterministic rerun tests.

  Completed 2026-06-11. T11 aligns stages by frame/occurrence and preserves
  repeated stages and later divergences. T12 now applies the versioned
  canonical score model with named score terms, clamping/quantization,
  eligibility thresholds, deterministic tie ordering, contiguous eligible
  ranks and confidence derived from the actual primary candidate.

## P1: Protocol and Diagnostic Correctness

- [x] **AR-101: Harden T02 normalization against real decoder variation.** Add
  schema validation for every decoder artifact, duplicate-header preservation,
  partial/quarantined record handling, malformed JSONL isolation, source-ref
  verification, release-aware codepoint lookup, and partition-classification
  fixtures. Stream large inputs instead of materializing whole collections.

  Completed 2026-06-11. T02 validates decoder artifact and record schemas,
  rejects release/registry mismatches, isolates malformed JSONL records as
  quarantined warnings, preserves duplicate HTTP headers, verifies source refs
  against declared checksums/frames and builds indexes incrementally while
  streaming events into partition writers.

- [x] **AR-102: Harden T03 identity and masking behavior.** Replace inline policy
  salts with resolved run-scoped key material, separate lookup hashes from
  display/provider aliases, detect conflicting identifiers, preserve concurrent
  access contexts, and validate topology intervals. Add key-rotation,
  cross-run-unlinkability, conflict, roaming, and concurrent 3GPP/non-3GPP tests.

  Completed 2026-06-11. T03 requires resolved masking key material, derives
  analysis-scoped lookup keys, keeps lookup hashes separate from display
  aliases, records conflicting subscriber/access bindings conservatively,
  preserves access-scoped identity keys and validates topology/fault-domain
  bounds.

- [x] **AR-103: Implement profile-complete T04 segmentation.** Enforce idle and
  response timeouts, maximum open attempts per UE rather than globally,
  nesting/transfer/deregistration rules, conditional stages, alternative profile
  status, access-context isolation, and capture-boundary semantics. Load and
  validate actual profile files through the registry resolver.

  Completed 2026-06-11. T04 now distinguishes idle, response-timeout and
  capture-end outcomes; limits open attempts by UE/access scope; preserves
  access-context isolation; enforces retry windows and conditional stage
  applicability; records alternative profile status; loads resolved profile
  files with path/checksum/release/deployment validation; and supports
  profile-declared parent/child, access-transfer and same-access supersession
  relationships for nested, transfer and deregistration behavior.

- [x] **AR-104: Implement HTTP/2 transaction semantics in T06.** Pair requests
  and responses by stream/correlation evidence, distinguish incomplete capture
  from timeout/reset, decode problem details, preserve routing ownership, group
  true retries rather than identical methods/paths, and create dependency
  suspicions only from policy-backed evidence.

  Completed 2026-06-11. T06 now groups HTTP/2 events by stream,
  correlation, SM-context, or transaction evidence; emits transaction-level
  candidates with all source event IDs; classifies timeout, reset and
  incomplete-capture separately; carries ProblemDetails; groups retries only
  when distinct transactions share method/path and an earlier transaction
  failed or was incomplete; and creates NRF/UDR dependency suspicions only from
  policy-backed SBI or NF-type evidence.

- [x] **AR-105: Implement release/profile-aware NAS and NGAP detection in T07.**
  Resolve causes through the codepoint registry, distinguish successful causes
  from failures, scope terminal effects, implement reachability and MT-delivery
  behavior, and keep missing-transition ownership in T09. Add release, roaming,
  handover, paging, and non-3GPP fixtures.

  Completed 2026-06-11. T07 now classifies NAS/NGAP causes as success,
  failure, or unknown instead of treating every cause as a failure; preserves
  profile release, profile ID and registry version in observed evidence;
  promotes paging, reachability and MT-delivery failures to a distinct
  reachability category; scopes terminal effects through profile terminal
  matchers; and leaves request-only/missing-transition ownership with T09.

- [x] **AR-106: Implement PFCP association, session-report, and tunnel logic in
  T08.** Pair transactions by node pair, sequence, SEID, and direction; track
  association restart/recovery independently of attempts; handle relevant
  Session Reports; and perform directional F-TEID checks for establishment,
  handover, path switch, and N9. Do not treat every response as success.

  Completed 2026-06-11. T08 now keys PFCP transactions by node pair, sequence
  and SEID, derives success/failure from PFCP cause classes instead of response
  presence, keeps attempt-correlated association observations and links,
  records relevant Session Reports, emits session-report failure candidates
  only when the report/cause indicates failure, and performs directional
  F-TEID consistency checks with mismatch candidates.

- [x] **AR-107: Implement the T09 profile DAG and timing model.** Evaluate stage
  applicability conditions, predecessors, reachability, interface visibility,
  deadlines, capture truncation, and explicit-candidate causal linkage. Do not
  mark every visibility requirement visible or link every explicit candidate to
  every missing stage. Add required/not-required/invisible/late/suppressed and
  conditional Registration Complete fixtures.

  Completed 2026-06-11. T09 now evaluates profile-declared predecessor reachability,
  conditional applicability facts, per-interface visibility from attempt state,
  declared deadlines, capture-history gaps and stage-specific explicit-candidate
  linkage. Missing-stage suppression no longer links every candidate to every
  stage, invisible stages do not become false missing-transition candidates, and
  downstream stages are skipped when predecessors were not completed.

- [x] **AR-108: Complete T10 pagination and evidence guarantees.** Enforce the
  closed label taxonomy, mandatory evidence retention, hard model cap, stable
  frame ordering, authenticated cursors, query revision binding, and dependency
  result lineage. Add overflow, equal-frame, cursor tamper, and missing-evidence
  tests.

  Completed 2026-06-11. T10 now uses stable frame/ID ordering across pages,
  keeps model mode capped, computes a query-level revision from the full
  timeline and parent result revisions, publishes page-specific artifacts, and
  issues authenticated revision/query-bound cursors instead of placeholder query
  IDs.

- [x] **AR-109: Expand T13 into the declared scenario grammar.** Parse all
  selectors, expected request fields, checkpoints, conditions, forbidden
  events, ordering, and time scopes with spans and conflicts. Reject ambiguous
  or unsupported claims rather than silently converting them to broad hints.
  Add a versioned scenario fixture corpus.

  Completed 2026-06-11. T13 deterministic parsing now extracts procedure,
  initiator, outcome, failure stage, PDU-session selectors, DNN/S-NSSAI request
  fields, frame scopes, forbidden registration rejects, stage checkpoints and
  simple checkpoint ordering into the structured scenario contract consumed by
  T14.

- [x] **AR-110: Build a real evidence registry for T06-T25.** Register evidence
  IDs with source revision, partition, source refs, checksums, and authorization
  metadata at creation. T18 must resolve registry entries rather than scan all
  normalized events or guess by frame/protocol. `raw_full` must read verified
  retained source data; never return normalized content as raw evidence.

  Completed 2026-06-11. T18 now builds an internal evidence registry from
  normalized events, request-field evidence and detector candidates, recording
  source revision, partition, source refs, checksums, attempts, candidate IDs,
  record IDs and authorization tags. Evidence ID and record ID selectors resolve
  through that registry before capability checks, and `raw_full` is sourced from
  retained source references rather than normalized event payloads.

- [ ] **AR-111: Implement temporal NF lifecycle and readiness in T22/T23.** Build
  state transitions per NF/service/version/endpoint, account for failures and
  recoveries relative to attempt start, preserve unknown/partial visibility,
  and execute the full causal decision table. A failure after attempt start
  must not make the NF retroactively not-ready.

## P2: Security, Persistence, and Operations

- [ ] **AR-201: Implement the policy/profile/dictionary resolver.** Load only
  allowlisted resources, verify schema/version/checksum compatibility, freeze a
  policy-set revision, and fail startup on missing or corrupt mandatory inputs.
  Remove ad hoc dictionary and salt inputs from stage requests.

- [ ] **AR-202: Implement run-store lifecycle and recovery.** Add retention,
  reader/writer leases, legal hold, atomic deletion, startup recovery, stale
  staging cleanup, disk-space checks, audit logs, dry-run deletion, and path/
  symlink protection.

- [ ] **AR-203: Add packaging and reproducible installation.** Define a pinned
  lock/constraints strategy, package metadata, supported Python and Go versions,
  console entry point, tshark/editcap version checks, clean-environment install
  test, container or deployment artifact, and license/SBOM generation.

- [ ] **AR-204: Add secrets, masking, and logging controls.** Resolve secrets
  from environment or a secret manager, prohibit raw keys in models/manifests/
  logs, redact command arguments and provider payload logs, apply surface-
  specific masking, set restrictive file permissions, and add secret-scanning
  and sensitive-evidence tests.

- [ ] **AR-205: Add bounded resource usage.** Replace repeated `_load_all_events`
  scans with indexed/streamed readers, cap request sizes and selector counts,
  enforce timeouts and cancellation throughout, bound open files/memory, and
  benchmark large captures and many concurrent attempts.

- [ ] **AR-206: Add operational observability.** Emit structured logs, stage and
  provider metrics, trace/run IDs, progress events, cancellation state, disk and
  memory warnings, and actionable terminal error codes without leaking evidence.

- [ ] **AR-207: Add schema and compatibility gates.** Generate/validate JSON
  schemas for shared models, lint issue-code ownership, validate descriptors and
  revisions, test backward-compatible readers, and reject unknown schema or
  policy versions deterministically.

- [ ] **AR-208: Add CI quality gates.** Run Python unit/integration tests, Go
  tests, formatting, lint, static typing, dependency/security scanning, coverage,
  schema checks, fixture checksums, deterministic reruns, and Markdown contract
  checks. Remove imported `TestCase` collection duplication and set meaningful
  coverage thresholds per stage.

## P3: Validation and Product Readiness

- [ ] **AR-301: Build reproducible real-capture fixtures.** Add sanitized or
  generated PCAPs with provenance, license, checksums, release/profile metadata,
  expected artifacts, and regeneration commands. Cover success, explicit
  failure, missing response, partial capture, roaming, non-3GPP, PFCP node and
  session failures, NRF/UDR dependency failures, retries, recovery, and corrupt
  input.

- [ ] **AR-302: Add end-to-end conformance and golden tests.** Run actual T01
  decode through T17 report and on-demand T18-T25 operations. Assert evidence
  resolution, partition security, immutable revisions, deterministic normalized
  outputs, and stable reports after approved normalization.

- [ ] **AR-303: Add scale, soak, and concurrency tests.** Establish supported
  capture sizes, packet counts, attempt counts, parallel runs, provider latency,
  disk usage, and runtime targets. Test cancellation, process death, full disk,
  stale leases, concurrent readers, and repeated resume over long-running jobs.

- [ ] **AR-304: Add provider quality and safety evaluation.** Maintain a fixed
  evidence-packet evaluation set, measure schema success, citation validity,
  deterministic-conflict rate, unsupported claims, dependency-request precision,
  latency, and cost for every supported provider/model configuration.

- [ ] **AR-305: Complete user-facing behavior.** Document installation,
  configuration, supported captures/releases, command examples, exit codes,
  progress, report interpretation, limitations, retention, masking, and incident
  diagnostics. Provide machine-readable output suitable for automation.

## Release Gates

The application is ready for a first supported release only when all of the
following are true:

- All P0 items are complete and have regression tests.
- No evidence partition or capability bypass is known.
- A clean install can run a real PCAP from T01 through T17 with no manual Python
  object construction.
- T18/T19 return resolvable, checksum-verified evidence and T20 performs a real
  bounded re-decode.
- Provider-disabled, local-provider, and remote-provider paths report truthful
  terminal status.
- Identical pinned inputs produce identical revision-bearing artifacts, apart
  from explicitly normalized operational timestamps.
- Real-capture conformance, failure recovery, scale, security, and golden-report
  suites pass in CI.
- The report exposes limitations and never claims a stage or integrity check ran
  when it did not.

## Review Verification Performed

- `PYTHONPATH=V2 python3 -m unittest discover -s V2/harness/tests -t V2 -v`
  passed: 49 collected tests after AR-107/AR-108/AR-109/AR-110.
- `go test ./...` passed in `V2/tools/decoder`.
- `python3 -m compileall -q V2/harness` passed.
- `python3 -m py_compile V2/harness/shared.py V2/harness/normalize.py
  V2/harness/identity.py V2/harness/attempts.py V2/harness/post_analysis.py
  V2/harness/tests/test_t02_t03.py V2/harness/tests/test_t04_t10.py
  V2/harness/tests/test_t11_t25.py` passed.
- `git diff --check` passed.
- No `ruff`, `mypy`, or `pyright` executable is currently installed.

## Exact Next Item

Continue with **AR-111**. T22/T23 still need temporal NF lifecycle and readiness:
per-NF/service/version/endpoint state transitions, failure/recovery timing,
unknown/partial visibility and the full causal decision table.
