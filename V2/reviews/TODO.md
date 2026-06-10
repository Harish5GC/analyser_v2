# V2 Consolidated Review Todo

This is the sole actionable review backlog for V2. It consolidates the accepted and valid portions of:

- `REVIEW_FINDINGS.md`
- `review_fable.md`
- `ultra_review.md`

Items are deduplicated by implementation outcome. Review references identify the originating findings; they are not separate work items.

## Completion Rules

An item is complete only when:

1. The canonical contract is updated in `requirement.md`, `architecture.md`, `LLD.md`, and affected Txx specifications where applicable.
2. Shared schemas have one owner and generated/validated serialization schemas.
3. Conflicting text is removed rather than left as an alternative interpretation.
4. Required unit, integration, security, and conformance tests are present.
5. Artifact paths, revisions, issue codes, and configuration versions are deterministic and auditable.

## Native Review Coverage

The mappings below use identifiers that appear in the source reviews. A finding may map to multiple consolidated items where it contained independent outcomes. Ultra `U1-U13` are aliases folded into A-items and section-4 lows, not additional findings.

### `REVIEW_FINDINGS.md`

- `H1 -> V2-006`; `H2 -> V2-014`; `H3 -> V2-015`; `H4 -> V2-045`; `H5 -> V2-018,V2-060`; `H6 -> V2-019`.
- `M1 -> V2-016`; `M2 -> V2-061`; `M3 -> V2-007`; `M4 -> V2-021`; `M5 -> V2-020`; `M6 -> V2-005`; `M7 -> V2-032`; `M8 -> V2-038`; `M9 -> V2-052`; `M10 -> V2-023`; `M11 -> V2-022`; `M12 -> V2-035`.
- `L1 -> V2-046`; `L2 -> V2-049,V2-055`; `L3 -> V2-006,V2-014`; `L4 -> V2-053`; `L5 -> V2-040`; `L6 -> V2-035`; `L7 -> V2-047`; `L8 -> V2-010`; `L9 -> V2-036`; `L10 -> V2-030`; `L11 -> V2-001,V2-048` with its ASCII-art sub-item explicitly rejected as cosmetic.

### `review_fable.md`

- `F1 -> V2-017,V2-054`; `F2 -> V2-025`; `F3 -> V2-037`; `F4 -> V2-031`; `F5 -> V2-026,V2-059`; `F6 -> V2-033,V2-034,V2-044,V2-059`; `F7 -> V2-008,V2-055`; `F8 -> V2-012,V2-056`; `F9 -> V2-038`; `F10 -> V2-011,V2-057`; `F11 -> V2-039,V2-044`; `F12 -> V2-013,V2-040,V2-058`; `F13 -> V2-019,V2-057`; `F14 -> V2-043,V2-057`.

### `ultra_review.md`

- `C1 -> V2-049,V2-055`; `C2 -> V2-005`; `C3 -> V2-052`; `C4 -> V2-038`; `C5 -> V2-019`; `C6 -> V2-007`.
- `A1 -> V2-017,V2-054`; `A2 -> V2-008,V2-055`; `A3 -> V2-014,V2-015,V2-016,V2-061`; `A4 -> V2-001,V2-002,V2-003`; `A5 -> V2-006,V2-007`; `A6 -> V2-045`; `A7 -> V2-018,V2-060`; `A8 -> V2-019,V2-057`; `A9 -> V2-005,V2-009`; `A10 -> V2-004`; `A11 -> V2-009`; `A12 -> V2-012,V2-056`; `A13 -> V2-038`; `A14 -> V2-011,V2-044,V2-057`; `A15 -> V2-039,V2-044`; `A16 -> V2-013,V2-040,V2-058`; `A17 -> V2-035,V2-036`; `A18 -> V2-027,V2-059`; `A19 -> V2-028,V2-029,V2-059`; `A20 -> V2-020,V2-021,V2-022,V2-023,V2-025,V2-026,V2-031,V2-032,V2-037,V2-043,V2-057`.
- Ultra aliases: `U1 -> V2-001,V2-002,V2-003`; `U2 -> V2-004`; `U3 -> V2-005,V2-009`; `U4 -> V2-009`; `U5 -> V2-027,V2-059`; `U6 -> V2-028,V2-029,V2-059`; `U7 -> V2-035,V2-036`; `U8 -> V2-024,V2-059`; `U9 -> V2-041`; `U10 -> V2-042`; `U11 -> V2-040`; `U12 -> V2-042`; `U13 -> V2-019,V2-057`.
- Ultra section-4 carried identifiers: `R18 -> V2-046`; `R20 -> V2-006,V2-014`; `R21 -> V2-053`; `R22 -> V2-040`; `R23 -> V2-035`; `R24 -> V2-047`; `R26 -> V2-035,V2-036`; `R27 -> V2-030`; `R28 -> V2-048`; `C1 residue -> V2-049,V2-055`; `C3 residue -> V2-052`; `C4 residue -> V2-038`; `F6 residue -> V2-044`; provider-package nit `-> V2-050`; hardware-language nit `-> V2-051`.

### Design Hardening Beyond Review Coverage

- `V2-062` adds reproducible fixture-PCAP provenance. It closes an implementation prerequisite discovered during consolidation and is not presented as a missing review finding.

## P0: Orchestration and Foundational Contracts

- [x] **V2-001: Rewrite the end-to-end orchestration contract.** Defined the T01-T25 dependency graph, mandatory/conditional/on-demand gates, T05/T10 placement, T06-T08-before-T09 ordering, per-attempt isolation, `DetectionContext` flow, publication ordering, corrected pseudocode, and orchestration tests in `requirement.md` section 7.1, `architecture.md` section 3.2, and `LLD.md` sections 19 and 21. Review refs: Ultra A4; Findings L11.
- [x] **V2-002: Define dependency-expanded deterministic processing.** Defined the inspection commit barrier, admitted terminal statuses, lineage/integrity checks, deterministic result ordering, immutable parent/child T12 and T14 revisions, revised T15 packet inputs, final T16 validation, T17 history/diff reporting, and empty/partial/failed inspection tests across the core documents and T12/T14/T15/T16/T17/T24/T25 specifications. Review refs: Ultra A4.
- [x] **V2-003: Define attempt selection and model-call policy.** Added explicit selector precedence, deterministic ordering modes, per-run model cap, manifest accounting, CLI/config fields, report disclosure, and narration-policy tests in `LLD.md` sections 2, 3, 21 and 28 plus `requirement.md`, `architecture.md`, and T17. Review refs: Ultra A4.
- [x] **V2-004: Separate evidence stage from model pass.** Defined shared `EvidenceStage` (`primary`, `dependency_expanded`) and `ModelPass` (`initial`, `final`), legal mappings/transitions, and shared imports for T12/T14/T15/T16 in `LLD.md` sections 4.10 and 23. Review refs: Ultra A10.
- [x] **V2-005: Canonicalize dependency request and result contracts.** Defined the canonical reason codes/request/result union and deterministic T16-to-T24/T25 adapters in `LLD.md` section 17 and affected tool contracts, retaining T23's discriminator without redundant T24/T25 fields. Review refs: Ultra C2/A9; Findings M6.
- [x] **V2-006: Define immutable `FailureCandidate` ownership.** Added named score terms, field-owner/default rules, inconclusive dependency-impact default, detector responsibilities, immutable T12 consumption, and ownership tests in `LLD.md` sections 4.6, 12 and 21 plus T06-T09/T12. Review refs: Ultra A5/R20; Findings H1/L3.
- [x] **V2-007: Add a shared `DetectionContext`.** Defined the attempt-scoped context with bounds, phase reader, visibility, assignment confidence and resolved policy handles in `LLD.md` sections 11 and 23; T06-T09 now consume it instead of loose version strings. Review refs: Ultra A5; Findings M3.
- [x] **V2-008: Implement the central evidence registry contract.** Defined deterministic minting, normalized source references, revision scope, deduplication/collision handling, storage/indexing and provider-independent T18 resolution in `LLD.md` section 24 and T06/T15/T18. Review refs: Ultra A2; Fable F7.
- [x] **V2-009: Publish the shared-model registry.** Assigned every cross-tool model to one module with one-way imports and canonical schemas in `LLD.md` section 23, including the common dependency baseline plus explicit UDR specialization. Review refs: Ultra A9/A11; Findings L9.
- [x] **V2-010: Define all T13 nested schemas.** Added selectors, expected requests, time scopes, ordering, spans, conflicts, matcher/condition models, validation limits and masking modes in T13 section 5a with shared-model ownership in `LLD.md` section 23. Review refs: Findings L8.
- [x] **V2-011: Define revision envelopes and immutable publication.** Defined canonical digests, parent/input lineage, tool/config/policy/schema versions, compatibility and manifest-last publication in `LLD.md` section 25; aligned T01/T02/T04 and orchestration tests. Review refs: Ultra A14; Fable F10.
- [x] **V2-012: Define the machine-readable issue registry.** Defined the canonical `Issue`, namespace rules, registry metadata, aggregation behavior and unknown-code prohibition in `LLD.md` section 26 with lint coverage in section 21. Review refs: Ultra A12; Fable F8.
- [x] **V2-013: Define the run manifest and `AnalysisState`.** Defined stage invocation lineage, selected attempts, provider/dependency executions, publication state and criticality-based run aggregation in `LLD.md` section 27 with T17 status ownership. Review refs: Ultra A16; Fable F12.
- [x] **V2-014: Canonicalize root-cause scoring.** Reconciled T12 and LLD into one 13-term Decimal model with defaults, bounds, persistence, scalar derivation and deterministic tie rules in `LLD.md` section 12 and T12 section 8. Review refs: Ultra A3; Findings H2/L3.
- [x] **V2-015: Canonicalize baseline selection.** Replaced conflicting weighted selection with eligibility filtering followed by deterministic similarity-band, nearest-earlier-frame and UUID ordering; retained numeric score for audit only in `LLD.md` section 13 and T11. Review refs: Ultra A3; Findings H3.
- [x] **V2-016: Reconcile T03 identity-link thresholds.** Defined validated automatic (`>=0.90`), warning (`0.70-0.89`) and candidate (`<0.70`) bands, conflict behavior and boundary tests in `LLD.md` section 4.4 and T03. Review refs: Ultra A3; Findings M1.
- [x] **V2-061: Clarify T07/T09 missing-transition ownership.** Made T09 the sole implicit missing-transition candidate owner at base `0.65`; T07 now retains request-only observations without duplicate missing-response candidates, with aligned scope, scoring and tests. Review refs: Ultra A3; Findings M2.
- [x] **V2-017: Complete the procedure-profile registry and traceability.** Added the single normative T04-owned contract at `profiles/README.md`, referenced by T04, T09, `LLD.md`, and `tools/README.md`; it defines schemas/API, release/deployment overlays, condition facts, ordering, revisions, compatibility, review and mappings for requirement flows 8.1-8.10 and acceptance criteria 13-18. Review refs: Ultra A1; Fable F1.

## P1: Runtime, Protocol, and Scenario Behavior

- [x] **V2-018: Define honest targeted re-decode bounds.** Defined independent result, slice/dissection and source-scan limits; indexed versus O(source-position) scan-preslice modes; HTTP2/HPACK, SCTP/NGAP and IP-fragment context expansion; source-frame remapping; optional T01 packet-access indexing; conservative scan accounting; full provenance; cleanup and mode-specific benchmarks across T20, T01, requirements, architecture and `LLD.md` section 7.3. Review refs: Ultra A7; Findings H5.
- [ ] **V2-019: Formalize token budgeting and counting.** Wire configured/provider/model limits into T15/T16, define effective budget and below-minimum behavior, pin model tokenizer/version when available, define a tested conservative fallback, add safety margin, include method identity in revisions, and test adversarial Unicode/JSON. Review refs: Ultra A8; Findings H6; Fable F13.
- [ ] **V2-020: Complete provider retry accounting.** Define a configurable total-call cap per model pass and precedence among transport retry, structured-output fallback, and schema repair. Persist every call and terminal reason. Review refs: Ultra A20/M5; Findings M5.
- [ ] **V2-021: Implement the central policy/profile/dictionary resolver.** Resolve version strings at startup to immutable schema-validated, checksummed handles. Define missing, incompatible, and corrupt-version behavior and pass handles rather than unverified strings. Review refs: Ultra A20/M4; Findings M4.
- [ ] **V2-022: Make dependency expansion accounting shared.** T22 extensions consume T24's one expansion budget. Persist the counter, reason, original/effective bounds, validator decision, and denial. Review refs: Ultra A20/M11; Findings M11.
- [ ] **V2-023: Convert T23 impact semantics into an executable decision table.** Define deterministic ordering for eligibility, causal-link construction, temporal checks, counterfactual, contradictions, recovery, and final causal/contributing/unrelated/inconclusive classification. Preserve the semantics already stated by T23. Review refs: Ultra A20/M10; Findings M10.
- [ ] **V2-024: Make `REGISTRATION COMPLETE` conditional.** Encode release/profile-specific acknowledgement conditions and fixtures for Registration Accept cases that do and do not require completion. Review refs: Ultra U8.
- [ ] **V2-025: Add a roaming topology and fault-domain producer.** Produce typed home/visited/home-routed/local-breakout/inconclusive topology, evidence terms, alternatives, confidence, provenance, and independent fault-domain classification for T04/T11/T12/T14/T17. Review refs: Ultra A20/F2; Fable F2.
- [ ] **V2-026: Complete concrete non-3GPP contracts.** Reuse existing requirement-level N3IWF/TNGF rules; add trusted/untrusted access anchors, T03 access-context identity keys, access-scoped registration state, and T04 non-merge rules for concurrent 3GPP/non-3GPP attempts. Review refs: Ultra A20/F5; Fable F5.
- [ ] **V2-027: Make interface visibility release/profile-aware.** Represent reference-point visibility separately from SBI service/API visibility. Add applicable N7, N13, N35, N36, and N37 definitions through the selected release/deployment profile rather than one timeless enum. Review refs: Ultra A18.
- [ ] **V2-028: Add PFCP node-state and association observations.** Index Association Setup/Update/Release rejection, timeout, restart/recovery discontinuity, and node-pair availability independently of attempts. Derive an attempt candidate only when the attempt selected or used that node pair and causal evidence exists. Review refs: Ultra A19.
- [ ] **V2-029: Add relevant PFCP Session Report handling.** Treat Error Indication and user-plane path failure as potential failure evidence when F-TEID/SEID maps to the attempt. Preserve Downlink Data, Usage, and other reports as observations unless profile/cause rules prove failure relevance. Review refs: Ultra A19.
- [ ] **V2-030: Define directional F-TEID consistency.** Use procedure/profile-aware IE roles to map NGAP downlink tunnels to PFCP FAR Outer Header Creation and PFCP-created uplink PDR/F-TEID to NGAP expectations. Cover handover/path-switch timing, target activation, and N9 variants without assuming one static direction rule for every procedure. Review refs: Ultra R27; Findings L10.
- [ ] **V2-031: Carry alternative procedure profiles.** Persist profile IDs, score terms, confidence, evidence, selection/rejection/disambiguation status, and render them separately from root-cause alternatives in T17. Review refs: Ultra A20/F4; Fable F4.
- [ ] **V2-032: Clarify NF readiness cardinality.** Choose either one snapshot per service/version/endpoint tuple or `ServiceRequirement[]`; define aggregation across NF instances and missing/partial observations. Review refs: Ultra A20/M7; Findings M7.
- [ ] **V2-033: Assign reachability-loss and mobile-terminated delivery ownership.** Map paging/service-request reachability and MT-delivery failures to concrete profiles and detectors, with visible/invisible-interface behavior and evidence requirements. Review refs: Fable F6.
- [ ] **V2-034: Publish the observability timing checklist.** Define required stage timings, source anchors, absent/not-applicable semantics, precision, and report fields in one shared contract. Review refs: Fable F6.

## P2: Persistence, Security, and Reporting

- [ ] **V2-035: Canonicalize the full artifact tree.** Reconcile requirements, architecture, LLD, and all Txx outputs. Include identity, attempts, requests, diagnostics, model, immutable T19 query directories, indexes, manifests, and staging ownership. Review refs: Ultra A17/R23/R26; Findings M12/L6.
- [ ] **V2-036: Define file and collection descriptors.** Specify relative-path constraints, media/schema types, checksum semantics, ordered child indexes, record counts, parent source checksum, and child-entry validation. Review refs: Ultra R26; Findings L9.
- [ ] **V2-037: Complete the `run_store` lifecycle contract.** Define retention calculation, completed-run eligibility, reader/writer leases, legal hold, all-or-nothing deletion, symlink/path safety, crash recovery, audit, dry-run, and failure tests under run-store/orchestrator ownership. Review refs: Ultra A20/F3; Fable F3.
- [ ] **V2-038: Centralize masking policy.** Define trusted clear storage, run-local keyed lookup hashes, analysis aliases, optional local-display masks, provider-packet aliases, report redaction, key scope/rotation, allowed transforms, and per-surface failure behavior. Forbid stable cross-run remote pseudonyms. Review refs: Ultra A13/C4; Findings M8; Fable F9.
- [ ] **V2-039: Define the authenticated cursor envelope.** Specify version, purpose/tool, key reference, issue/expiry times, query/policy/revision binding, payload, replay checks, and reviewed MAC/AEAD policy. Retain tool-specific T10/T18/T19 payloads inside the common envelope. Review refs: Ultra A15; Fable F11.
- [ ] **V2-040: Reconcile report schema, status, and golden normalization.** Adopt `pipeline` with a typed decoder subsection, map stage/run status, define backward compatibility, and normalize IDs, times, paths, durations, ordering, and provider metadata in golden reports. Review refs: Ultra A16/R22/U11; Findings L5.
- [ ] **V2-041: Fix the secret input contract.** Replace raw `api_key` inputs with `api_key_env` or a secret-manager reference in every requirements/config/provider contract. Review refs: Ultra U9.
- [ ] **V2-042: Clarify logical event schema versus JSONL persistence.** Define required per-record metadata, cardinality, and use `raw_refs` consistently while retaining JSONL as the physical format. Review refs: Ultra U10/U12.
- [ ] **V2-043: Canonicalize persisted numeric and timestamp semantics.** Use absolute Unix-epoch decimal seconds with source precision and canonical decimal-string serialization for persisted/revision-bearing scores, times, and policy inputs. Define conversion from runtime floats without banning them. Review refs: Ultra A20/F14; Fable F14.
- [ ] **V2-044: Ratify external cursor and revision guarantees.** Add requirement-level guarantees that cursors cannot broaden authorization or cross query/revision scope and that published evidence revisions remain immutable and resolvable for their retention lifetime. Keep algorithms and key lifecycle in architecture/LLD. Review refs: Ultra F6; Fable F6.

## P3: Contract Clarifications

- [ ] **V2-045: Define version vocabulary and capability gates.** Separate product generation, release milestone, document revision, schema version, policy version, and artifact revision. Replace behavioral `V2.1` prose with named capabilities where appropriate. Review refs: Ultra A6; Findings H4.
- [ ] **V2-046: Reference one canonical NAS message registry.** T02 must reference the LLD/config codepoint registry and explicitly route NAS/NGAP/PFCP to the primary partition. Do not duplicate tables. Review refs: Ultra R18; Findings L1.
- [ ] **V2-047: Tighten the T10 timeline contract.** Hard-clamp model mode to 20, define the eight-label taxonomy and extensibility, and replace diagnostic-conclusion wording with checkpoint/candidate evidence wording. Review refs: Ultra R24; Findings L7.
- [ ] **V2-048: Reconcile operational CLI flags and configuration.** Define or remove NRF/UDR-success and unmasked-local-evidence flags, including safety/report effects, and ensure orchestration signatures receive declared configuration. Review refs: Ultra R28; Findings L11.
- [ ] **V2-049: Document T05's existing `primary_internal` capability.** Name the already-enforced capability in T05 and reference T18's post-selector-expansion NRF/UDR denial. This is contract clarity, not a new partition mechanism. Review refs: Ultra C1; refuted Findings L2 residue.
- [ ] **V2-050: Reference the shared provider abstraction.** Remove T13/T14 wording that makes T16 appear to own provider interfaces; name the common provider package and contracts. Review refs: Ultra provider-naming item.
- [ ] **V2-051: Move hardware assumptions to deployment profiles.** Replace normative RTX 5090 wording with resource-profile language and maintain local-model hardware benchmarks separately. Review refs: Ultra T16 hardware item.
- [ ] **V2-052: Document T15's existing mandatory-evidence guarantee.** State that nonessential details may be shortened during normal trimming, mandatory evidence is never removed, and construction fails deterministically when mandatory content cannot fit. No behavioral reordering is required solely to satisfy the rejected bodies-last claim. Review refs: Ultra C3; effectively satisfied Findings M9 residue.
- [ ] **V2-053: Document PFCP unknown versus inconclusive.** Keep transaction outcome `unknown` as an observation state; map partial/unknown visibility to inconclusive diagnostic confidence only where evidence warrants it. Do not add `inconclusive` to the transaction-outcome enum. Review refs: rejected Ultra R21/Findings L4 proposal, retained documentation residue.

## P4: Required Validation

- [ ] **V2-054: Add profile-registry completeness tests.** Fail CI when a required procedure has no profile file, fixture, requirement mapping, supported release/deployment, terminal definition, or owner. Review refs: Fable F1.
- [ ] **V2-055: Add evidence-resolution and partition-security tests.** Every evidence ID emitted by T06-T14 and T22-T25 must resolve through T18 before T15. Prove T05 plus `primary_internal` cannot resolve NRF/UDR evidence through direct IDs, indexes, cursors, or selector expansion. Review refs: Fable F7; Findings L2.
- [ ] **V2-056: Add issue-code registry linting.** Validate code membership, namespace ownership, severity compatibility, stable serialization, and absence of unknown machine codes. Review refs: Fable F8.
- [ ] **V2-057: Add deterministic revision, numeric, and token tests.** Identical inputs and pinned tool/policy/tokenizer versions must produce byte-identical artifacts, revisions, and trimming across supported machines. Review refs: Fable F10/F13/F14.
- [ ] **V2-058: Add status aggregation fixtures.** Cover absent protocol, partial decode, no scenario, provider disabled/failed, empty dependency result, unknown phase, evidence corruption, and report publication failure. Review refs: Fable F12.
- [ ] **V2-059: Add protocol and scenario conformance fixtures.** Cover conditional Registration Complete, roaming modes, non-3GPP access separation, release/profile visibility, PFCP association failures before/during attempts, PFCP Error Indication, non-failure Session Reports, directional F-TEIDs, reachability loss, and MT delivery. Review refs: Ultra U8/A18/A19; Fable F5/F6.
- [ ] **V2-060: Add targeted re-decode scale and correctness tests.** Test early/late windows in large captures, compressed inputs, HTTP2/HPACK state, TCP fragmentation, SCTP reassembly, source/slice provenance, and declared fallback complexity. Review refs: Ultra A7; Findings H5.
- [ ] **V2-062: Define reproducible fixture-PCAP provenance.** Make `V2/harness/tests/fixtures/README.md` the fixture manifest contract. For each PCAP or generated trace, record source/license, sanitization method, generator and version, deterministic seed/inputs, protocol and scenario coverage, applicable release/profile, checksum, expected outputs, and regeneration instructions. CI must detect unmanifested or checksum-drifted fixtures. Design-hardening addition discovered during consolidation.

## Rejected or Refuted Finding Audit

No actionable item above implements these rejected fixes. Only the listed valid residue remains:

| Rejected or over-broad proposal | Consolidated treatment |
|---|---|
| Add `dependency_type` to T24/T25 because routing is absent | Rejected. V2-005 documents the existing T16 `tool` routing adapter and canonicalizes only the genuinely stale shared contracts. |
| Add a new NRF/UDR partition restriction for T05/T18 | Refuted because T18 already enforces it after selector expansion. V2-049 documents the capability; V2-055 adds regression coverage. |
| Reorder T15 so body shortening is a new mandatory last-resort behavior | Rejected as a functional defect because mandatory evidence is already protected. V2-052 is documentation-only. |
| Replace or extend PFCP transaction outcome `unknown` with `inconclusive` | Rejected. V2-053 documents the separation between observation outcome and diagnostic confidence. |
| Treat the profile registry as a callable runtime/model tool because no owner exists | Rejected. Ultra A1's request for one specification is accepted by V2-017 at `V2/profiles/README.md`; only the callable-tool interpretation is rejected. |
| Unify every stage/tool status into one enum | Rejected. V2-013 and V2-040 retain local statuses and define only run-level aggregation. |
| Use one enum for evidence stage and model pass | Rejected as conceptually over-broad. V2-004 defines separate enums plus mappings. |
| Duplicate NAS codepoint tables in T02 | Rejected. V2-046 references one canonical registry and adds only the missing routing statement. |
| Redesign T01 `--output-dir` semantics | Rejected. V2-035/V2-036 clarify layout and descriptors without changing the command contract. |
| Treat `editcap` pre-slicing as source-size-independent random access | Rejected. V2-018/V2-060 distinguish scan cost from decode bounds and require context-safe/indexed handling where needed. |
| Hard-code all known reference points in one permanent visibility enum | Rejected as insufficient. V2-027 makes visibility release/profile-aware and separates reference points from SBI services. |
| Emit one node-level PFCP candidate directly against multiple attempts | Rejected. V2-028 stores node observations and derives attempt candidates only through supported links. |
| Convert every runtime float to `Decimal` | Rejected as over-broad. V2-043/V2-057 require canonical serialization only at persistence and revision boundaries. |
| Put cursor cryptographic mechanisms into product requirements | Rejected. V2-044 ratifies only externally observable authorization, scope, immutability, and retention guarantees. |
| Fix cosmetic architecture diagram alignment as implementation work | Rejected as non-blocking and omitted from the backlog. |

## Explicit Non-Actions

- Do not add a redundant `dependency_type` field to T24/T25.
- Do not replace PFCP transaction outcome `unknown` with diagnostic `inconclusive`.
- Do not make the profile registry model-callable unless a future runtime-service requirement proves it necessary; its normative specification is required at `V2/profiles/README.md`.
- Do not duplicate NAS codepoint tables across LLD and T02.
- Do not collapse tool-specific statuses into one enum.
- Do not collapse evidence composition stage and model invocation phase into one enum.
- Do not use `ceil(bytes/3.5)` as a normative token estimator without tokenizer-specific validation.
- Do not claim `editcap` makes decode cost independent of source-capture size.
- Do not create one PFCP failure candidate shared directly by multiple attempts.
- Do not require every runtime float to become `Decimal`; require canonical serialization at persistence/revision boundaries.
- Do not elevate cursor cryptographic mechanisms into product requirements; requirements contain externally observable security guarantees only.
- Do not redesign T01 `--output-dir`; clarify descriptors and layout instead.
- Do not remove mandatory T15 evidence to meet a token budget.

## External Technical References

- 3GPP TS 23.501 reference points: <https://www.etsi.org/deliver/etsi_ts/123500_123599/123501/15.13.00_60/ts_123501v151300p.pdf>
- 3GPP TS 24.501 registration acknowledgement behavior: <https://www.etsi.org/deliver/etsi_ts/124500_124599/124501/15.01.00_60/ts_124501v150100p.pdf>
- 3GPP TS 29.244 PFCP association and Session Report procedures: <https://www.etsi.org/deliver/etsi_ts/129200_129299/129244/18.06.00_60/ts_129244v180600p.pdf>
- TShark display-filter behavior: <https://www.wireshark.org/docs/man-pages/tshark.html>
- Editcap range-selection behavior: <https://www.wireshark.org/docs/man-pages/editcap.html>
