# T03 `build_identity_graph` Implementation Specification

## 1. Purpose

`build_identity_graph` correlates identifiers observed across primary NGAP, NAS, SBI, and PFCP events into evidence-backed UE, session, access-context, and user-plane-context identities.

The graph allows later tools to follow one procedure across protocol boundaries while preserving uncertainty, identifier reuse, handover remapping, and incomplete-capture conditions.

## 2. Non-Goals

T03 must not:

- Access NRF or UDR partitions.
- Decide where an attempt starts or ends.
- Diagnose a protocol failure.
- Merge identities using timestamp proximity alone.
- Treat a PDU session ID, PTI, SEID, TEID, UE IP, or stream ID as globally unique.
- Expose clear subscriber identifiers outside the trusted local store.

## 3. Ownership Boundary

### 3.1 Inputs owned by T03

- Read-only `PrimaryEventReader`.
- T02 canonical events and identifier index.
- Analysis-scoped identity-correlation configuration.

### 3.2 Outputs owned by T03

- Identity nodes and edges.
- Validity intervals.
- Connected-component assignments.
- Ambiguous edge candidates and conflicts.
- UE/session/context lookup indexes.
- Time-bounded roaming topology classifications and independent fault-domain
  maps for each resolved UE/access/session context.

T04 consumes the graph but remains responsible for attempt segmentation.

## 4. Python Tool Contract

```python
class BuildIdentityGraphRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    primary_reader: PrimaryEventReader
    config: IdentityGraphConfig


class IdentityGraphConfig(BaseModel):
    identity_rules: ResolvedPolicy
    topology_rules: ResolvedPolicy
    supporting_signal_window_seconds: Decimal = Decimal("5")
    context_idle_timeout_seconds: Decimal = Decimal("30")
    max_candidate_edges_per_observation: int = 20
    auto_link_threshold: Decimal = Decimal("0.90")
    warning_link_threshold: Decimal = Decimal("0.70")
    sensitive_hash_key_id: str


class BuildIdentityGraphResult(BaseModel):
    schema_version: Literal["2.0"]
    analysis_id: UUID
    status: Literal["success", "partial", "failed"]
    graph_manifest: ArtifactDescriptor
    ue_nodes: int
    session_nodes: int
    context_nodes: int
    accepted_edges: int
    ambiguous_edges: int
    conflicts: int
    topology_intervals: int
    warnings: list[IdentityWarning]
```

The returned result contains counts and artifact descriptors. Downstream code opens the graph through `IdentityGraphReader`; it does not receive a large in-memory result object.

### 4.1 Roaming topology output

```python
class TopologyEvidenceTerm(BaseModel):
    fact: Literal[
        "SERVING_PLMN", "HOME_PLMN", "SUCI_HOME_NETWORK", "GUAMI_PLMN",
        "TAI_PLMN", "NF_DOMAIN", "SBI_ROUTING_DOMAIN", "DNN", "S_NSSAI"
    ]
    normalized_value: str
    implication: Literal["home", "visited", "home_path", "visited_path", "inter_plmn", "neutral"]
    weight: Decimal
    evidence_ids: list[UUID]

class TopologyAlternative(BaseModel):
    topology: Literal["home", "visited_unknown", "home_routed", "local_breakout", "inconclusive"]
    score: Decimal
    reason_codes: list[str]

class FaultDomainMap(BaseModel):
    ue_id: UUID | None
    access_context_id: UUID | None
    home_plmn: str | None
    serving_plmn: str | None
    home_nf_domain_aliases: set[str]
    visited_nf_domain_aliases: set[str]
    inter_plmn_path_aliases: set[str]
    upf_path_aliases: set[str]
    evidence_ids: list[UUID]
    confidence: Literal["high", "medium", "low", "inconclusive"]

class RoamingTopologyInterval(BaseModel):
    topology_id: UUID
    ue_id: UUID | None
    access_context_id: UUID | None
    session_node_id: UUID | None
    valid_from_frame: int
    valid_to_frame: int | None
    selected_topology: Literal["home", "visited_unknown", "home_routed", "local_breakout", "inconclusive"]
    alternatives: list[TopologyAlternative]
    evidence_terms: list[TopologyEvidenceTerm]
    confidence: Literal["high", "medium", "low", "inconclusive"]
    fault_domains: FaultDomainMap
    rules_revision: str
```

Topology and fault domain are separate outputs: topology describes home versus
visited routing; `FaultDomainMap` maps observed network entities/paths so T12
can classify a particular failure as `UE`, `RAN`, `VISITED_CORE`, `HOME_CORE`,
`INTER_PLMN`, `UPF_PATH` or `UNKNOWN`. A home-routed topology does not by itself
prove that a failure belongs to the home core.

### 4.2 Classification rules

T03 evaluates time-compatible facts in this order:

1. Resolve serving PLMN from TAI/GUAMI/access context and home PLMN from SUCI
   home-network identity or trusted subscriber context.
2. Equal trusted home/serving PLMN selects `home` unless stronger visited-path
   evidence conflicts.
3. Different home/serving PLMN establishes roaming but not routing mode;
   classify `visited_unknown` until path evidence exists.
4. V-SMF/visited consumer plus H-SMF/home-domain service and home-anchored UPF
   evidence selects `home_routed`; an N9/inter-PLMN path strengthens it but its
   invisibility alone does not disprove it.
5. Visited SMF/UPF anchoring with no required H-SMF/N9 and compatible
   authorization evidence selects `local_breakout`.
6. Conflicting, masked, missing or low-confidence PLMN/domain mappings produce
   scored alternatives and `inconclusive` when the lead over the next
   alternative is below the configured threshold.

Observed identifiers/domains outrank scenario hints. Domain matching uses
configured masked suffix/PLMN mappings, never substring guesses. Every selected
or rejected alternative persists score terms and evidence.

## 5. Graph Data Model

### 5.1 Identifier observation

```python
class IdentifierObservation(BaseModel):
    observation_id: UUID
    event_id: UUID
    frame: int
    timestamp: Decimal | None
    kind: IdentifierKind
    normalized_value: str
    sensitive: bool
    source_path: str
    role: Literal["UE", "SESSION", "ACCESS_CONTEXT", "USER_PLANE", "TRANSACTION"]
    confidence: Decimal
```

### 5.2 Identity node

```python
class IdentityNode(BaseModel):
    node_id: UUID
    node_type: Literal[
        "UE", "PDU_SESSION", "ACCESS_CONTEXT", "SM_CONTEXT", "PFCP_SESSION"
    ]
    first_frame: int
    last_frame: int
    first_timestamp: Decimal | None
    last_timestamp: Decimal | None
    provisional: bool = False
    incomplete_history: bool = False
    observation_ids: list[UUID]
```

### 5.3 Edge and conflict

```python
class IdentityEdge(BaseModel):
    edge_id: UUID
    left_observation_id: UUID
    right_observation_id: UUID
    relation: str
    strength: Literal["exact", "strong", "supporting"]
    confidence: Decimal
    reason_codes: list[str]
    supporting_event_ids: list[UUID]
    valid_from_frame: int
    valid_to_frame: int | None
    accepted: bool


class IdentityConflict(BaseModel):
    conflict_id: UUID
    kind: str
    observation_ids: list[UUID]
    competing_node_ids: list[UUID]
    frames: list[int]
    resolution: Literal["split", "prefer_explicit", "unresolved"]
    reason: str
```

## 6. Identifier Types and Scope

### 6.1 UE-level

- SUPI, SUCI, GPSI, PEI.
- 5G-GUTI and components.
- Masked/tokenized subscriber aliases.

### 6.2 Access-context

- AMF UE NGAP ID.
- RAN UE NGAP ID.
- SCTP association/stream as supporting context.
- GUAMI, TAI, CGI, access type, serving PLMN.
- Access family: `3gpp`, `non_3gpp_untrusted`, or `non_3gpp_trusted`.
- 3GPP anchor: gNB identity plus time-bounded N2 association and NGAP IDs.
- Untrusted non-3GPP anchor: N3IWF identity plus time-bounded N2 context and
  normalized NWu/IKE/IPsec tunnel or EAP-session identifiers when visible.
- Trusted non-3GPP anchor: TNGF identity plus time-bounded N2 context and
  normalized trusted-access tunnel/session identifiers when visible.

```python
class AccessContextKey(BaseModel):
    access_family: Literal["3gpp", "non_3gpp_untrusted", "non_3gpp_trusted"]
    anchor_type: Literal["GNB", "N3IWF", "TNGF", "UNKNOWN"]
    anchor_identity_alias: str | None
    n2_association_alias: str | None
    amf_ue_ngap_id: int | None
    ran_ue_ngap_id: int | None
    access_tunnel_alias: str | None
    validity_start_frame: int
    validity_end_frame: int | None

class AccessRegistrationState(BaseModel):
    ue_id: UUID
    access_context_id: UUID
    access_family: Literal["3gpp", "non_3gpp_untrusted", "non_3gpp_trusted"]
    state: Literal["deregistered", "registering", "registered", "suspended", "unknown"]
    state_event_ids: list[UUID]
    valid_from_frame: int
    valid_to_frame: int | None
```

An access context is keyed by the complete scoped tuple, not by UE identity or
AMF UE NGAP ID alone. Missing tunnel/anchor fields reduce confidence but never
permit a 3GPP and non-3GPP context to collapse into one node.

### 6.3 Session/context

- PDU session ID and NAS PTI.
- SM context reference and SBI correlation ID.
- Charging/session identifiers.
- DNN and S-NSSAI as supporting attributes.

### 6.4 User-plane/PFCP

- CP/UP SEID.
- PFCP sequence within endpoint pair.
- UE IP address.
- F-TEID/TEID and tunnel endpoint.
- PDR/FAR/QER relationship.

Each identifier kind has an explicit uniqueness scope. For example, `pdu_session_id` is scoped to UE/access context and time; TEID is scoped to endpoint/direction/time; PFCP sequence is scoped to endpoint pair.

### 6.5 Non-3GPP separation invariants

- One UE component may own multiple simultaneous `ACCESS_CONTEXT` nodes, one
  per active access-family/anchor/validity tuple.
- Subscriber-level evidence may link those nodes to the same UE, but it does
  not union the access-context nodes themselves.
- N3IWF and TNGF contexts are distinct even when they share AMF, PLMN, UE or
  PDU session identifiers. A trusted/untrusted access change creates a new
  access context and an evidence-backed mobility edge.
- A PDU session may have access-specific legs linked to one session node; leg
  identity, registration state, tunnel state and attempt assignment remain
  access-scoped.
- Deregistration/release for one access family closes only that context unless
  the decoded message explicitly scopes both access types.
- Time proximity, shared AMF endpoint, DNN/S-NSSAI or subscriber identity alone
  cannot merge concurrent access contexts.

## 7. Normalization and Privacy

- Normalize identifiers before matching but preserve source values through event references.
- Store clear subscriber values only in encrypted/local trusted artifacts if configured.
- General indexes use run-local keyed hashes for SUPI/SUCI/GPSI/PEI.
- Stable report/model aliases use analysis-scoped tokens such as `UE-1`; they cannot be reversed without local mapping.
- Never write clear subscriber identifiers to logs, metrics, warnings, or filenames.

## 8. Correlation Rule Classes

### 8.1 Exact evidence

Exact evidence may create an edge without supporting proximity when validity does not conflict:

- Same explicit SUPI/SUCI/GUTI observation.
- Same AMF/RAN UE ID pair in linked NGAP records.
- Explicit old/new UE ID mapping in context transfer or handover signaling.
- Explicit SM context URI/reference shared across SBI records.
- Explicit PFCP SEID linkage between establishment and later transactions.
- Explicit SBI-to-PFCP correlation field when present.

### 8.2 Strong evidence

Strong edges require a rule-specific combination:

- UE context + PDU session ID + PTI.
- SM context + matching PDU session + DNN/S-NSSAI.
- PFCP session establishment near a correlated SM-context operation with matching UE IP/DNN/slice.
- NGAP transport tunnel matching PFCP-created tunnel for the same session stage.
- Inter-AMF context transfer with old/new access identifiers and UE/session continuity.

### 8.3 Supporting evidence

Supporting signals can adjust an existing candidate score but never create a link alone:

- Timestamp proximity.
- Endpoint pair.
- Same NF type.
- Same DNN or S-NSSAI.
- Same UE IP without explicit session context.
- Similar procedure stage.

## 9. Confidence Scoring

Each rule has versioned weights. A typical score is:

```text
confidence = exact_signal_score
           + strong_signal_scores
           + bounded_supporting_scores
           - active_conflict_penalty
           - identifier_reuse_penalty
           - incomplete_capture_penalty
```

Scores are clamped to `[0, 1]`. Confidence is evidence quality, not statistical probability.

Link decisions use the named bands defined in `LLD.md` section 4.4
(`IdentityLinkThresholds`); both bounds are validated with
`auto_link_threshold > warning_link_threshold`:

- `confidence >= auto_link_threshold` (default `0.90`) and no hard conflict:
  edge is accepted automatically.
- `warning_link_threshold <= confidence < auto_link_threshold` (default
  `0.70-0.89`): edge is accepted with a persisted warning that lowers
  downstream correlation confidence.
- `confidence < warning_link_threshold`: candidate only. Candidates are
  persisted as ambiguous edges, never union components, and never merge UE
  contexts.

A hard conflict blocks acceptance in every band and routes the edge through
conflict resolution (section 13).

## 10. Validity Intervals

Every dynamic identifier has a validity interval derived from:

- First observation.
- Explicit allocation/creation.
- Explicit release/deregistration/deletion.
- Handover/context transfer remapping.
- Last observation plus bounded idle timeout when no release exists.
- Capture start/end uncertainty.

An identifier observed after its prior validity interval creates a new observation/node candidate. Reuse is expected and must not bridge completed contexts.

Explicit release closes the relevant context but does not erase historical edges.

## 11. Correlation Algorithm

1. Stream primary events in frame order.
2. Extract typed observations and write them to staging.
3. Query scoped active-observation indexes for exact candidates.
4. Evaluate exact rules and accept non-conflicting edges.
5. Evaluate strong rules for remaining candidates.
6. Add supporting scores only to already qualified candidates.
7. Detect hard conflicts before unioning graph components.
8. Close/expire dynamic identifier intervals on explicit release or timeout.
9. Build typed connected components.
10. Allocate deterministic UE/session/context node UUIDs.
11. Persist accepted, ambiguous, and rejected/conflict evidence.
12. Validate that no component contains prohibited simultaneous identities.

The implementation should use union-find for accepted edges plus explicit interval/conflict checks; ambiguous edges do not union components.

## 12. Deterministic Node IDs

Node IDs use UUIDv5 derived from:

```text
analysis_id + node_type + minimum stable observation key + first_frame
```

Adding a later supporting observation must not change an existing node ID. When a previous merge decision changes because configuration/rules change, the graph is a new revision with a different manifest, not an in-place rewrite.

## 13. Conflict Detection

Hard conflict examples:

- Two different explicit SUPIs active on the same proposed UE node.
- Same access IDs simultaneously associated with distinct explicit UE identities.
- One PFCP session linked to two incompatible active PDU sessions.
- Old and new handover contexts overlap beyond allowed transition without mapping evidence.
- Same GUTI reused after an explicit deregistration/context expiry.
- Proposed union of active 3GPP, N3IWF and/or TNGF access contexts without an
  explicit access-transfer relation.

Resolution policy:

- Prefer explicit identity evidence over inferred edges.
- Split connected components when possible.
- Retain unresolved alternatives when evidence is insufficient.
- Emit a warning that lowers downstream correlation confidence.

## 14. Capture Boundary Handling

- Capture starts mid-call: create provisional nodes with `incomplete_history=true`.
- Capture ends before release: leave validity open-ended and mark incomplete.
- Missing NAS identity: access/session nodes may exist without a resolved UE subscriber node.
- Encrypted NAS: use visible NGAP/SBI/PFCP evidence without inventing subscriber identity.

## 15. Output Layout and Indexes

```text
normalized/identity/
  observations.jsonl
  nodes.jsonl
  edges.jsonl
  ambiguous_edges.jsonl
  conflicts.jsonl
  identity_graph_manifest.json
indexes/
  ue_index.jsonl
  session_index.jsonl
  context_index.jsonl
  access_registration_state_index.jsonl
  identifier_index.jsonl
  event_identity_index.jsonl
  roaming_topology_index.jsonl
  fault_domain_index.jsonl
```

Indexes contain node IDs, validity bounds, hashed lookup values, and evidence
references. They must support lookup by event, masked identity, access-family /
anchor / context tuple, access-scoped registration state, session ID within UE
and access leg, SM context, SEID, UE IP, and tunnel identity.

## 16. Manifest

The graph manifest records:

- Analysis ID, graph schema, and rules version.
- T02 normalization manifest checksum.
- Configuration hash.
- Counts by node/edge/identifier/conflict type.
- Topology/fault-domain rules revision, outcome/confidence counts and
  alternative ambiguity counts.
- Confidence histogram.
- Provisional/incomplete node counts.
- Artifact descriptors.
- Timing, throughput, and peak RSS.
- Warning summaries.

## 17. Idempotency and Atomicity

- Same normalization checksum + rules/configuration produces identical observations, edges, node IDs, and indexes.
- Write under `normalized/identity/.staging-<uuid>/`.
- Publish graph data and indexes before the manifest.
- Failed runs leave no valid graph manifest.
- Existing graph revisions are immutable.

## 18. Failure Semantics

- Invalid/missing T02 manifest: fatal.
- One event with malformed identifier: warning, retain other observations.
- Candidate explosion beyond configured cap: truncate weakest candidates, warn, and mark partial.
- Hard graph invariant violation after resolution: fatal publication failure.
- Ambiguity/conflict: not fatal; persist explicitly and return partial when above policy threshold.
- Missing/conflicting roaming facts: persist `inconclusive` alternatives and
  an `UNKNOWN` domain map; do not fail identity graph publication.
- Disk/checksum/index publication failure: fatal.

## 19. Performance and Resource Requirements

- O(events + scoped candidate edges), not all-pairs O(n^2).
- Maintain active indexes partitioned by identifier type/scope.
- Expire closed contexts to bound candidate search.
- Stream persisted observations and edges.
- Metrics: events/sec, observations/sec, candidate edges, accepted/ambiguous edges, maximum active contexts, peak RSS.
- Large multi-UE captures must remain bounded by active contexts, not total historical events.

## 20. Security Requirements

- T03 only receives `PrimaryEventReader`.
- Clear sensitive identifiers never appear in logs or general indexes.
- Hash keys come from run-local secret material and are not persisted with reports.
- Treat identifier strings and URIs as untrusted data.
- Reject path escape and corrupted graph revision inputs.

## 21. Observability

Structured logs include:

- `analysis_id`, `tool=T03`, `event_id`, `observation_kind`.
- `rule_id`, `edge_strength`, `confidence_bucket`, `decision`.
- `conflict_code`, counts, and duration without sensitive values.

Metrics include edge-rule hit counts, ambiguity rate, conflict rate, provisional-node count, and graph build latency.

## 22. Proposed Python Code Structure

```text
V2/harness/analysis/
  identity_graph.py          orchestration and graph revision
  observations.py           typed extraction
  identity_rules.py         versioned exact/strong/supporting rules
  identity_scoring.py       confidence calculation
  validity.py               allocation/release/expiry intervals
  conflicts.py              invariant and split handling
  union_find.py             accepted component construction
  session_linker.py         SM/PFCP/session-specific rules
  roaming_topology.py       PLMN/domain/path classification
  fault_domains.py          independent entity/path domain maps
V2/harness/storage/
  identity_store.py
  identifier_index.py
V2/harness/models/
  identity.py
```

## 23. Implementation Sequence

1. Define observation/node/edge/conflict schemas.
2. Implement sensitive normalization and hashed indexes.
3. Implement exact access and subscriber rules.
4. Implement session/SM/PFCP strong rules.
5. Add validity interval and identifier reuse handling.
6. Add roaming topology alternatives and independent fault-domain maps.
7. Add conflict detection and component splitting.
8. Add persisted graph reader/indexes.
9. Add handover/inter-AMF rules and performance fixtures.

## 24. Tests

### 24.1 Unit tests

- Identifier normalization and scope.
- Exact, strong, supporting rule gating.
- Confidence thresholds and deterministic ties.
- Band boundaries: exactly `auto_link_threshold` auto-links, just below it warns, exactly `warning_link_threshold` warns, just below it stays candidate; config validation rejects `auto_link_threshold <= warning_link_threshold`.
- Validity open/close/expiry.
- UUID stability.
- Sensitive hashing and masking.
- Conflict detection and component split.
- Candidate cap behavior.
- Home, visited-unknown, home-routed, local-breakout and inconclusive topology
  classification with deterministic alternatives.
- Fault-domain maps remain independent from topology selection.

### 24.2 Integration tests

- Two UEs with overlapping timestamps/endpoints.
- Same UE with ten reused PDU session cycles.
- GUTI and NGAP ID reuse after release.
- Capture starting mid-procedure.
- Inter-AMF handover old/new identifier mapping.
- Concurrent 3GPP and N3IWF registrations for one UE remain separate access
  nodes and registration states.
- Trusted TNGF and untrusted N3IWF contexts remain distinct across access
  mobility and identifier reuse.
- Access-scoped deregistration closes one context without closing the other.
- SBI SM context to PFCP SEID and UE-IP correlation.
- Conflicting explicit SUPI/GUTI evidence.
- Encrypted NAS with unresolved subscriber identity.
- Large capture with bounded active-index memory.
- Roaming attempt with home/serving PLMN and NF-domain/path evidence consumed
  by T04/T11/T12/T14/T17.

### 24.3 Negative tests

- Timestamp-only records remain unlinked.
- Same DNN/slice does not merge UEs.
- Same TEID on different endpoints does not merge tunnels.
- Same UE/AMF/PLMN and overlapping time do not merge 3GPP, N3IWF or TNGF
  access contexts.
- T03 cannot open NRF/UDR readers.

## 25. Acceptance Criteria

T03 is complete when:

1. Every accepted edge has evidence, reason codes, confidence, and validity bounds.
2. Dynamic identifier reuse does not merge completed or unrelated contexts.
3. Timestamp proximity alone never creates an identity edge.
4. Ambiguity and conflicts remain explicit and queryable.
5. Node and edge IDs are deterministic for identical input/configuration.
6. Multi-protocol session correlation supports later attempt segmentation.
7. Capture-boundary uncertainty is represented, not hidden.
8. Sensitive values remain inside the trusted local boundary.
9. Primary-only access is enforced by the constructor/interface.
10. Every topology/domain classification is time-bounded, evidence-backed,
    revisioned and exposes alternatives/confidence without scenario override.
11. Large captures avoid all-pairs behavior and remain resource-bounded.
