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
- Validated T02 result, normalization manifest, revision and artifact
  descriptors.
- Resolved identity-correlation, topology and masking policies.
- Analysis-scoped correlation thresholds and resource limits.

### 3.2 Outputs owned by T03

- Identity nodes and edges.
- Validity intervals.
- Connected-component assignments.
- Ambiguous edge candidates and conflicts.
- UE/session/context lookup indexes.
- Access-scoped registration-state history.
- Time-bounded roaming topology classifications and independent fault-domain
  maps for each resolved UE/access/session context.

T04 consumes the graph but remains responsible for attempt segmentation.

## 4. Python Tool Contract

```python
class BuildIdentityGraphRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    normalization: NormalizeEventsResult
    primary_reader: PrimaryEventReader
    capture: CaptureMetadata
    run_dir: Path
    identity_dir: Path
    indexes_dir: Path
    identity_rules: ResolvedPolicy
    topology_rules: ResolvedPolicy
    masking_policy: ResolvedPolicy
    enabled_capabilities: set[CapabilityName] = Field(default_factory=set)
    policy_versions: dict[str, str]
    config: IdentityGraphConfig


class IdentityGraphConfig(BaseModel):
    supporting_signal_window_seconds: Decimal = Decimal("5")
    supporting_signal_window_frames: int = 200
    context_idle_timeout_seconds: Decimal = Decimal("30")
    context_idle_timeout_frames: int = 2000
    max_candidate_edges_per_observation: int = 20
    auto_link_threshold: Decimal = Decimal("0.90")
    warning_link_threshold: Decimal = Decimal("0.70")
    max_issue_samples_per_code: int = 20
    fsync_outputs: bool = True


class BuildIdentityGraphResult(BaseModel):
    schema_version: Literal["2.0"]
    analysis_id: UUID
    status: Literal["success", "partial", "failed"]
    revision: str
    manifest: ArtifactDescriptor
    artifacts: list[ArtifactDescriptor]
    collections: list[CollectionDescriptor] = Field(default_factory=list)
    observation_count: int
    ue_nodes: int
    pdu_session_nodes: int
    access_context_nodes: int
    sm_context_nodes: int
    pfcp_session_nodes: int
    accepted_edges: int
    ambiguous_edges: int
    conflicts: int
    registration_state_intervals: int
    topology_intervals: int
    fault_domain_maps: int
    warning_counts: dict[str, int]
    elapsed_ms: int
    issues: list[IdentityWarning]
```

The returned result contains counts and artifact descriptors. Downstream code
opens the graph through `IdentityGraphReader`; it does not receive a large
in-memory result object. `IdentityWarning` is a type alias of the shared
`Issue` model and every emitted code must exist in
`harness/config/issue_registry.yaml`.

T03 validates that `normalization.revision`, the T02 manifest revision and the
revision pinned by `primary_reader` are identical. The identity and topology
policies must declare T03/schema compatibility, and their name/version/SHA-256
triples must match `policy_versions`. `masking_policy.payload` validates as the
shared `MaskingPolicy` model.
Bare policy version strings and lazy policy-file loading are forbidden.

`capture.source_sha256` and frame bounds must match the T01/T02 lineage and
frame index. T03 uses those bounds to issue bounded `PrimaryEventReader.by_frame`
reads and groups the returned events into deterministic frame batches.

The request paths are run-directory relative publication roots. The writer
rejects absolute paths, `..`, symlink escapes, aliases between staging and
published paths, and an `identity_dir` outside `run_dir/normalized/identity`.
The in-memory masking key is resolved through `MaskingPolicy.salt_ref`; neither
the key nor clear sensitive identifier values are written to the request,
manifest, logs, issues or general indexes.

Configuration validation requires positive windows/timeouts/caps,
`0 <= warning_link_threshold < auto_link_threshold <= 1`, and a bounded issue
sample count. A capability may affect behavior only when named in the shared
capability registry and declared by the resolved policy; release-milestone or
document-version strings never gate T03 behavior.

### 4.1 Resolved identity-rule payload

`identity_rules.payload` is validated once before event iteration. It is data,
not executable code:

```python
IdentityNodeType = Literal[
    "UE", "PDU_SESSION", "ACCESS_CONTEXT", "SM_CONTEXT", "PFCP_SESSION"
]
IdentityObservationRole = Literal[
    "UE", "SESSION", "ACCESS_CONTEXT", "USER_PLANE", "TRANSACTION"
]


class IdentityRule(BaseModel):
    rule_id: str
    phase: Literal["close", "explicit", "strong", "supporting", "state"]
    left_kinds: set[IdentifierKind]
    right_kinds: set[IdentifierKind]
    relation: str
    strength: Literal["exact", "strong", "supporting"]
    edge_effect: Literal["union_same_type", "associate_nodes", "state_only"]
    base_score: Decimal
    supporting_cap: Decimal = Decimal("0")
    required_equal_facts: list[str] = Field(default_factory=list)
    required_present_facts: list[str] = Field(default_factory=list)
    prohibited_conflicts: list[str] = Field(default_factory=list)
    maximum_seconds: Decimal | None = None
    maximum_frames: int | None = None
    reason_codes: list[str]


class IdentityRulePolicyPayload(BaseModel):
    payload_schema_version: Literal["2.0"]
    rules: list[IdentityRule]
    attribute_sources: dict[str, IdentifierKind]
    identifier_normalizers: dict[IdentifierKind, str]
    identifier_scopes: dict[IdentifierKind, list[str]]
    identifier_node_types: dict[IdentifierKind, IdentityNodeType]
    identifier_roles: dict[IdentifierKind, IdentityObservationRole]
    sensitive_identifier_kinds: set[IdentifierKind]
    allocation_messages: dict[str, list[IdentifierKind]]
    release_messages: dict[str, list[IdentifierKind]]
    registration_state_messages: dict[str, str]
    conflict_predicates: dict[str, list[str]]
    penalties: dict[str, Decimal]
    node_anchor_priority: dict[str, list[IdentifierKind]]
```

Rule facts are allowlisted canonical event/observation fields. Payload
validation rejects duplicate rule IDs, unknown fields, scores outside
`[0, 1]`, supporting rules with `union_same_type`, cross-node-type union rules,
negative penalties, missing scope definitions, regular expressions, code
snippets and arbitrary JSONPath. T03 does not embed a second local rule table.

### 4.2 Roaming topology output

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
    score_terms: list[TopologyEvidenceTerm]
    evidence_ids: list[UUID]
    status: Literal["selected", "alternative", "rejected"]
    reason_codes: list[str]

class FaultDomainMap(BaseModel):
    fault_domain_map_id: UUID
    ue_id: UUID | None
    access_context_id: UUID | None
    session_node_id: UUID | None
    valid_from_frame: int
    valid_to_frame: int | None
    home_plmn: str | None
    serving_plmn: str | None
    home_nf_domain_aliases: set[str]
    visited_nf_domain_aliases: set[str]
    inter_plmn_path_aliases: set[str]
    upf_path_aliases: set[str]
    evidence_ids: list[UUID]
    confidence: Literal["high", "medium", "low", "inconclusive"]
    rules_revision: str

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

### 4.3 Resolved topology-rule payload

```python
class TopologyRule(BaseModel):
    rule_id: str
    topology: Literal["home", "visited_unknown", "home_routed", "local_breakout"]
    required_facts: list[str] = Field(default_factory=list)
    prohibited_facts: list[str] = Field(default_factory=list)
    score_delta: Decimal
    implication: Literal[
        "home", "visited", "home_path", "visited_path", "inter_plmn", "neutral"
    ]
    reason_code: str


class TopologyRulePolicyPayload(BaseModel):
    payload_schema_version: Literal["2.0"]
    base_scores: dict[str, Decimal]
    rules: list[TopologyRule]
    domain_suffix_map: dict[str, Literal["home", "visited", "inter_plmn"]]
    plmn_domain_map: dict[str, list[str]]
    minimum_selection_score: Decimal
    minimum_selection_margin: Decimal
    high_confidence_score: Decimal
    high_confidence_margin: Decimal
    medium_confidence_score: Decimal
```

Domain suffixes are canonical FQDN suffixes matched on DNS-label boundaries.
Payload validation rejects substring patterns, overlapping suffix ownership
without an explicit precedence entry, duplicate rule IDs, noncanonical PLMNs,
unknown facts and scores/deltas that cannot be serialized as canonical
decimals. Selection/confidence thresholds must be in `[0, 1]`, high confidence
must be at least as strict as medium confidence, and margins must be
nonnegative.

### 4.4 Classification rules

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
   alternative is below `topology_rules.payload.minimum_selection_margin`.

Observed identifiers/domains outrank scenario hints. Domain matching uses
configured masked suffix/PLMN mappings, never substring guesses. Every selected
or rejected alternative persists score terms and evidence.

`TopologyEvidenceTerm.normalized_value` is masked or aliased whenever its fact
kind is sensitive under the resolved masking policy.

## 5. Graph Data Model

### 5.1 Identifier observation

```python
class IdentifierObservation(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    observation_id: UUID
    event_id: UUID
    frame: int
    timestamp: Decimal | None
    timestamp_precision: Literal[
        "seconds", "milliseconds", "microseconds", "nanoseconds", "unknown"
    ]
    kind: IdentifierKind
    node_type: IdentityNodeType
    lookup_value: str
    sensitive: bool
    scope_key: str
    field_path: str
    raw_refs: list[SourceRef]
    role: IdentityObservationRole
    confidence: Decimal
    valid_from_frame: int
    valid_to_frame: int | None
    provisional: bool = False
```

`lookup_value` is the canonical normalized value for non-sensitive kinds and
`<kind>:mask_<hmac>` for sensitive kinds. It is sufficient for equality
matching but is not a display alias. Clear values remain in the trusted T02
event/source record and are reachable only through authorized local evidence
lookups. `scope_key` is canonical JSON over the policy-declared uniqueness
scope, hashed when any member is sensitive.

### 5.2 Identity node

```python
class IdentityNode(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    node_id: UUID
    node_type: IdentityNodeType
    first_frame: int
    last_frame: int
    first_timestamp: Decimal | None
    last_timestamp: Decimal | None
    provisional: bool = False
    incomplete_history: bool = False
    observation_ids: list[UUID]
    accepted_edge_ids: list[UUID]
    association_edge_ids: list[UUID]
    display_alias: str | None = None
```

### 5.3 Edge and conflict

```python
class IdentityEdge(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    edge_id: UUID
    left_observation_id: UUID
    right_observation_id: UUID
    left_node_type: IdentityNodeType
    right_node_type: IdentityNodeType
    left_node_id: UUID | None = None
    right_node_id: UUID | None = None
    relation: str
    strength: Literal["exact", "strong", "supporting"]
    edge_effect: Literal["union_same_type", "associate_nodes"]
    confidence: Decimal
    score_terms: list[ScoreTerm]
    rule_id: str
    reason_codes: list[str]
    supporting_event_ids: list[UUID]
    valid_from_frame: int
    valid_to_frame: int | None
    decision: Literal["accepted", "accepted_with_warning", "candidate", "rejected"]
    conflict_ids: list[UUID] = Field(default_factory=list)


class IdentityConflict(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    conflict_id: UUID
    code: str
    observation_ids: list[UUID]
    competing_node_ids: list[UUID]
    frames: list[int]
    resolution: Literal["split", "prefer_explicit", "unresolved"]
    reason_codes: list[str]
    evidence_event_ids: list[UUID]
```

Only accepted `union_same_type` edges enter a typed union-find. An
`associate_nodes` edge links resulting nodes, for example UE to access context,
access context to PDU session, SM context to PDU session, or PDU session to
PFCP session; it never collapses those node types into one component.
Supporting evidence cannot create an edge or change `edge_effect`; it can only
add bounded score terms to a candidate already qualified by an exact or strong
rule. Candidate/rejected edges never enter union-find or node associations.

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
    schema_version: Literal["2.0"] = "2.0"
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
    schema_version: Literal["2.0"] = "2.0"
    state_id: UUID
    ue_id: UUID | None
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

- Normalize identifiers before matching but preserve source values through
  `raw_refs` and event references.
- Apply the resolved `MaskingPolicy` through the shared masking helper. Do not
  implement a T03-only hash or alias scheme.
- Sensitive lookup values use keyed HMAC with a type prefix and the resolved
  run/policy salt. General indexes never contain clear SUPI, SUCI, GPSI, PEI,
  GUTI, UE IP or policy-declared sensitive values.
- Stable report/model aliases use deterministic analysis-scoped tokens such as
  `UE-1`; alias numbering follows node sort order and cannot be reversed
  without the local mapping.
- Never write clear sensitive identifiers to logs, metrics, issues, manifests,
  descriptors, filenames or revision inputs.
- A masking-key resolution failure is fatal. T03 must not fall back to an
  unkeyed hash, clear value, process-global salt or cross-run stable token.

### 7.1 Observation extraction algorithm

T03 reads events through the parent-revision-pinned `PrimaryEventReader` in
ascending `(frame, event_id)` order and processes all events for one frame as
a batch. Every returned event must have `partition="primary"` and must not be
quarantined; any reader result that violates this is `RUN_ACCESS_BOUNDARY` and
fails publication.

`iter_primary_frame_batches()` calls
`by_frame(capture.first_frame, capture.last_frame)`, requires nondecreasing
frames from the index-backed
reader, sorts only the current frame by event ID, and yields that bounded
batch. Out-of-range frames, duplicate event IDs or a decreasing frame are
integrity failures; T03 never sorts the whole capture in memory.

For each event:

1. Validate `analysis_id`, schema version, parent revision, frame, timestamp
   and `raw_refs` checksums against the T02 manifest.
2. Enumerate the fixed `EventIdentifiers` fields in schema order, followed by
   allowlisted protocol attribute paths declared by `identity_rules`.
3. Ignore absent values. An invalid optional value emits
   `T03_IDENTIFIER_PARSE_FAILED`, leaves the source event available, and does
   not create an observation for that field.
4. Normalize the value with the policy-named normalizer. Normalizers accept
   typed values only and cover PLMN, FQDN/DNN, URI reference, integer/hex
   identifiers, IP address, GUAMI/TAI/CGI, SEID, F-TEID and access tunnel IDs.
5. Determine `node_type`, role, sensitivity and uniqueness scope from the
   policy. Missing required scope members produce a provisional observation;
   they do not widen the scope to global.
6. Build `lookup_value` and `scope_key` through the shared masking/canonical
   serialization helpers.
7. Mint the observation ID:

   ```text
   UUIDv5(
     analysis_id,
     t02_revision + event_id + kind + field_path + normalized_lookup_value
     + scope_key + semantic_ordinal + identity_rules.sha256
   )
   ```

8. Deduplicate identical observations from duplicate decoder paths within one
   event. Same identity with a different payload is an integrity failure, not
   last-write-wins.
9. Add the observation to staged output and active scoped indexes. Source
   values are never copied from the event into persisted observation fields.

Protocol-specific extraction uses these minimum facts:

- NAS: subscriber aliases, GUTI components, PDU session ID, PTI, access type,
  registration state messages, DNN, S-NSSAI and serving/home PLMN hints.
- NGAP: AMF/RAN UE IDs, gNB/N3IWF/TNGF anchor, N2 association, GUAMI, TAI,
  CGI, access family, PDU session resource IDs, old/new context mappings and
  transport tunnel endpoints.
- HTTP/2/SBI: correlation ID, HTTP/2 key, SM-context reference, subscriber
  aliases, PDU session ID, charging/session IDs, NF type/domain, API/service,
  DNN, S-NSSAI and explicit SBI-to-PFCP correlation fields.
- PFCP: endpoint pair, sequence, CP/UP SEID, F-SEID, UE IP, DNN, S-NSSAI,
  PDR/FAR/QER/URR/BAR IDs, F-TEID, outer-header creation and explicit
  create/update/remove relationships.

T03 consumes only normalized canonical fields and allowlisted attributes. It
does not reopen T01 decoder trees to search for identifiers omitted by T02.

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

### 8.4 Candidate generation

Candidate generation is index-driven and deterministic:

1. Query exact active indexes by `(kind, lookup_value, scope_key)` and by
   explicit relation keys such as response-to event, old/new context mapping,
   SM-context reference or CP/UP SEID pair.
2. Query only policy-declared strong join indexes, for example
   `(access_context, pdu_session_id, pti)`, `(sm_context, pdu_session_id)` or
   `(endpoint_pair, seid)`. No rule may request an unbounded scan.
3. Reject candidates whose validity intervals cannot overlap or whose
   access-family/node-type scope violates section 6.
4. Evaluate exact and strong rules in ascending `rule_id`; create at most one
   candidate per canonical
   `(left_observation_id, right_observation_id, relation, rule_id)` key, with
   the lower observation UUID always on the left for symmetric rules.
5. Add supporting terms only after a rule has qualified the pair. Timestamp
   proximity is eligible only when both timestamps are valid; otherwise the
   rule's frame bound or `supporting_signal_window_frames` is used.
6. Sort non-exact candidates by base score descending, exact-signal count
   descending, strong-signal count descending, absolute frame distance
   ascending, rule ID and candidate UUID. Keep the first
   `max_candidate_edges_per_observation` per observation.
7. Never discard an explicit old/new mapping or direct transaction link. If
   explicit candidates alone exceed the cap, emit
   `T03_CANDIDATE_LIMIT_EXCEEDED` and fail publication because silently
   dropping explicit identity evidence would corrupt the graph. Truncating
   only weaker candidates emits `T03_CANDIDATE_LIMIT_TRUNCATED` and marks the
   result `partial`.

The active indexes are partitioned by node type, identifier kind, scope and
validity bucket. Historical closed intervals remain queryable from staged
storage but are removed from active memory.

## 9. Confidence Scoring

Each rule has versioned weights. The implementation computes:

```text
raw_score = rule.base_score
          + sum(qualified_strong_terms)
          + min(sum(supporting_terms), rule.supporting_cap)
          - sum(conflict_and_uncertainty_penalties)
confidence = clamp(raw_score, 0, 1)
```

Every addition or subtraction is persisted as the shared canonical-decimal
`ScoreTerm`. Its `rationale_code` identifies the rule/term and its
`evidence_ids` resolve to T03-minted `identity_link_signal` evidence records
containing the supporting primary event IDs/refs. Runtime floats may be used
internally only if conversion to `Decimal` follows the canonical policy before
comparison, persistence or revision hashing. Candidate sorting never uses an
unpersisted float. Confidence is evidence quality, not statistical probability.

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

For equal confidence, decisions are ordered by strength (`exact`, then
`strong`), lower first frame, rule ID and edge UUID. Warning-band acceptance
emits `T03_WARNING_BAND_LINK`; the issue carries only event/evidence IDs and
reason codes, never lookup values. The warning does not by itself make the
whole T03 result partial because no evidence was discarded.

## 10. Validity Intervals

Every dynamic identifier has a validity interval derived from:

- First observation.
- Explicit allocation/creation.
- Explicit release/deregistration/deletion.
- Handover/context transfer remapping.
- Last observation plus bounded idle timeout when no release exists.
- Capture start/end uncertainty.

An identifier observed after its prior validity interval creates a new
observation/node candidate. Reuse is expected and must not bridge completed
contexts. A timestamp is never used to reverse frame order. When both
timestamps exist, the timeout closes at the earlier of the configured
seconds/frame limits; otherwise the frame limit applies. Explicit release
always outranks idle expiry.

Explicit release closes the relevant context but does not erase historical edges.

Events sharing a frame are handled as one batch. T03 extracts all observations
first, evaluates explicit transfer/mapping rules second, evaluates allocation
and association rules third, and applies release/close rules last. This allows
an explicit same-frame handover mapping to connect old and new contexts before
the old context closes. Within each phase, rules run by `rule_id` and events by
`event_id`.

Capture-start observations with no visible allocation are
`provisional=true,incomplete_history=true`. At capture end, active intervals
remain `valid_to_frame=None` and their nodes are incomplete; T03 must not
invent a release at the last frame.

## 11. Correlation Algorithm

1. Validate the request, T02 lineage, policies, masking context and output
   paths.
2. Return the existing result only when the complete T03 revision inputs match;
   otherwise allocate a sibling publication target without overwriting a
   valid graph.
3. Create `staging/T03-<uuid>/` and staged writers/index builders.
4. Read primary events by frame batch and extract typed observations using
   section 7.1.
5. Apply explicit close/transfer/allocation/state phases and maintain active
   validity indexes.
6. Generate exact and strong candidates using section 8.4.
7. Add bounded supporting score terms, evaluate thresholds and persist every
   candidate decision.
8. Detect hard conflicts before applying any accepted edge.
9. Apply accepted same-type unions to one union-find per node type; stage
   accepted cross-type associations separately.
10. Expire dynamic identifiers and registration states on explicit release or
    timeout.
11. Materialize typed nodes from union-find roots, then resolve association
    edge observation endpoints to node IDs.
12. Derive access registration-state intervals, topology intervals and fault
    domain maps from the finalized typed graph.
13. Build reader indexes, descriptors, counters, T03 revision and manifest.
14. Run a streaming validation pass over every staged file and index.
15. Flush/fsync, publish data and indexes, and publish
    `identity_graph_manifest.json` last.

Reference runner control flow:

```python
def build_identity_graph(req: BuildIdentityGraphRequest) -> BuildIdentityGraphResult:
    started = clock.now()
    parent = validate_t02_lineage(req.normalization, req.primary_reader)
    policies = validate_t03_policies(req)
    masking = resolve_masking_context(validate_masking_policy(req.masking_policy))
    validate_output_paths(req.run_dir, req.identity_dir, req.indexes_dir)
    revision = build_t03_revision(req, parent, policies)

    existing = inspect_existing_graph(req.run_dir, req.analysis_id)
    if existing and existing.revision == revision:
        return result_from_manifest(existing.manifest)
    publication = resolve_sibling_publication(existing, req)

    staging = make_unique_staging_dir(req.run_dir / "staging", prefix="T03-")
    writers = open_graph_writers(staging, publication.relative_layout)
    indexes = open_identity_index_builders(staging)
    state = GraphBuildState(config=req.config, policies=policies, masking=masking,
                            revision=revision)
    counters = IdentityGraphCounters()
    issues: list[Issue] = []

    for frame_events in iter_primary_frame_batches(req.primary_reader, req.capture):
        validate_primary_batch(frame_events, parent)
        observations = extract_observations(frame_events, state, issues)
        writers.observations.write_all(observations)
        state.index_observations(observations)
        state.apply_frame_phases(frame_events, observations, writers, issues)
        state.expire_before_next_frame(frame_events[-1].frame, writers, issues)

    state.close_capture_boundary(req.capture, writers)
    nodes = materialize_typed_nodes(state)
    associations = resolve_association_endpoints(state, nodes)
    registration_states = materialize_registration_states(state, nodes)
    topology, domain_maps = classify_topology(nodes, associations, policies.topology,
                                              revision)
    writers.write_final(nodes, associations, registration_states, topology, domain_maps)
    indexes.build(nodes, associations, registration_states, topology, domain_maps)

    close_flush_fsync(writers, indexes, enabled=req.config.fsync_outputs)
    counters = validate_staged_graph(staging, state, indexes)
    descriptors = build_t03_descriptors(staging, counters, revision, parent)
    manifest = build_t03_manifest(req, parent, policies, descriptors, counters,
                                  issues, revision, started)
    validate_t03_manifest(manifest, descriptors, counters)
    publish_staged_graph(staging, publication, manifest_last=True)
    return result_from_manifest(manifest)
```

`iter_frame_batches()` is a bounded index-backed reader operation; it is not a
generic partition selector. The reader must not expose NRF/UDR paths, indexes
or event IDs. During frame processing, edge decisions go to an internal staged
decision spool. Public `edges.jsonl`/`ambiguous_edges.jsonl` records are written
after node materialization so accepted edges carry resolved node IDs.
Ambiguous and rejected edges never mutate union-find.

## 12. Deterministic Node IDs

Observation, edge, conflict, node, topology and domain-map IDs are deterministic.
Node IDs use UUIDv5 derived from:

```text
analysis_id + t02_revision + identity_rules.sha256 + node_type
+ minimum stable anchor observation key + first_frame
```

The anchor observation is selected from the policy-declared kind priority,
then by frame, lookup hash and observation UUID. Supporting-only observations
cannot become anchors. Adding a later supporting observation therefore does
not change an existing node ID. Edge IDs use ordered observation IDs, relation,
rule ID and validity start. Conflict IDs use conflict code plus sorted
observation/edge IDs. Topology/domain-map IDs use the typed node IDs, interval
start and topology-policy checksum.

When a previous merge decision changes because configuration/rules change,
the graph is a new revision with different IDs/manifest where the rule checksum
is an identity input; the previous graph is never rewritten.

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

- Evaluate policy-declared hard-conflict predicates before union. A proposed
  union that would introduce two incompatible active explicit identifiers is
  rejected and recorded; T03 never unions first and tries to repair later.
- Prefer an accepted explicit edge over a strong inferred edge only when the
  explicit edge itself is conflict-free and validity-compatible.
- If a conflict is between already accepted inferred edges, remove the lowest
  ordered edge by confidence, strength, later first frame, rule ID and edge ID,
  rebuild only the affected typed component, and record `resolution="split"`.
- Never remove a direct explicit mapping merely to preserve a supporting or
  inferred link. Competing explicit mappings remain separate and
  `resolution="unresolved"` unless a policy rule gives a deterministic
  precedence basis.
- Retain every rejected/removed edge in `ambiguous_edges.jsonl` with conflict
  IDs and reason codes. Emit `T03_HARD_IDENTITY_CONFLICT`; conflicts do not
  make publication fail when the post-resolution graph satisfies invariants.
- A graph that still contains a prohibited component after deterministic
  resolution is a fatal invariant violation and no manifest is published.

Conflict resolution is local to one typed component and deterministic for the
same ordered edge set. It must not use wall-clock order, Python set iteration,
thread completion order or mutable global lists.

## 14. Capture Boundary Handling

- Capture starts mid-call: create provisional nodes with `incomplete_history=true`.
- Capture ends before release: leave validity open-ended and mark incomplete.
- Missing NAS identity: access/session nodes may exist without a resolved UE subscriber node.
- Encrypted NAS: use visible NGAP/SBI/PFCP evidence without inventing subscriber identity.

### 14.1 Access registration-state derivation

Registration states are derived only from policy-declared NAS/NGAP state
messages attached to a finalized `ACCESS_CONTEXT` node:

1. Start with `unknown` at the first access-context frame when no earlier state
   is visible.
2. A registration request opens `registering` for that access family/context.
3. A successful registration accept/complete transition opens `registered` as
   defined by the resolved state rule; a reject returns to `deregistered` only
   when the message semantics explicitly end registration.
4. Suspend/resume transitions affect only their scoped access context.
5. Deregistration or access-context release closes the current interval and
   opens `deregistered`; a UE-wide message may close multiple contexts only
   when its decoded scope explicitly says so.
6. Consecutive identical states are coalesced by extending evidence IDs and
   the validity interval. Conflicting same-frame states produce `unknown` plus
   `T03_REGISTRATION_STATE_CONFLICT` rather than an arbitrary last value.

The state record ID is UUIDv5 over analysis ID, access-context node ID, state,
valid-from frame and identity-policy checksum. State history never merges
gNB, N3IWF and TNGF contexts.

### 14.2 Topology and fault-domain algorithm

T03 derives topology after graph finalization so facts are evaluated against
time-bounded UE/access/session associations:

1. Build topology fact intervals from SUCI/trusted home PLMN, TAI/GUAMI serving
   PLMN, NF/domain aliases, SBI routing domains, DNN/S-NSSAI and observed
   UPF/N9/inter-PLMN paths. Scenario hints are not inputs.
2. Mint evidence records through the shared evidence registry for each cited
   topology fact using the T03 revision scope. Evidence records contain source
   event IDs/refs and masked observed values; T03 never invents source frames.
3. Split an interval whenever home PLMN, serving PLMN, access context, session
   association, domain ownership or path mapping changes.
4. Initialize each non-inconclusive alternative from the policy base score,
   apply matching rules in `rule_id` order, clamp to `[0, 1]`, and persist every
   term. Sort by score descending then fixed topology order `home`,
   `visited_unknown`, `home_routed`, `local_breakout`.
5. Select `inconclusive` when required home/serving facts are missing, the top
   score is below `minimum_selection_score`, or the top-minus-second score is
   below `minimum_selection_margin`. Otherwise select the highest alternative.
6. Set confidence `high` when score and margin meet both high thresholds,
   `medium` when the selected score meets `medium_confidence_score`, `low` for
   other selected outcomes, and `inconclusive` when no topology is selected.
7. Build `FaultDomainMap` independently from observed entity/path ownership.
   Unknown aliases remain unmapped; topology selection must not populate a
   domain merely by implication.
8. Coalesce adjacent intervals only when selected topology, ordered
   alternatives, scores, confidence, node associations and fault-domain map
   are byte-identical except for interval bounds.

The evidence registry helper must support revision-scoped staged minting so
the graph and its evidence records publish atomically. A divergent duplicate
evidence payload is `RUN_EVIDENCE_INTEGRITY` and fails publication. Missing or
conflicting roaming facts emit sampled `T03_TOPOLOGY_INCONCLUSIVE` issues but
do not make the graph partial because uncertainty is the represented result.
T03 registers and uses the semantic evidence record types
`identity_link_signal` and `topology_fact`; it does not mint detector failure
evidence or reuse an unregistered free-form record type.

## 15. Output Layout and Indexes

```text
normalized/identity/
  observations.jsonl
  nodes.jsonl
  edges.jsonl
  ambiguous_edges.jsonl
  conflicts.jsonl
  access_registration_states.jsonl
  roaming_topology.jsonl
  fault_domain_maps.jsonl
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
staging/T03-<uuid>/
```

All JSONL files are published even when empty. `edges.jsonl` contains only
accepted and accepted-with-warning edges. `ambiguous_edges.jsonl` contains
candidate and rejected edges, including edges removed during conflict splits.
Records are ordered by their primary UUID after deterministic materialization;
observations retain `(frame, event_id, observation_id)` order for streaming.

### 15.1 Index record contracts

```python
class IdentifierIndexEntry(BaseModel):
    revision: str
    identifier_kind: IdentifierKind
    lookup_value: str
    scope_key: str
    node_ids: list[UUID]
    observation_ids: list[UUID]
    valid_from_frame: int
    valid_to_frame: int | None


class EventIdentityIndexEntry(BaseModel):
    revision: str
    event_id: UUID
    observation_ids: list[UUID]
    node_ids: list[UUID]
    accepted_edge_ids: list[UUID]


class ContextIndexEntry(BaseModel):
    revision: str
    access_context_id: UUID
    ue_id: UUID | None
    key: AccessContextKey
    session_node_ids: list[UUID]
    valid_from_frame: int
    valid_to_frame: int | None


class SessionIndexEntry(BaseModel):
    revision: str
    session_node_id: UUID
    ue_id: UUID | None
    access_context_ids: list[UUID]
    pdu_session_id: int | None
    sm_context_node_ids: list[UUID]
    pfcp_session_node_ids: list[UUID]
    valid_from_frame: int
    valid_to_frame: int | None
```

The UE index maps analysis-scoped display aliases and sensitive HMAC lookup
values to UE nodes. The registration, topology and fault-domain indexes map
their node/interval keys to byte offsets in the corresponding identity JSONL
files. Every index entry includes the T03 revision and references only records
in the same generation. Lists declared as sets are sorted by UUID; duplicate
entries are invalid. String-valued sets in topology/domain-map records
serialize as lexicographically sorted arrays.

Indexes must support bounded lookup by event, masked identity, access-family /
anchor / context tuple, access-scoped registration state, session ID within UE
and access leg, SM context, SEID, UE IP and tunnel identity. General callers
provide an already masked lookup value. A trusted local helper may accept a
clear value only by applying the same resolved masking policy before index
access; clear query values are never logged or persisted.

### 15.2 Reader capability

```python
class IdentityGraphReader(Protocol):
    @property
    def revision(self) -> str: ...
    def nodes_for_event(self, event_id: UUID) -> list[IdentityNode]: ...
    def ue_by_lookup(self, kind: IdentifierKind, masked_value: str) -> list[IdentityNode]: ...
    def access_context_at(self, key: AccessContextKey, frame: int) -> IdentityNode | None: ...
    def sessions_for_context(self, access_context_id: UUID, frame: int) -> list[IdentityNode]: ...
    def registration_state_at(self, access_context_id: UUID, frame: int) -> AccessRegistrationState: ...
    def topology_at(self, node_id: UUID, frame: int) -> RoamingTopologyInterval | None: ...
    def fault_domains_at(self, node_id: UUID, frame: int) -> FaultDomainMap | None: ...
```

The storage factory constructs this reader only after manifest, descriptor,
checksum and revision validation. It has no method for opening event
partitions, decoder files or a sibling graph revision. T04 receives this
reader and a separate `PrimaryEventReader`; it cannot broaden either one.

### 15.3 Artifact descriptor expectations

| Relative path | Artifact type | Media type | Record count |
| --- | --- | --- | --- |
| `normalized/identity/observations.jsonl` | `identity_observations` | `application/x-ndjson` | `observation_count` |
| `normalized/identity/nodes.jsonl` | `identity_nodes` | `application/x-ndjson` | total node count |
| `normalized/identity/edges.jsonl` | `identity_edges` | `application/x-ndjson` | `accepted_edges` |
| `normalized/identity/ambiguous_edges.jsonl` | `identity_edge_candidates` | `application/x-ndjson` | `ambiguous_edges` |
| `normalized/identity/conflicts.jsonl` | `identity_conflicts` | `application/x-ndjson` | `conflicts` |
| `normalized/identity/access_registration_states.jsonl` | `access_registration_states` | `application/x-ndjson` | `registration_state_intervals` |
| `normalized/identity/roaming_topology.jsonl` | `roaming_topology_intervals` | `application/x-ndjson` | `topology_intervals` |
| `normalized/identity/fault_domain_maps.jsonl` | `fault_domain_maps` | `application/x-ndjson` | `fault_domain_maps` |
| `normalized/identity/identity_graph_manifest.json` | `identity_graph_manifest` | `application/json` | `1` |
| `indexes/ue_index.jsonl` | `identity_index` | `application/x-ndjson` | index entries |
| `indexes/session_index.jsonl` | `identity_index` | `application/x-ndjson` | index entries |
| `indexes/context_index.jsonl` | `identity_index` | `application/x-ndjson` | index entries |
| `indexes/access_registration_state_index.jsonl` | `identity_index` | `application/x-ndjson` | index entries |
| `indexes/identifier_index.jsonl` | `identity_index` | `application/x-ndjson` | index entries |
| `indexes/event_identity_index.jsonl` | `identity_index` | `application/x-ndjson` | index entries |
| `indexes/roaming_topology_index.jsonl` | `identity_index` | `application/x-ndjson` | index entries |
| `indexes/fault_domain_index.jsonl` | `identity_index` | `application/x-ndjson` | index entries |

Each shared `ArtifactDescriptor` records path, artifact/media/schema type,
SHA-256, byte size, verifiable record count, producing stage `T03`, T02
manifest SHA-256 as `parent_source_sha256`, and T03 revision. The run-store
artifact registrar incorporates these descriptors into the canonical artifact
index; T03 does not overwrite a previously published artifact-index generation
directly.

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

Required shape:

```json
{
  "schema_version": "2.0",
  "tool": "T03",
  "analysis_id": "00000000-0000-0000-0000-000000000000",
  "status": "success",
  "revision": "sha256:...",
  "parent": {
    "tool": "T02",
    "revision": "sha256:...",
    "manifest_sha256": "..."
  },
  "policies": {
    "identity_rules": {"name": "...", "version": "...", "sha256": "..."},
    "topology_rules": {"name": "...", "version": "...", "sha256": "..."},
    "masking_policy": {"version": "...", "sha256": "..."}
  },
  "config_sha256": "...",
  "counts": {
    "observation_count": 0,
    "nodes_by_type": {},
    "accepted_edges": 0,
    "ambiguous_edges": 0,
    "conflicts": 0,
    "registration_state_intervals": 0,
    "topology_intervals": 0,
    "fault_domain_maps": 0,
    "warning_counts": {},
    "provisional_nodes": 0,
    "incomplete_nodes": 0
  },
  "confidence_histogram": {},
  "topology_counts": {},
  "topology_confidence_counts": {},
  "artifacts": [],
  "collections": [],
  "issues": [],
  "timing": {
    "started_at": "2026-06-10T00:00:00Z",
    "ended_at": "2026-06-10T00:00:00Z",
    "elapsed_ms": 0,
    "peak_rss_bytes": null
  }
}
```

Manifest issues are sampled per code; `warning_counts` retains full counts.
Generated timestamps and elapsed measurements are not revision inputs. Scores,
thresholds, timestamps and policy numeric fields use canonical decimal-string
serialization.

### 16.1 Revision inputs

T03 mints its own `RevisionEnvelope` before record IDs that use the revision
scope are finalized. Inputs are:

- T02 revision and normalization-manifest SHA-256.
- Primary-reader schema/revision identity.
- Validated capture source checksum and frame/timestamp bounds.
- Identity, topology and masking policy name/version/SHA-256 triples.
- Canonical T03 configuration hash.
- T03 tool version and graph schema version.
- Enabled capability set when any capability changes T03 behavior.

Output descriptors are stamped with the resulting revision and recorded in the
manifest; they do not recursively enter their own revision digest. Same inputs
produce the same revision and byte-identical deterministic records on every
supported machine.

## 17. Idempotency and Atomicity

- Same T02 revision/checksum, policies, configuration and tool version produce
  identical observations, edges, nodes, indexes and revision.
- Write only under `staging/T03-<uuid>/`; never stage beneath a published
  identity directory.
- Close, flush and optionally fsync data files before indexes; validate all
  checksums/counts before promotion.
- Publish graph data first, indexes second, evidence-registry additions through
  the same run-store transaction, and the graph manifest last.
- A crash before manifest publication leaves an unreferenced staging tree that
  recovery removes. A crash after manifest publication must find all declared
  descriptors valid or quarantine the run for integrity failure.
- Failed runs leave no valid graph manifest and never modify a prior valid
  revision.
- Existing graph revisions are immutable. Identical re-entry returns the
  existing result; changed inputs allocate a sibling generation.

### 17.1 Writer and publication invariants

Maintain counters while writing, then prove them with a streaming validation
pass before publication:

```python
class IdentityGraphCounters(BaseModel):
    observation_count: int = 0
    observations_by_kind: dict[str, int] = Field(default_factory=dict)
    nodes_by_type: dict[str, int] = Field(default_factory=dict)
    accepted_edges: int = 0
    ambiguous_edges: int = 0
    conflicts: int = 0
    registration_state_intervals: int = 0
    topology_intervals: int = 0
    fault_domain_maps: int = 0
    provisional_nodes: int = 0
    incomplete_nodes: int = 0
    warning_counts: dict[str, int] = Field(default_factory=dict)
```

- Every observation ID, edge ID, conflict ID, node ID, state ID, topology ID
  and fault-domain-map ID is unique in the T03 revision.
- Every observation references one existing primary T02 event and valid
  parent-checksummed `raw_refs`.
- Every edge endpoint references an observation; every accepted association
  resolves to existing typed node endpoints after materialization.
- `rows(edges.jsonl) == accepted_edges` and every row decision is accepted or
  accepted-with-warning.
- `rows(ambiguous_edges.jsonl) == ambiguous_edges` and every row decision is
  candidate or rejected.
- Every same-type union edge connects equal node types. No supporting-only,
  candidate or rejected edge appears in union-find membership.
- Each observation belongs to exactly one node of its declared node type;
  association edges do not change that membership.
- No finalized component violates subscriber, access-family, session or PFCP
  conflict predicates.
- Every state/topology/domain interval has `valid_to_frame=None` or
  `valid_to_frame >= valid_from_frame`; intervals for the same scoped key do
  not overlap unless the schema explicitly represents alternatives.
- Every index entry resolves to an existing same-revision record and valid byte
  offset. Sensitive identifier indexes contain only correctly prefixed HMAC
  lookup values.
- Manifest counts equal validated file/index counts, not merely in-memory
  counters. Descriptor SHA-256, byte size and record count match staged bytes.
- Every T03 evidence ID resolves through the staged evidence index to the same
  source events/refs and T03 revision scope.

Empty outputs and indexes still receive descriptors and participate in these
checks.

## 18. Failure Semantics

- Invalid/missing T02 manifest: fatal.
- Parent revision/schema/checksum mismatch: fatal.
- Invalid/incompatible policy or unresolved masking key: fatal.
- One event with malformed identifier: warning, retain other observations.
- Weak candidate explosion beyond configured cap: deterministically truncate,
  warn, and mark partial; explicit-candidate overflow is fatal.
- Hard graph invariant violation after resolution: fatal publication failure.
- Ambiguity/conflict: not fatal when represented and post-resolution invariants
  hold; it does not alone make the result partial.
- Missing/conflicting roaming facts: persist `inconclusive` alternatives and
  an `UNKNOWN` domain map; do not fail identity graph publication.
- Recoverable identifier parse loss, unsupported optional canonical attributes
  or weak-candidate truncation make status `partial`.
- Warning-band accepted links, provisional capture-boundary nodes and
  represented topology uncertainty remain `success` unless evidence was lost.
- Disk/checksum/index publication failure: fatal.

`failed` has no published T03 manifest. `partial` always publishes a valid,
queryable graph and lists the exact information-loss issue codes. The runner
does not return a synthetic failed result after a fatal pre-publication error;
the orchestrator records the failed invocation in the run manifest.

## 19. Performance and Resource Requirements

- O(events + scoped candidate edges), not all-pairs O(n^2).
- Maintain active indexes partitioned by identifier type/scope.
- Expire closed contexts to bound candidate search.
- Stream persisted observations and edge decisions; do not retain full source
  events or all historical candidates in memory.
- Materialize union-find parents, active scope indexes and the minimum node
  summaries in memory. Spill closed observation/node mappings to staged sorted
  runs when a configured storage implementation threshold is reached.
- External merge-sort spill files use canonical keys and are deleted after
  final index publication. Spill/no-spill execution must produce identical
  bytes.
- Metrics: events/sec, observations/sec, candidate edges, accepted/ambiguous
  edges, active contexts, active observations, spill bytes/runs, maximum
  candidate fanout and peak RSS.
- Large multi-UE captures must remain bounded by active contexts, not total historical events.

## 20. Security Requirements

- T03 only receives `PrimaryEventReader`.
- The runner verifies every input event is primary and excludes generic event
  store, NRF reader, UDR reader and arbitrary selector dependencies from the
  T03 constructor.
- Clear sensitive identifiers never appear in logs, general indexes,
  descriptors, manifests, revisions, issues, topology terms or fault-domain
  aliases.
- Hash keys come from run-local secret material resolved by reference and are
  not persisted with reports or graph artifacts.
- Treat identifier strings and URIs as untrusted data.
- Bound normalized identifier, URI/FQDN and scope-key lengths before hashing;
  reject control characters and invalid canonical encodings.
- Reject path escape, symlink escape, corrupted graph revision inputs and
  cross-analysis/cross-revision index records.
- Evidence-registry minting is restricted to primary source events in this
  tool. T03 cannot use topology processing to cite dependency-partition
  evidence.

## 21. Observability

Structured logs include:

- `analysis_id`, `tool=T03`, `event_id`, `observation_kind`.
- `rule_id`, `edge_strength`, `confidence_bucket`, `decision`.
- `conflict_code`, counts, and duration without sensitive values.

Metrics include edge-rule hit counts, ambiguity rate, conflict rate, provisional-node count, and graph build latency.

The minimum T03 issue-code namespace is:

- `T03_IDENTIFIER_PARSE_FAILED`
- `T03_UNSUPPORTED_IDENTIFIER_SHAPE`
- `T03_CANDIDATE_LIMIT_TRUNCATED`
- `T03_CANDIDATE_LIMIT_EXCEEDED`
- `T03_WARNING_BAND_LINK`
- `T03_HARD_IDENTITY_CONFLICT`
- `T03_REGISTRATION_STATE_CONFLICT`
- `T03_TOPOLOGY_INCONCLUSIVE`
- `T03_GRAPH_INVARIANT_FAILED`

Access and evidence-integrity violations use shared `RUN_ACCESS_BOUNDARY` and
`RUN_EVIDENCE_INTEGRITY`. Registry validation fixes owner, allowed severity,
message template, remediation and aggregation behavior. Logs may include
event/observation/edge IDs and issue codes, but never lookup values or scope
keys.

## 22. Proposed Python Code Structure

```text
V2/harness/analysis/
  identity_graph.py          orchestration and graph revision
  observations.py           typed extraction
  identity_rules.py         resolved-rule validation and evaluation
  identity_scoring.py       confidence calculation
  validity.py               allocation/release/expiry intervals
  conflicts.py              invariant and split handling
  union_find.py             accepted component construction
  registration_state.py     access-scoped state intervals
  session_linker.py         SM/PFCP/session-specific rules
  roaming_topology.py       PLMN/domain/path classification
  fault_domains.py          independent entity/path domain maps
V2/harness/storage/
  identity_store.py         staged writers, descriptors, manifest-last publish
  identity_reader.py        revision-pinned bounded reader
  identifier_index.py       scoped active and persisted indexes
  identity_spill.py         deterministic external-sort spill support
V2/harness/models/
  identity.py
  topology.py
V2/harness/evidence/
  registry.py               shared revision-scoped evidence minting
```

## 23. Implementation Sequence

1. Define graph, topology, manifest and index schemas using shared models.
2. Register T03 issue codes and validate resolved policy payloads.
3. Implement parent-lineage, path, masking and reader-capability validation.
4. Implement deterministic observation extraction and scoped active indexes.
5. Implement rule-driven candidates, scoring, threshold decisions and caps.
6. Implement typed union-find, cross-type associations and conflict handling.
7. Implement validity expiry, access registration state and identifier reuse.
8. Materialize deterministic nodes/aliases and persisted reader indexes.
9. Implement topology alternatives, fault-domain maps and evidence minting.
10. Add descriptors, revision, manifest, invariant validation and atomic
    publication.
11. Add spill support only after no-spill correctness/golden fixtures pass.

## 24. Tests

### 24.1 Unit tests

- Identifier normalization and scope.
- Observation ID and deduplication determinism.
- Resolved policy rejection for duplicate rules, unknown facts, bad scopes,
  executable payloads and incompatible checksums.
- Exact, strong, supporting rule gating.
- Confidence thresholds and deterministic ties.
- Band boundaries: exactly `auto_link_threshold` auto-links, just below it
  warns, exactly `warning_link_threshold` warns, just below it stays candidate;
  config validation rejects `auto_link_threshold <= warning_link_threshold`.
- Supporting evidence cannot create or union an edge.
- Same-type unions and cross-type associations remain distinct.
- Validity open/close/expiry.
- Same-frame transfer/allocation/release phase ordering.
- UUID stability.
- Sensitive hashing, scope hashing, key rotation and no clear-value leakage.
- Conflict detection and component split.
- Weak/explicit candidate cap behavior and stable truncation order.
- Registration-state coalescing and same-frame conflict behavior.
- Home, visited-unknown, home-routed, local-breakout and inconclusive topology
  classification with deterministic alternatives.
- Fault-domain maps remain independent from topology selection.
- Topology score/margin/confidence boundaries and DNS-label suffix matching.
- Decimal serialization, revision hashing and descriptor validation.

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
- Identical rerun returns the existing revision; policy/config change creates a
  sibling revision and preserves the first graph.
- Crash before manifest publication leaves no readable graph; recovery removes
  staging without touching the prior revision.
- T03 topology evidence resolves through T18 in `provider=none` mode.
- Spill and no-spill builds produce byte-identical graph/index artifacts.

### 24.3 Golden compatibility tests

- A fixed multi-protocol capture produces stable observation/edge/node/state,
  topology/domain-map and index JSONL bytes after generated timing fields are
  normalized.
- The golden fixture covers two UEs, identifier reuse, one warning-band link,
  one rejected conflict, concurrent 3GPP/non-3GPP access, one PFCP session and
  one inconclusive roaming interval.
- Reader queries for event, alias, context, session, registration state,
  topology and fault domain return the expected IDs and bounds.
- Manifest/descriptors/revision compare under the shared golden normalization
  policy without normalizing source frames, confidence, ordering or evidence
  IDs.

### 24.4 Negative and access-control tests

- Timestamp-only records remain unlinked.
- Same DNN/slice does not merge UEs.
- Same TEID on different endpoints does not merge tunnels.
- Same UE/AMF/PLMN and overlapping time do not merge 3GPP, N3IWF or TNGF
  access contexts.
- Clear subscriber/UE-IP inputs never appear in graph artifacts, indexes,
  manifest, issues or logs.
- Corrupt T02 checksum, stale parent revision, incompatible policy, masking-key
  failure, symlink escape, duplicate ID with divergent payload and unresolved
  graph invariant all fail without a T03 manifest.
- T03 cannot open NRF/UDR readers or resolve NRF/UDR event IDs through direct
  lookup, generic indexes, cursors or selector expansion.
- Primary reader returning a quarantined or non-primary event fails with
  `RUN_ACCESS_BOUNDARY`.

## 25. Acceptance Criteria

T03 is complete when:

1. Request validation pins T02, reader, policy, masking and output-path
   identities before any event is read.
2. Every accepted edge has rule/source event IDs, reason codes, canonical score
   terms, confidence, validity bounds and a typed union/association effect.
3. Supporting evidence alone never creates, accepts or unions an edge.
4. Every observation belongs to one typed node and cross-type associations do
   not collapse UE/access/session/SM/PFCP node boundaries.
5. Dynamic identifier reuse does not merge completed or unrelated contexts.
6. Timestamp proximity alone never creates an identity edge.
7. Ambiguity and conflicts remain explicit and queryable.
8. Record IDs, revision and deterministic artifact bytes are stable for
   identical inputs/configuration on every supported machine.
9. Multi-protocol session correlation supports later attempt segmentation.
10. Capture-boundary uncertainty is represented, not hidden.
11. Sensitive values remain inside the trusted local boundary and all general
    lookup values follow the shared masking policy.
12. Primary-only access is enforced by constructor, reader and index tests.
13. Every access registration state is scoped to one access context and
    trusted/untrusted/3GPP contexts remain separate.
14. Every topology/domain classification is time-bounded, evidence-backed,
    revisioned and exposes deterministic alternatives/confidence without
    scenario override.
15. Fault-domain maps are derived independently from topology and never infer
    failure ownership from topology alone.
16. Published files, indexes, descriptors, counters, evidence references and
    manifest pass the section 17.1 invariants.
17. Fatal failures publish no graph manifest; partial publication occurs only
    for explicit information-loss conditions.
18. Large captures avoid all-pairs behavior and remain bounded by active
    contexts, with spill/no-spill equivalence when spill is enabled.

## 26. Mechanical Implementation Checklist

A small implementer should be able to build T03 in this order:

1. Import shared `Issue`, `RevisionEnvelope`, `ArtifactDescriptor`,
   `CollectionDescriptor`, `SourceRef`, `ScoreTerm`, `MaskingPolicy` and
   topology/identity models; do not duplicate them locally.
2. Define the request/result/config models from section 4 and validate numeric
   bounds, positive windows/caps and the rule that
   `auto_link_threshold > warning_link_threshold`.
3. Register the T03 issue codes from section 21 and add the issue-registry lint
   test before emitting any issue.
4. Validate `identity_rules`, `topology_rules` and masking payloads/checksums;
   reject unknown/executable rule content.
5. Validate run-relative paths and create only `staging/T03-<uuid>/`.
6. Load and checksum the T02 manifest/descriptors; prove the normalization
   result and primary reader pin the same revision.
7. Resolve the masking key by secret reference in memory and add leak-scanning
   tests for graph outputs/logs/issues.
8. Build the T03 revision from section 16.1 and return an identical existing
   generation when present.
9. Implement bounded `iter_primary_frame_batches(reader, capture)` using
   `PrimaryEventReader.by_frame()` and no generic partition selector.
10. Implement policy-named typed normalizers and canonical scope-key creation.
11. Implement observation extraction and UUID generation from section 7.1.
12. Write observations incrementally and maintain active exact/strong lookup
   indexes partitioned by node type/kind/scope.
13. Implement frame phases: extract, explicit mapping, allocation/association,
   registration state and release/close.
14. Implement candidate generation and deterministic cap handling from
   section 8.4.
15. Implement canonical score terms, confidence clamping and threshold-band
   decisions from section 9.
16. Implement pre-union hard-conflict checks and one union-find per node type.
17. Implement cross-type association staging without unioning node types.
18. Implement local component split/rebuild and persist rejected/removed edges
   with conflict IDs.
19. Implement timeout/release/capture-boundary interval handling and identifier
   reuse.
20. Materialize nodes with policy-priority anchors and stable display aliases.
21. Resolve accepted association endpoints to node IDs and validate every
   observation/node membership.
22. Materialize access-scoped registration-state intervals.
23. Extract time-bounded roaming facts and mint primary-only T03 evidence
   records through the shared evidence registry.
24. Score topology alternatives, select confidence and build independent fault
   domain maps using section 14.2.
25. Write all identity data files, including empty files, in deterministic
   order.
26. Build UE, identifier, event, context, session, registration, topology and
   fault-domain indexes with same-revision byte offsets.
27. Close, flush and optionally fsync writers; run every section 17.1
   invariant against staged bytes.
28. Build descriptors from section 15.3 and register them through the run-store
   artifact registrar.
29. Build and validate the section 16 manifest with full counts and sampled
   issues.
30. Publish data, indexes and evidence-registry additions atomically, then
   publish the T03 manifest last.
31. On fatal error, remove only this staging tree and preserve every published
   parent/sibling generation.
32. Add unit tests for rules, normalization, scoring, IDs, intervals,
   conflicts, topology, masking, revision and descriptor validation.
33. Add integration tests for reuse, handover, concurrent access families,
   SBI/PFCP linkage, capture boundaries, idempotency, recovery and T18
   resolution.
34. Add golden tests for full graph/index bytes and reader lookup behavior.
35. Add access-control tests proving T03 cannot read or cite NRF/UDR evidence.
