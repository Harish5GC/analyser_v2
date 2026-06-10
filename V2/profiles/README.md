# Procedure Profile Registry

This directory is the single normative contract for procedure profiles used
by T04 `segment_attempts` and T09 `detect_missing_transitions`. It owns profile
source files, schema validation, release and deployment overlays, condition
facts, deterministic resolution, compatibility rules, authoring controls and
requirements traceability.

The registry is an internal deterministic subsystem owned by T04. It is not a
model-callable tool. T04 and T09 receive only an immutable resolved profile
through the configuration and policy resolver defined in `../LLD.md` section
29.

## 1. Directory Layout

```text
profiles/
  README.md
  schema/
    procedure-profile.schema.json
    profile-overlay.schema.json
    registry-index.schema.json
  registry.yaml
  definitions/
    <profile_id>.yaml
  overlays/
    releases/<release>/<profile_id>.yaml
    deployments/<deployment_profile>/<profile_id>.yaml
    deployment-releases/<deployment_profile>/<release>/<profile_id>.yaml
  fixtures/
    <fixture_id>/
      fixture.yaml
      capture.pcapng
      expected.json
```

`profile_id` is a stable lowercase dotted identifier and maps to exactly one
base file. For example, `registration.initial` maps to
`definitions/registration.initial.yaml`. A registry implementation must
reject duplicate IDs, path aliases, case-only collisions, symlinks escaping
the registry root and files not declared by `registry.yaml`.

All files are UTF-8 without a byte-order mark. YAML is a source format only.
Resolved profiles are schema-validated and serialized as canonical JSON before
checksumming or publication. YAML anchors, aliases, custom tags and executable
constructors are prohibited.

## 2. Source and Runtime Models

The base document is a source realization of T04 section 6
`ProcedureProfile` and T09 section 5 `StageDefinition`:

```python
class ProfileSourceDocument(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    profile_id: str
    version: str
    procedure_type: str
    supported_releases: list[str]
    supported_deployment_profiles: list[str]
    trigger_matchers: list[EventMatcher]
    correlation_keys: list[CorrelationKeyRule]
    stages: list[StageDefinition]
    success_terminals: list[EventMatcher]
    failure_terminals: list[EventMatcher]
    abort_terminals: list[EventMatcher]
    retry_rules: list[RetryRule]
    timeout_rules: list[TimeoutRule]
    nesting_rules: list[NestingRule]
    visibility_requirements: list[VisibilityRequirement]
    owner: str
    requirement_refs: list[str]
    fixture_ids: list[str]
```

Resolution produces the immutable runtime model consumed by tools:

```python
class ResolvedProcedureProfile(ProcedureProfile):
    schema_version: Literal["2.0"] = "2.0"
    source_version: str
    source_checksum: str
    overlay_checksums: list[str]
    resolved_revision: str
```

The inherited `ProcedureProfile` fields remain exactly those in T04 section
6, including the explicit runtime `release` and `deployment_profile`
dimensions. The equivalent `ProcedureDefinition` in `../LLD.md` section 10 is
the state-engine projection of this same resolved object, not a second schema.

Every `stage_id` is unique within a `profile_id` and remains stable across
compatible profile versions and overlays. Stage display names may change;
stage identity may not.

## 3. Overlay Contract

Profiles are resolved from one base plus zero or more overlays. Overlay
precedence is fixed from least to most specific:

1. Base profile.
2. Release overlay.
3. Deployment overlay.
4. Deployment-and-release overlay.

```python
class ProfileOverlay(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    profile_id: str
    base_version_constraint: str
    release: str | None = None
    deployment_profile: str | None = None
    stage_patches: list[StagePatch]
    matcher_patches: list[MatcherPatch] = Field(default_factory=list)
    rule_patches: list[RulePatch] = Field(default_factory=list)
    rationale: str
    owner: str
```

An overlay may:

- Change stage applicability, conditions, timeout-rule references, visibility
  requirements, legal skips, matchers or terminal flags.
- Add a new stage only when the base profile declares an extension point and
  the new ID is namespaced beneath that extension point.
- Disable a stage by making it non-applicable through an explicit condition;
  it must not silently delete the stage.
- Refine correlation, retry, timeout, nesting and terminal matchers for a
  release or deployment.

An overlay must not rename an existing `stage_id`, change `profile_id`, alter
the procedure family, weaken a mandatory visible-interface requirement
without rationale, or introduce arbitrary fields. Conflicting patches at the
same precedence are an error. Missing required overlays produce an
incompatible resolution result, never an implicit fallback to another
deployment.

## 4. Conditional Expression Grammar

Conditions use `ConditionExpression` from `../LLD.md` section 23.3:

```python
class ConditionExpression(BaseModel):
    op: Literal["and", "or", "not", "eq", "ne", "present", "absent", "in"]
    fact: str | None = None
    value: JsonValue | None = None
    children: list["ConditionExpression"] = Field(default_factory=list)
```

Validation rules:

- `and` and `or` require two or more `children` and no `fact` or `value`.
- `not` requires exactly one child and no `fact` or `value`.
- `present` and `absent` require one allowlisted `fact` and no `value`.
- `eq`, `ne` and `in` require one allowlisted `fact` and a schema-compatible
  value. `in` requires an array value.
- Maximum nesting depth is 8 and maximum nodes per expression is 64.
- Evaluation is side-effect free. Unknown facts return `unknown`; they never
  coerce to false. A conditional stage whose condition is unknown is
  `inconclusive` when the stage would otherwise be required.
- Regex, JSONPath, template expansion, environment lookup, file/network
  access and executable expressions are forbidden.

### 4.1 Allowlisted Facts

The following prefixes and value domains are the complete V2 condition-fact
vocabulary. Adding a fact requires a schema-versioned registry change.

| Fact | Value domain | Producer |
|---|---|---|
| `request.registration_type` | `initial`, `mobility_update`, `periodic_update`, `emergency`, `unknown` | T05/T04 request signature |
| `request.access_type` | `3gpp`, `non_3gpp_trusted`, `non_3gpp_untrusted`, `unknown` | T05/T04 |
| `request.access_anchor_type` | `GNB`, `N3IWF`, `TNGF`, `UNKNOWN` | T03/T04 |
| `request.emergency` | boolean | T05/T04 |
| `request.service_request_type` | normalized NAS service-request type or `unknown` | T05 |
| `request.dnn` | normalized/masked string or absent | T05 |
| `request.s_nssai` | normalized/masked string or absent | T05 |
| `request.pdu_session_type` | `ipv4`, `ipv6`, `ipv4v6`, `ethernet`, `unstructured`, `unknown` | T05 |
| `request.ssc_mode` | integer `1..3` or absent | T05 |
| `request.release_origin` | `ue`, `network`, `cleanup`, `unknown` | T04 |
| `attempt.incomplete_history` | boolean | T04/capture bounds |
| `attempt.has_prior_registration` | boolean or unknown | T04/identity state |
| `attempt.has_active_session` | boolean or unknown | T04/session state |
| `attempt.handover_type` | `xn`, `n2`, `inter_amf`, `inter_system`, `access_mobility`, `unknown` | T04 |
| `attempt.roaming_topology` | `home`, `visited_unknown`, `home_routed`, `local_breakout`, `inconclusive` | topology producer |
| `attempt.rollback_observed` | boolean or unknown | T04 |
| `attempt.source_context_available` | boolean or unknown | T04/identity graph |
| `attempt.registration_accept_requires_ack` | boolean or unknown, derived by the selected release rule from the decoded Registration Accept | T02/T04 profile projection |
| `visibility.<reference_point>` | `observed`, `not_observed`, `unknown` | `DetectionContext.visibility` |
| `visibility.service.<service_name>` | `observed`, `not_observed`, `unknown` | release/profile visibility registry |
| `profile.release` | resolved release identifier | profile resolver |
| `profile.deployment_profile` | resolved deployment identifier | profile resolver |
| `profile.feature.<feature_id>` | boolean or unknown; feature ID declared in `registry.yaml` | profile resolver |
| `scenario.expected_outcome` | `success`, `failure`, `unknown` or absent | T13/T14 |
| `scenario.named_variant` | allowlisted variant ID or absent | T13/T14 |

`<reference_point>`, `<service_name>`, and `<feature_id>` are validated against
the selected release/deployment registry; they are not free-form namespaces.

## 5. Ordering and State Semantics

`StageDefinition.order` is a stable presentation order, not an assumption that
all events are strictly serial. Causal ordering is defined by
`predecessor_ids`, alternative/parallel groups and legal skip conditions.

- A stage is eligible only after every required predecessor is completed or
  legally skipped.
- Stages with the same `order` may run in parallel when their predecessor
  constraints permit it.
- Repeatable stages create ordered occurrences under one `stage_id`; they do
  not create new stage identities.
- Alternative branches use explicit any-of groups. The group is satisfied by
  one legal branch; unselected alternatives are `not_applicable`.
- A success or failure terminal closes only the owning attempt or declared
  nested attempt. It cannot close a sibling attempt.
- T09 emits an implicit missing-transition candidate only for the earliest
  applicable mandatory stage that was causally reachable and visible.

Profile validation rejects cycles, dangling predecessors, unreachable
mandatory stages, terminals without a trigger path, duplicate order/branch
definitions that are ambiguous, and conditions referencing undeclared facts.

### 5.1 Registration Complete acknowledgement rule

Initial, mobility-update and periodic-update profiles define
`REGISTRATION_COMPLETE` as `conditional`:

```yaml
stage_id: REGISTRATION_COMPLETE
applicability: conditional
condition:
  op: eq
  fact: attempt.registration_accept_requires_ack
  value: true
```

Each release overlay owns an `AckRequirementRule` listing the normalized
Registration Accept indicators/information elements that require an
acknowledgement for that release, including applicable new identity assignment,
SOR acknowledgement and NSSAI-related acknowledgement conditions. Deployment
overlays may narrow behavior only when a standards/vendor profile and fixtures
justify it; they cannot infer acknowledgement merely because another attempt
sent Registration Complete.

The decoder/normalizer preserves the relevant Registration Accept fields and
T04 evaluates the selected rule:

- `true`: missing Registration Complete on a visible N1 path is eligible for
  T09 missing-transition evaluation.
- `false`: the stage is `not_applicable`; Registration Accept can complete the
  registration profile without a Registration Complete message.
- `unknown`: absent/undecodable accept fields or encrypted/invisible N1 make
  the stage `inconclusive`, never missing.

Required fixtures per supported release/deployment: accept with each
acknowledgement trigger and observed complete; same trigger with missing
complete; accept with no trigger and no complete; accept fields unavailable;
periodic and mobility variants for both required/not-required behavior.

### 5.2 Non-3GPP access anchors and state

The registry realizes the requirement-level non-3GPP behavior through these
profile variants:

| Profile/overlay | Required trigger/anchor facts | State and visibility intent |
|---|---|---|
| `registration.non_3gpp` + `access.untrusted_n3iwf` | `request.access_type=non_3gpp_untrusted`, `request.access_anchor_type=N3IWF`, NAS Registration Request and time-compatible N3IWF/N2 context | Independent untrusted non-3GPP registration state; NWu/IKE/IPsec/EAP facts are supporting anchors when captured, not mandatory when outside visibility |
| `registration.non_3gpp` + `access.trusted_tngf` | `request.access_type=non_3gpp_trusted`, `request.access_anchor_type=TNGF`, NAS Registration Request and time-compatible TNGF/N2 context | Independent trusted non-3GPP registration state; trusted-access tunnel/session facts are supporting anchors when visible |
| 3GPP registration profiles | `request.access_type=3gpp`, `request.access_anchor_type=GNB` | Independent 3GPP registration state under the same UE |
| `mobility.access_transfer` | Explicit source/target access contexts and transfer/re-registration/session-continuity evidence | Links source and target contexts/attempts without merging their events or registration states |

Base and release/deployment overlays declare trigger matchers, source/target
access families, anchor matchers, access-scoped success/failure terminals,
deregistration scope rules and session-continuity conditions. Unknown anchor
type or invisible access-side signalling lowers confidence and produces
`inconclusive`; it must not be guessed from IP address, shared AMF or timing.

Required fixtures: simultaneous 3GPP+N3IWF registration, simultaneous
3GPP+TNGF registration, independent success/failure on each access, N3IWF to
3GPP transfer retaining a session, TNGF to 3GPP transfer, trusted/untrusted
context replacement, access-scoped deregistration, both-access deregistration,
and invisible/ambiguous anchor evidence.

## 6. Registry API and Resolution

The profile subsystem exposes an internal Python API, not a network endpoint:

```python
class ProfileRegistry(Protocol):
    def resolve(
        self,
        profile_id: str,
        release: str,
        deployment_profile: str,
    ) -> ResolvedProcedureProfile: ...

    def candidates(
        self,
        procedure_type: str,
        release: str,
        deployment_profile: str,
    ) -> tuple[ResolvedProcedureProfile, ...]: ...

    def validate_all(self) -> RegistryValidationReport: ...
```

Resolution steps are deterministic:

1. Resolve `registry.yaml` through the section-29 configuration resolver and
   validate its schema and checksum.
2. Locate exactly one base document by `profile_id`.
3. Verify requested release and deployment support.
4. Select overlays by the fixed precedence in section 3.
5. Apply patches by declared list order after rejecting conflicts.
6. Validate the merged runtime schema, graph, facts and traceability metadata.
7. Serialize canonical JSON and compute `resolved_revision` using section 7.
8. Cache by registry revision, profile ID, release and deployment. Return an
   immutable object.

Profile selection may score multiple returned candidates as defined in
`../LLD.md` section 10.4, but resolution itself never guesses a release,
deployment or profile ID.

## 7. Versioning, Checksums and Compatibility

Profile `version` is semantic versioning:

- Patch: wording, matcher correction or timeout tuning that does not alter
  stage identity or required behavior for existing fixtures.
- Minor: additive compatible stage, branch, release or deployment support.
- Major: removed/renamed stage, changed procedure identity, incompatible
  condition fact or behavior requiring migration.

Each source and overlay file has a SHA-256 checksum in `registry.yaml`.
Canonical serialization and digest construction follow `../LLD.md` section
25. The resolved revision is:

```text
sha256:<canonical-json(profile_id, source_version, release,
deployment_profile, source_checksum, ordered_overlay_checksums,
schema_version, resolved_profile)>
```

Artifacts produced by T04, T09 and consumers record the exact
`resolved_revision`. A changed profile never mutates an existing run. Loading
a run with an unavailable or checksum-mismatched revision fails closed with a
registered issue code.

Compatibility requires all persisted `stage_id` values to retain their
meaning within a major version. Migrations are explicit maps containing old
revision, new revision, stage-ID mappings, rationale and fixture results.
Automatic migration of published artifacts is prohibited.

## 8. Authoring and Review Process

1. Assign an owner and requirement references before adding a profile.
2. Add or update the base definition and only the smallest necessary overlay.
3. Add positive, failure, partial-capture and invisible-interface fixtures.
4. Run schema, graph, fact-vocabulary, checksum and traceability validation.
5. Run T04 segmentation and T09 missing-transition conformance tests.
6. Obtain review from protocol and harness owners; security review is required
   for new matchable fields or identifiers.
7. Update `registry.yaml`, checksums and compatibility/migration notes in the
   same change.

A profile cannot be marked supported until its traceability row has at least
one versioned fixture and owner. Generated or sanitized fixture PCAP
provenance follows backlog item V2-062. CI completeness enforcement is owned
by V2-054.

## 9. Requirements Traceability

Status `contract_only` means the profile ID and required fixture set are
reserved by this contract but the YAML/PCAP fixture has not yet been authored.
This explicit state is a CI input; it must never be interpreted as runtime
support.

| Requirement | Profile IDs | Required fixture IDs | Status |
|---|---|---|---|
| 8.1 registration family | `registration.initial`, `registration.mobility_update`, `registration.periodic_update`, `registration.emergency`, `registration.non_3gpp` | `reg-initial-success`, `reg-mobility-context-transfer`, `reg-periodic-complete-conditional`, `reg-emergency-limited-service`, `reg-non3gpp-coexisting-access`, `reg-retry-new-attempt` | `contract_only` |
| 8.2 authentication, identity and NAS security | `auth.identity`, `auth.primary`, `auth.nas_security`, plus nested variants of registration/service profiles | `auth-success`, `auth-sync-failure-recovery`, `auth-reject`, `auth-udm-http-failure`, `nas-security-reject` | `contract_only` |
| 8.3 service request and paging | `service.ue_request`, `service.network_triggered`, `service.paging` | `service-mo-data-success`, `service-emergency`, `service-context-missing`, `paging-response-delivery`, `paging-timeout`, `paging-multi-access` | `contract_only` |
| 8.4 PDU session lifecycle | `pdu.establishment`, `pdu.emergency_establishment`, `pdu.modification`, `pdu.release` | `pdu-establish-success`, `pdu-establish-tenth-fails`, `pdu-emergency-policy`, `pdu-modify-qos`, `pdu-release-ue`, `pdu-release-cleanup`, `pdu-multi-session` | `contract_only` |
| 8.5 idle-mode mobility | `mobility.idle_reselection`, `registration.mobility_update`, `registration.periodic_update`, `service.paging`, `service.ue_request`, `mobility.reachability_loss` | `idle-radio-only-no-core-failure`, `idle-tau-registration`, `idle-periodic`, `idle-release-resume`, `idle-mt-unreachable` | `contract_only` |
| 8.6 connected mobility and handover | `handover.xn`, `handover.n2`, `handover.inter_amf`, `handover.path_switch`, `handover.rollback` | `ho-xn-path-switch`, `ho-n2-success`, `ho-n2-preparation-failure`, `ho-inter-amf-context-transfer`, `ho-core-path-update-failure`, `ho-rollback-success`, `ho-rollback-failure` | `contract_only` |
| 8.7 inter-system and access mobility | `mobility.5gs_to_eps_n26`, `mobility.5gs_to_eps_no_n26`, `mobility.eps_fallback`, `mobility.eps_to_5gs`, `mobility.access_transfer` | `mobility-n26`, `mobility-no-n26`, `mobility-eps-fallback`, `mobility-return-5gs`, `mobility-3gpp-non3gpp`, `mobility-invisible-radio` | `contract_only` |
| 8.8 roaming family | `roaming.registration`, `roaming.pdu_home_routed`, `roaming.pdu_local_breakout`, plus roaming overlays for handover profiles | `roaming-registration-home-auth`, `roaming-registration-restricted`, `roaming-home-routed`, `roaming-local-breakout`, `roaming-handover-anchor`, `roaming-topology-inconclusive` | `contract_only` |
| 8.9 deregistration and context release | `deregistration.ue`, `deregistration.network`, `deregistration.implicit`, `context.release`, `context.amf_relocation_cleanup` | `dereg-ue-3gpp`, `dereg-network-both-accesses`, `dereg-implicit-expiry`, `context-release-idle`, `context-loss-active-failure`, `amf-relocation-cleanup` | `contract_only` |
| 8.10 policy, charging, slice and NF dependencies | Conditional stages/overlays on affected call profiles; dependency stage IDs `dependency.nrf`, `dependency.udm_udr`, `dependency.ausf`, `dependency.nssf`, `dependency.pcf`, `dependency.chf`, `dependency.scp` | `dep-nrf-precall-recovered`, `dep-nrf-unavailable-at-call`, `dep-udr-correlated-failure`, `dep-ausf-auth-failure`, `dep-nssf-slice-reject`, `dep-pcf-policy-failure`, `dep-chf-nonblocking`, `dep-scp-alternate-route` | `contract_only` |

### 9.1 Acceptance-Criteria Coverage

| Acceptance criterion | Profiles/fixtures proving it | Status |
|---|---|---|
| 13. Distinguish registration variants | `registration.initial`, `.mobility_update`, `.periodic_update`, `.emergency`, `.non_3gpp`; all 8.1 fixtures | `contract_only` |
| 14. Emergency conditional requirements | `registration.emergency`, `pdu.emergency_establishment`; `reg-emergency-limited-service`, `pdu-emergency-policy` | `contract_only` |
| 15. Distinguish Xn/N2/inter-AMF and rollback | `handover.xn`, `.n2`, `.inter_amf`, `.rollback`; handover fixture set in 8.6 | `contract_only` |
| 16. Correlate path switch, SBI and PFCP updates | `handover.path_switch`; `ho-xn-path-switch`, `ho-core-path-update-failure` | `contract_only` |
| 17. Classify roaming topology correctly | `roaming.registration`, `.pdu_home_routed`, `.pdu_local_breakout`; roaming fixture set in 8.8 | `contract_only` |
| 18. Invisible mandatory stage is inconclusive | Every profile with `visibility_requirements`; `mobility-invisible-radio`, `roaming-topology-inconclusive`, plus one invisible-interface fixture per supported family | `contract_only` |

## 10. Registry Index Contract

`registry.yaml` is the only discovery entry point:

```python
class RegistryProfileEntry(BaseModel):
    profile_id: str
    relative_path: str
    version: str
    checksum: str
    owner: str
    supported_releases: list[str]
    supported_deployment_profiles: list[str]
    fixture_ids: list[str]
    support_status: Literal["contract_only", "experimental", "supported", "deprecated"]

class ProfileRegistryIndex(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    registry_version: str
    entries: list[RegistryProfileEntry]
    facts: list[str]
    feature_ids: list[str]
    checksum: str
```

Entries are sorted by `profile_id`; lists with semantic set behavior are
sorted before canonical serialization. A `supported` entry with no owner,
release, deployment, terminal definition, requirement reference or fixture is
invalid. Unknown files are reported and ignored; they cannot become active by
being dropped into the directory.
