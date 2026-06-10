# V2 5G Call Failure Analysis Harness Architecture

## 1. Architecture Summary

V2 is a hybrid analysis system. Protocol correctness comes from deterministic decoders, normalizers, correlation logic and state machines. A language model is optional and is used only to interpret a bounded evidence packet and write a concise diagnosis.

```text
                         +--------------------+
PCAP + optional scenario|  CLI / API Adapter |
----------------------->+----------+---------+
                                   |
                                   v
                         +---------+----------+
                         | Analysis Orchestrator|
                         +----+---------+-----+
                              |         |
                  decode      |         | scenario
                              v         v
                    +---------+--+   +--+----------------+
                    | Go Decoders |   | Scenario Parser   |
                    | + tshark    |   | optional model    |
                    +------+------+   +-------------------+
                           |
                           v
                    +------+---------+
                    | Normalization  |
                    | Event Store    |
                    +------+---------+
                           |
                           v
                    +------+---------+
                    | Identity Graph |
                    | Attempt Engine |
                    +------+---------+
                           |
                           v
              +------------+-------------+
              | Deterministic Diagnostics|
              | HTTP/NAS/NGAP/PFCP/state |
              +------------+-------------+
                           |
                           v
                    +------+---------+
                    | Evidence Builder|
                    +---+----------+-+
                        |          |
             provider=none          | provider=local/openrouter
                        |          v
                        |   +------+---------+
                        |   | Model Gateway  |
                        |   +------+---------+
                        |          |
                        +----------+
                                   v
                           +-------+-------+
                           | Report Builder|
                           +---------------+
```

## 2. Architectural Decisions

### 2.1 The model is not the protocol parser

The current HTTP/2 lean file can be several megabytes. Raw NGAP structures are deeply nested. Sending either directly to an under-10B model is inaccurate and inefficient. V2 therefore extracts semantic events and supplies only relevant evidence.

### 2.2 V2.1 uses controlled two-pass orchestration

The primary harness pipeline is fixed. The first model pass may emit a structured request for one or both bounded dependency tools: `inspect_nrf_flow` and `inspect_udr_flow`. The orchestrator validates and executes approved requests, rebuilds the evidence packet, and performs one final model pass. The model cannot invoke arbitrary tools or create an unbounded tool loop. Native provider function calling is optional because the same request can be returned as schema-constrained JSON.

### 2.3 OpenAI-compatible provider boundary

Both local inference and OpenRouter use one client contract. Provider configuration changes the endpoint, model and authentication, not the analysis workflow.

### 2.4 Full data and model evidence are separate

The system stores the source PCAP, raw/full decoder output and normalized events for the complete run lifetime. Normalized events are partitioned into primary call flow, NRF and UDR evidence. No detailed NRF/UDR transaction is placed in the first model packet. Raw evidence is immutable and is never destroyed by normalization. Cleanup operates on the complete analysis run only after its retention period.

Compact evidence is therefore a first-pass working set, not a permanent information boundary. Any later diagnostic stage may follow evidence references back to the complete record or request a bounded re-decode of surrounding packets.

### 2.5 Attempts are first-class objects

The main unit of diagnosis is a procedure attempt, not the whole PCAP and not only a UE. Reused session IDs are handled by transaction and time-bounded attempt instances.

## 3. Major Components

Detailed implementation contracts for all tools are indexed in `tools/README.md`. This architecture document defines their ownership boundaries and runtime composition.

### 3.1 Input adapters

V2.1 provides a CLI. A FastAPI adapter can call the same application service later.

Responsibilities:

- Validate input path and configuration.
- Create `analysis_id` and run directory.
- Accept optional scenario and selectors.
- Return report locations and process exit status.

### 3.2 Analysis orchestrator

The orchestrator owns run lifecycle and composes tools as a dependency graph. It never supplies a generic event-store handle to primary analysis code and never accumulates candidates from multiple attempts into one ranking input.

| Phase | Tools | Placement and gate |
|---|---|---|
| Run setup | application/run store | Validate input/configuration, create `analysis_id`, retain source PCAP and initialize the manifest. |
| Optional scenario parse | T13 | Runs only when scenario text exists. It may execute independently of capture processing, but its persisted result is required before T14. |
| Capture foundation | T01 -> T02 -> T03 -> T04 -> T21 | Decode, normalize/partition, correlate identities, segment attempts, then classify capture/attempt phases. Each arrow is a hard data dependency. |
| Per-attempt extraction | T05 | Runs for every attempt and records what the UE/network requested. |
| Explicit detection | T06, T07, T08 | Run per attempt against assigned primary events. They may execute concurrently but cannot read NRF/UDR partitions. |
| Implicit detection | T09 | Runs after T06-T08 for the same attempt so explicit failures can suppress or explain missing-transition candidates. |
| Timeline and baseline | T10, then T11 | T10 builds primary timelines for every attempt. T11 runs for failed/incomplete attempts when eligible earlier successes exist. |
| Primary determination | T12 | Ranks only candidates belonging to the current failed/incomplete attempt. |
| Optional scenario validation | T14 | Runs only when T13 produced a scenario; primary validation uses T04/T05/T09 and primary evidence. |
| Optional model pass | T15 -> T16 | Runs only for failed/incomplete attempts selected by the deterministic model-narration policy (explicit selectors, configured ordering, per-run cap) when a provider is enabled. Initial T15 packets are primary-only. Attempts skipped by the cap are disclosed in the report. |
| Optional dependency inspection | T24/T25, with T22/T23 internal | Runs only for schema-valid initial T16 requests. T22 is internal to T24; T23 is internal to T24/T25. The executor grants scoped NRF/UDR readers only after validation. |
| Dependency-expanded determination | T12 and applicable T14, then T15 -> T16 | Returned dependency results are deterministic inputs. Ranking and applicable scenario checkpoints are revised before the expanded packet and single final model pass. |
| On-demand forensic support | T18 -> T19 -> T20 as needed | Capability-scoped lookup/context/re-decode services run only for a validated evidence need. T20 is never directly model-callable. |
| Reporting | T17 | Always renders deterministic results; optional model/dependency outcomes and their failures are included when present. |

Every executed stage publishes an immutable result and status before `manifest.json` records completion. Skipped optional stages are recorded as absent/disabled according to their contracts, not treated as failed. A partial optional stage cannot erase already completed deterministic results.

#### Dependency-expanded commit barrier

Dependency expansion is a deterministic commit barrier, not a direct append to the model packet:

1. Settle every approved T24/T25 request for an attempt.
2. Validate attempt, initial-packet, request and revision lineage for each returned result.
3. Admit only published `completed`, `empty` or `partial` results with valid integrity metadata; retain failed/invalid results only as stage outcomes.
4. Publish a new T12 dependency-expanded ranking using the admitted result set.
5. Publish a new T14 validation only when dependency-aware scenario checkpoints exist.
6. Build T15 from the exact initial packet plus those revised deterministic artifacts and admitted inspection revisions.
7. Invoke one T16 final pass. The final result cannot request more tools.

The primary T12/T14 artifacts remain immutable. T17 reports both generations and their differences. If the barrier has no admitted result, the orchestrator does not create an expanded packet or final model call.

### 3.3 Go decoder process

The existing Go decoder remains a separate process in V2.1. This keeps fast PCAP processing and avoids embedding Go in Python.

The complete implementation contract for this component is `tools/T01_decode_capture.md`. It defines the Python wrapper, Go command, UUID stream documents, manifest, atomic publication, partial failures, security, performance and tests.

Required CLI evolution:

```text
5g_call decode <pcap> --output-dir <dir> --format v2
```

The command runs HTTP/2, NGAP and PFCP decoding concurrently and writes to supplied paths. It returns nonzero only for fatal decode failure and writes protocol-specific status into a decoder manifest.

The decoder retains every HTTP/2 stream as a separate UUID-named JSON document and writes a stream index that preserves `tcp.stream:http2.streamid`. It does not partition NRF/UDR traffic or invoke a model.

### 3.4 Normalization layer

The normalizer translates changing `tshark` field trees into stable semantic events.

It has four adapters:

- HTTP/2 adapter.
- NGAP adapter.
- NAS adapter embedded within NGAP processing.
- PFCP adapter.

Normalization is the compatibility boundary. Changes in `tshark` output should require adapter changes without altering diagnostic tools or model prompts.

### 3.5 Event store and indexes

V2.1 uses file-backed JSONL plus in-memory indexes for one analysis run.

Files:

- `events.jsonl`: canonical events ordered by frame.
- `primary_events.jsonl`: NGAP/NAS, PFCP and non-NRF/UDR HTTP events eligible for first-pass analysis.
- `nrf_events.jsonl`: NRF management, discovery and delegated-discovery evidence.
- `udr_events.jsonl`: UDR data-access evidence.
- `frame_index.json`: frame to normalized/full/raw record references.
- `stream_index.json`: transport and protocol stream lookup.
- `nrf_index.json`: NF instance, NF type, service, operation and frame lookup.
- `udr_index.json`: masked subscriber correlation, resource, consumer NF, operation and frame lookup.
- `identifier_index.json`: UE/session/correlation identifier lookup.
- `ue_index.json`: identifiers to internal UE IDs.
- `session_index.json`: session/context identifiers.
- `attempts.json`: segmented attempts.
- `failures.json`: detector output.

An embedded database is not required for V2.1. The repository layer must hide storage details so SQLite can replace JSONL later.

### 3.6 Full-fidelity evidence repository

The evidence repository retains:

- Immutable source PCAP with checksum.
- Raw packet-level `tshark` records where configured.
- Full HTTP/2 conversations, including all headers/bodies and incomplete-state details.
- Full NGAP PDUs with embedded NAS trees.
- Full PFCP messages with all retained IEs.
- Derived targeted re-decodes and frame-window extracts.

Every normalized event and failure candidate points to one or more full records. The repository supports lookups by frame, time, protocol stream and correlation identifier without reparsing all files.

If the requested field was not included in the original `tshark` tree, the
repository invokes T20. T20 plans protocol context, extracts a bounded slice
through the optional T01 packet-access index or an honestly accounted
scan-and-preslice path, dissects only that slice, maps slice frames back to
source frames, and registers the output as new derived evidence. Result size,
slice/dissection work and source scan cost are independent bounds.

### 3.7 Identity graph

The identity graph links identifiers with evidence-backed edges.

Examples:

```text
SUCI -> AMF UE NGAP ID
AMF UE NGAP ID -> RAN UE NGAP ID
PDU session ID + PTI -> SM context reference
SM context -> PFCP CP SEID
PFCP session -> UE IP / F-TEID
```

Each edge has:

- Confidence.
- Correlation reason.
- Source event IDs.
- Valid time interval.

Conflicting mappings create separate candidates and warnings. They are not silently merged.

### 3.8 Attempt engine

The attempt engine consumes the ordered UE timeline and procedure definitions.

Each attempt contains:

- Internal attempt UUID.
- UE ID.
- Procedure type and sequence number.
- Start/end frames and timestamps.
- Correlation identifiers.
- State transitions.
- Associated events.
- Outcome and completion reason.

Retries are attached to an existing attempt when transaction identifiers match and the prior attempt remains open. A new request after completion or with a new transaction starts another attempt.

The engine loads versioned scenario profiles rather than assuming one call sequence. Profile families include:

- Initial, mobility, periodic, emergency and non-3GPP registration.
- Authentication, identity and NAS security.
- UE-triggered service request, network-triggered paging and resume.
- Normal and emergency PDU session lifecycle.
- Idle mobility, Xn handover, N2 handover, inter-AMF handover and path switch.
- Inter-system and 3GPP/non-3GPP access mobility.
- Home-routed and local-breakout roaming.
- Deregistration, context release and NF dependency subprocedures.

Profiles express mandatory, conditional, optional and repeatable stages. They also declare which interfaces must be visible before a missing stage can be diagnosed.

### 3.9 Diagnostic engine

The diagnostic engine consists of independent detectors:

- HTTP failure detector.
- NAS/NGAP failure detector.
- PFCP failure detector.
- Missing-transition detector.
- Retry-loop detector.
- Cross-protocol consistency detector.
- Capture-phase classifier.

Detectors emit candidates into a common schema. A root-cause ranker applies temporal, causal and attempt-association rules.

The lazy dependency subsystem is separate from the primary diagnostic engine:

- `inspect_nrf_flow` invokes scoped NF lifecycle/readiness and background-impact analysis.
- `inspect_udr_flow` invokes scoped UDR request/response, retry and correlation analysis.
- Neither subsystem runs unless approved model evidence requests select it.

Scenario-aware detectors additionally distinguish:

- Emergency-policy exceptions from normal subscription failures.
- Periodic registration from mobility or initial registration.
- Xn handover, where N2 preparation is not expected, from N2 handover.
- Successful handover rollback from failed mobility.
- Home-network, visited-network and inter-PLMN roaming failures.
- Pure idle cell reselection from core-network mobility procedures.
- Benign pre-call NF cleanup/startup errors from unresolved infrastructure faults that affect a call.

### 3.10 Capture phase and lazy dependency analysis

The phase classifier anchors UE call windows from NAS/NGAP initiation and completion events. It labels all other traffic as preamble, active, between attempts, postamble or unknown. This label alone does not determine relevance.

NRF and UDR evidence is not analyzed in the primary pass. When the first model pass observes a symptom consistent with discovery, NF registration/readiness or subscriber-data access, it may request the corresponding bounded inspection tool. Only that tool receives the separate dependency flow.

Example:

```text
frame 100: DELETE NF instance A -> 404
frame 140: PUT NF instance A -> 201
frame 160: service status REGISTERED/AVAILABLE
frame 1000: UE Registration Request
```

If the model requests NRF inspection, the tool classifies the frame 100 failure as resolved startup cleanup and excludes it from the UE call root cause.

If frames 140/160 are absent and the primary call flow contains a discovery/readiness symptom, the model may request NRF inspection. The unresolved lifecycle failure then becomes eligible as a causal or contributing candidate.

If the model does not request dependency evidence, these frames remain in the retained NRF partition and are not included in the diagnosis.

The report keeps separate sections for:

- Call-related failures.
- Call-impacting infrastructure state.
- Background/startup anomalies with no demonstrated call impact.

### 3.11 Baseline comparator

For a failed attempt, the comparator selects the nearest prior successful attempt with matching procedure and similar request signature.

The request signature excludes dynamic fields and may include:

- Procedure type.
- DNN.
- S-NSSAI.
- PDU type.
- Access type.
- Registration/request type.

The comparator aligns semantic stages and reports the first divergence. It does not diff raw JSON.

### 3.12 Scenario engine

When a scenario is supplied:

- The model converts free text into a strict `ScenarioSpec` when a provider is configured.
- A deterministic fallback extracts obvious named values and procedure terms.
- Checkpoint validation uses canonical events and attempt states.
- Model narrative cannot override deterministic checkpoint status.

### 3.13 Evidence builder

The evidence builder creates the only protocol payload sent to a model.

It includes:

- UE request.
- Selected attempt summary.
- Primary and alternative failure candidates.
- Bounded timeline.
- Baseline divergence.
- Scenario results.
- Exact evidence records.
- Schema version and field descriptions.

The first packet contains no detailed NRF or UDR transactions, including their failures. It may contain only symptoms from the primary call flow that justify a dependency investigation. A second packet may contain the bounded output of `inspect_nrf_flow` or `inspect_udr_flow` after the model requests it.

The builder may expand the packet in controlled stages:

1. Start with primary normalized evidence.
2. Fetch complete records for selected primary failure candidates.
3. Ask the model for a diagnosis and optional structured dependency evidence requests.
4. Validate and execute bounded NRF/UDR requests.
5. Add only the returned dependency evidence.
6. Run targeted re-decode only when required fields were not retained initially.
7. Rebuild the final compact model packet within its token budget.

### 3.14 Model gateway

The gateway supports:

- `none`: no inference.
- `local`: OpenAI-compatible local endpoint.
- `openrouter`: OpenRouter endpoint and API key.

The gateway handles:

- Context/token budget enforcement.
- Structured diagnosis and dependency-evidence request output.
- Validation of tool name, attempt ID, target selectors, reason code and bounded window.
- A maximum of one dependency-evidence round before the final diagnosis.
- Timeout and one retry for malformed output.
- Schema validation.
- Provider metadata and usage reporting.
- Privacy masking before remote calls.

The model result is advisory narrative. The report stores deterministic and model findings separately.

### 3.15 Report builder

The builder combines deterministic findings and optional model narrative into one report.

The first section must directly answer:

- UE request.
- Failed stage.
- Root cause.
- Exact evidence frames.

It then shows the attempt timeline, alternatives, baseline comparison, scenario validation and warnings.

### 3.16 Code ownership and capability boundaries

```text
harness.orchestrator
  +-- decoder.runner -> Go `decode` command
  +-- normalize.partition_router -> primary/NRF/UDR stores
  +-- analysis -> PrimaryEventReader only
  +-- evidence.initial_builder -> primary evidence only
  +-- providers -> structured diagnosis/tool request
  +-- dependency_tools.executor
        +-- request_validator
        +-- NRFInspector -> NRFEventReader
        +-- UDRInspector -> UDREventReader
  +-- evidence.expanded_builder -> completed inspection results only
  +-- reporting
```

The storage factory exposes a `PrimaryEventReader` to the orchestrator. NRF and UDR readers are constructed inside `dependency_tools.executor` and are not accepted by primary detector or initial-evidence interfaces. This prevents accidental eager dependency analysis even if modules are later refactored.

The package responsibilities are:

- `decoder`: safe process execution and decoder-manifest validation.
- `normalize`: conversion from full decoder artifacts to canonical events and partition routing.
- `storage`: immutable artifacts, JSONL partitions, indexes and capability-specific readers.
- `analysis`: UE/session correlation, attempts, primary detectors, comparison and ranking.
- `dependency_tools`: validated lazy NRF/UDR inspection only.
- `evidence`: initial and dependency-expanded model packets.
- `providers`: local/OpenRouter-compatible structured inference.
- `scenario`: scenario parsing and deterministic checkpoint validation.
- `reporting`: machine-readable and human-readable results.

## 4. Runtime Data Flow

### 4.1 Standard analysis without scenario

```text
PCAP
-> decode all protocols
-> normalize and partition primary/NRF/UDR events
-> correlate UE/session identities
-> segment attempts
-> detect explicit and implicit failures in the primary flow
-> compare failed attempts
-> rank primary candidates
-> build first-pass evidence without NRF/UDR details
-> optional model diagnosis plus justified NRF/UDR evidence request
-> optional bounded dependency inspection
-> optional final model diagnosis with returned dependency evidence
-> reports
```

### 4.2 Analysis with scenario

```text
scenario
-> parse ScenarioSpec
-> identify target procedure/UE constraints
-> standard analysis
-> validate checkpoints against evidence
-> include results in model packet and reports
```

### 4.3 Repeated session example

For nine successful establishment/release cycles and a tenth failed establishment:

1. Identity graph groups all events under the same UE.
2. Attempt engine creates ten establishment attempts and nine release attempts.
3. Attempt ten receives only events linked by its NAS PTI/session, SM context, PFCP session and time window.
4. Detectors find explicit errors or the first missing transition within attempt ten.
5. Comparator selects attempt nine or the closest equivalent successful attempt.
6. Root-cause ranker identifies the first causal divergence.
7. Model receives attempt ten and a compact comparison, not all ten raw sessions.

### 4.4 Mobility and roaming example

For a roaming UE performing inter-AMF N2 handover:

1. Topology classifier identifies home and visited PLMN roles and the roaming session mode.
2. Identity graph links old and new AMF UE contexts to the same UE.
3. Profile selector chooses the inter-AMF N2 handover profile rather than normal registration.
4. Attempt engine correlates Handover Required, context transfer, target preparation, SM/PFCP path update and old-context release.
5. Diagnostic engine classifies a failed target PFCP update as primary and later Handover Failure/rollback as downstream recovery evidence.
6. Report identifies whether the failure belongs to the visited access/core, home network or inter-PLMN path.

## 5. Deployment Architecture

### 5.1 Local workstation

```text
V2 CLI
  + Go/tshark decoder processes
  + Python deterministic harness
  + local OpenAI-compatible server on RTX 5090
```

Recommended local inference profile:

- One request at a time.
- Under-10B or quantized larger model.
- 12K maximum evidence input.
- Structured JSON response.
- Low temperature.

### 5.2 OpenRouter

The deterministic pipeline remains local. Only the masked evidence packet and optional scenario are sent to OpenRouter. Full PCAP and raw decoder output remain local.

### 5.3 Future service mode

A future API service can place analysis jobs into a queue and execute the same orchestrator in isolated worker directories. This does not change tool contracts.

## 6. Failure and Recovery Architecture

- Decoder failure: mark protocol unavailable; continue if other protocols are useful.
- Normalization error: retain source reference and warning; continue other records.
- Ambiguous UE mapping: keep candidates separate and lower confidence.
- Model timeout/error: emit deterministic report and provider warning.
- Invalid model JSON: retry once with validation error, then fall back.
- Capture begins or ends mid-procedure: classify as `incomplete_capture`, not automatically as network failure.
- Output write failure: fail the run because evidence cannot be audited safely.

## 7. Security Boundaries

```text
Raw PCAP and full decoder output: local trusted boundary
Canonical event store: local trusted boundary
Targeted re-decode artifacts: local trusted boundary
Masked evidence packet: model boundary
OpenRouter request: remote boundary, explicit opt-in only
```

Sensitive values are represented internally but masked before model submission and report rendering according to policy. Authorization headers, client certificates and API keys are never model evidence.

## 8. Evolution Path

V2.1:

- CLI.
- JSONL store.
- Fixed primary orchestration with one validated, bounded dependency-evidence round.
- One PCAP at a time.
- Local/OpenRouter/none providers.

V2.2 candidates:

- FastAPI job interface.
- SQLite event store.
- Parallel queued analyses.
- Additional procedure state machines.
- Additional model-requestable evidence tools beyond NRF and UDR.

V2.3 candidates:

- Learned anomaly ranking from labeled cases.
- Vendor-specific procedure profiles.
- Regression corpus and automated RCA scoring.
