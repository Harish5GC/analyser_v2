# V2 5G Call Failure Analysis Harness Requirements

## 1. Purpose

V2 accepts a 5G packet capture containing NGAP/NAS, HTTP/2 SBI, and PFCP traffic and produces an evidence-backed diagnosis for each UE procedure attempt.

The harness must answer:

1. What did the UE request?
2. Did the requested procedure succeed or fail?
3. At which protocol stage did it first fail?
4. What is the most likely root cause?
5. Which later errors are consequences rather than the root cause?
6. If a scenario is supplied, which expected checkpoints passed, failed, or cannot be verified?

The harness must support:

- A local model exposed through an OpenAI-compatible API.
- OpenRouter using an API key.
- Operation without a model, returning deterministic findings only.
- One PCAP analysis at a time in V2.1.
- Multiple UEs and repeated procedures within the same PCAP.

## 2. Design Principles

### 2.1 Deterministic analysis first

Go and Python code must perform protocol extraction, correlation, request/response pairing, attempt segmentation, failure detection, and evidence selection. The model must not be responsible for searching raw decoder output.

### 2.2 Model as an explanation layer

The model receives a compact evidence packet and performs:

- Root-cause explanation.
- Ranking when deterministic analysis leaves multiple plausible candidates.
- Natural-language scenario interpretation.
- Final report generation.

The deterministic result remains available if the model is disabled or fails.

### 2.3 Evidence traceability

Every conclusion must reference evidence containing:

- Protocol.
- Frame number.
- Capture timestamp.
- Source and destination when available.
- Original decoder field path.
- Original field value or a bounded excerpt.

### 2.4 Attempt isolation

The harness must not analyze a UE's entire capture as one call. Registration, service request, PDU session establishment, modification, and release must be segmented into distinct attempts.

A PDU session ID may be reused. It must never be the sole attempt identifier.

## 3. Inputs

### 3.1 Required input

- `pcap_path`: readable PCAP or PCAPNG file.

### 3.2 Optional inputs

- `scenario`: free-text description of expected behavior or test intent.
- `provider`: `none`, `local`, or `openrouter`.
- `model`: provider-specific model name.
- `base_url`: OpenAI-compatible API base URL.
- `api_key`: required for OpenRouter; optional for local endpoints.
- `ue_selector`: SUPI, SUCI, GPSI, GUTI, AMF UE NGAP ID, RAN UE NGAP ID, or internal UE ID.
- `attempt_selector`: internal attempt ID.
- `max_model_attempts_per_run`: default `5`; caps how many failed/incomplete attempts receive model narration. Deterministic analysis always covers every attempt.
- `model_attempt_order`: deterministic narration ordering policy; default selects by highest deterministic severity, then earliest start frame.
- `dependency_lookup_mode`: fixed to `model_requested` in V2.1.
- `max_dependency_requests_per_attempt`: default `2`, with at most one NRF and one UDR request.
- `dependency_context_frames_before`: bounded default for approved dependency lookup.
- `dependency_context_frames_after`: bounded default for approved dependency lookup.
- `retention_days`: optional lifecycle policy; omitted means retain until explicit deletion.
- `context_frames_before`: default `20`.
- `context_frames_after`: default `20`.

Secrets must come from environment variables or a secret manager. API keys must not be written into reports or logs.

## 4. Outputs

Each analysis run receives a UUID `analysis_id` and an isolated output directory:

```text
V2/output/<analysis_id>/
  manifest.json
  source/
    capture.pcap
  decoded/
    decoder_manifest.json
    raw/
      http2.packets.jsonl
      ngap.packets.jsonl
      pfcp.packets.jsonl
    full/
      http2/
        streams/<stream-document-uuid>.json
        stream_index.jsonl
      ngap/
        messages.jsonl
        message_index.jsonl
      pfcp/
        messages.jsonl
        message_index.jsonl
  normalized/
  indexes/
  evidence/
  report.json
  report.md
  logs/
```

`report.json` is the authoritative machine-readable result. `report.md` is a human-readable rendering.

The run directory must retain three evidence levels:

1. Original PCAP: immutable source for later targeted re-decoding.
2. Raw/full decoder output: complete protocol fields and bodies without lean filtering.
3. Normalized/indexed events: compact semantic data used for routine analysis.

Normalized data is an index and analysis representation. It must never be the only retained copy of protocol evidence.

Source PCAP and raw/full decoder retention are mandatory. No analysis stage may delete or rewrite them. Lifecycle cleanup may remove the entire completed run only after the configured retention period; it must never selectively remove source evidence while keeping a report that cites it.

The report must contain:

- Analysis status: `success`, `partial`, or `failed`.
- Capture and decoder metadata.
- One result per UE.
- One result per procedure attempt.
- UE request details.
- Attempt outcome.
- Primary failure candidate.
- Secondary and downstream failures.
- Evidence references.
- Scenario checkpoint results when a scenario was supplied.
- Deterministic confidence and model confidence as separate fields.
- Attempts analyzed deterministically but skipped by the model-narration cap, with the policy values that caused the skip.
- Missing-data and decoder warnings.

## 5. Decoder Requirements

### 5.1 Existing Go decoders

The existing Go decoders remain responsible for PCAP decoding through `tshark`:

- HTTP/2 SBI conversations.
- NGAP with embedded NAS.
- PFCP messages and information elements.

The harness invokes one Go command and stores all outputs under the analysis directory. Output paths must not be global fixed filenames.

The decoder must retain complete full-fidelity output in addition to normalized or cleaned output. Full-fidelity means:

- No NRF/UDR removal.
- No removal of NAS subtrees.
- No removal of unknown protocol fields or IEs.
- No truncation of HTTP request/response bodies, including multipart content.
- No loss of duplicate headers.
- No loss of incomplete streams, resets, retransmissions or unmatched requests/responses.
- Original frame numbers and full timestamps preserved.

Sanitized and lean outputs may be generated as derived artifacts but must not overwrite full output.

### 5.2 HTTP/2 requirements

Each HTTP/2 conversation must retain:

- TCP stream ID and HTTP/2 stream ID.
- Request and response frame numbers.
- Request method, URI, headers, and body.
- Response status, headers, body, and `ProblemDetails` fields.
- Request and response timestamps.
- Source and destination addresses.
- Completion state, including missing response or truncated stream.

NRF and UDR policy:

- Full decoded output must retain all NRF and UDR traffic.
- Normalized NRF and UDR events must be stored in separate searchable partitions from the primary UE call-flow evidence.
- No detailed NRF or UDR transaction, including failures, is included in the first model evidence packet.
- The first model pass receives only the primary UE flow and symptoms visible at the NF boundary, such as an upstream `5xx`, missing dependency response, discovery-related error indication, or subscriber-data-related error returned by another NF.
- Detailed NRF evidence is loaded only through `inspect_nrf_flow` after the model returns a justified NRF evidence request.
- Detailed UDR evidence is loaded only through `inspect_udr_flow` after the model returns a justified UDR evidence request.
- A supplied scenario may make NRF or UDR investigation more likely, but it must still use the same evidence-request path.
- If no request is made, NRF and UDR flows remain retained and searchable but are not analyzed or sent to the model.

Partition routing:

- `nrf`: `nnrf-nfm`, `nnrf-disc`, NRF status notifications, and SCP delegated-discovery evidence that exposes NRF discovery semantics.
- `udr`: `nudr-dr` operations and transactions resolved to a configured or discovered UDR endpoint.
- `primary`: NGAP/NAS, PFCP and all remaining HTTP/2 transactions.
- A hidden NRF/UDR failure must not be converted into a first-pass failure candidate or summary. The first packet may state only that dependency tools are available.

### 5.3 NGAP/NAS requirements

The normalized output must preserve compact semantic NAS fields rather than dropping the NAS subtree without replacement.

Required NAS fields include, when present:

- Mobility-management message type.
- Session-management message type.
- Registration type and follow-on request flag.
- Service request type.
- Request type.
- PDU session ID.
- Procedure transaction ID.
- DNN.
- S-NSSAI SST and SD.
- Requested and selected PDU type.
- SSC mode.
- Requested QoS indicators.
- SUCI/SUPI/GUTI/GPSI identifiers, with configurable masking.
- 5GMM and 5GSM reject causes.
- Registration, service, and PDU session accept/reject result.

Required NGAP fields include:

- Procedure code and semantic procedure name.
- Initiating, successful, or unsuccessful outcome.
- AMF UE NGAP ID and RAN UE NGAP ID.
- PDU session resource IDs.
- NGAP cause group and cause value.
- TAI, PLMN, NR CGI, and transport tunnel information when relevant.
- Request/response frame linkage where possible.

### 5.4 PFCP requirements

Each PFCP message must retain:

- Semantic message type.
- Frame and timestamp.
- Sequence number.
- Request/response relationship.
- CP and UP F-SEID values.
- Session SEID.
- Node IDs.
- PFCP cause.
- PDR, FAR, QER, URR, BAR, F-TEID, QFI, UE IP, DNN/network instance, and S-NSSAI fields needed for diagnosis.
- Missing response or retransmission state.

## 6. Canonical Data Requirements

All decoder outputs must be normalized into a versioned schema:

```json
{
  "schema_version": "2.0",
  "analysis_id": "uuid",
  "events": []
}
```

Every canonical event must have:

- `event_id`: UUID.
- `protocol`: `NAS`, `NGAP`, `HTTP2`, or `PFCP`.
- `frame` and `timestamp`.
- `direction` when known.
- `message_type`.
- `outcome`: `request`, `success`, `failure`, `notification`, or `unknown`.
- `identifiers`: normalized correlation identifiers.
- `attributes`: protocol-specific semantic fields.
- `raw_ref`: source file and JSON path.

The canonical schema is internal to the harness. The model receives a smaller evidence schema, not the complete event collection.

## 7. Tool Requirements

Tools are deterministic Python services with JSON-compatible inputs and outputs. The primary protocol pipeline is fixed. NRF and UDR inspection tools are lazy and may run only after the first model pass returns a schema-valid evidence request. Native provider function calling is not required; the model may emit the request as structured JSON for the orchestrator to validate and execute.

Implementation-ready specifications for T01-T25 are indexed in `tools/README.md`. Each tool file is normative for its detailed contracts, algorithms, failure behavior, tests, and acceptance criteria.

### 7.1 Canonical execution graph

The harness must implement the following dependency graph. Numbering defines dependencies, not a requirement to serialize independent work:

1. Validate the request/configuration, create the run, retain the source PCAP and initialize the run manifest.
2. When scenario text is supplied, run T13 and persist its result. T13 is independent of protocol decoding, but T14 cannot run until both T13 and its deterministic evidence inputs are complete.
3. Run T01, then T02, T03 and T04 in order. T21 classifies capture phases after T04 establishes attempt boundaries.
4. For every persisted attempt, run T05. Run T06, T07 and T08 against only that attempt's assigned primary events; these explicit detectors may run concurrently.
5. Run T09 only after the T06-T08 results for the same attempt are available. T09 consumes those explicit candidates for suppression/linking and must not duplicate them.
6. Build the primary T10 timeline for every attempt. Failed/incomplete attempts may then run T11 against eligible earlier successful attempts and T12 against only their own candidates/comparison. Successful attempts remain available as baselines and report data.
7. When a scenario was supplied, run primary T14 validation after T05 and T09 artifacts exist. Scenario absence produces no scenario-validation stage, not a failure.
8. T17 deterministic reporting is mandatory even when no model provider is configured. T15 and T16 run only for failed/incomplete attempts selected by the configured model-narration policy and only when a provider is enabled.
9. An initial T16 pass may request T24 and/or T25. The orchestrator validates every request before granting a scoped dependency capability. T22 runs only inside T24; T23 runs only inside T24/T25. No hidden NRF/UDR reader is exposed to primary tools.
10. When dependency inspection returns at least one valid admitted outcome, rerun dependency-aware T12 and, where applicable, T14 before building the dependency-expanded T15 packet and invoking one final T16 pass. Final-pass tool requests are rejected.
11. T18, T19 and T20 are on-demand evidence services, not unconditional primary stages. T18 performs capability-scoped lookup, T19 obtains bounded context, and T20 runs only after a validated need for missing decode detail. Their results are immutable derived artifacts and do not silently alter earlier assignments or findings.
12. Run T17 after deterministic processing and any enabled model/dependency work. Persist the final report and manifest status even when optional scenario, provider or dependency stages are absent, disabled, partial or failed.

All per-attempt artifacts and candidate collections must remain keyed by `attempt_id`. A candidate from one attempt must never enter another attempt's ranking merely because both were processed in the same run. Every executed stage must publish its result/revision before the manifest records that stage as complete.

Dependency expansion obeys these additional rules:

- All approved NRF/UDR requests for the selected attempt must reach a terminal inspection status before expanded deterministic processing begins.
- Published inspection results with status `completed`, `empty`, or `partial` and valid integrity/revision metadata are valid expansion inputs. `failed`, unpublished, mismatched or integrity-invalid results remain reportable stage outcomes but cannot enter T12, T14 or T15 evidence.
- T12 must create a new immutable dependency-expanded ranking from the primary ranking, the exact valid inspection-result revisions and their T23 impact/candidates. It must not overwrite the primary ranking.
- T14 creates a new immutable validation only when selected scenario checkpoints depend on inspected NRF/UDR evidence. Unaffected primary checkpoint results remain unchanged and retain their evidence references.
- T15 may build an expanded packet only from the exact initial packet, the dependency-expanded T12 result for that attempt, the applicable latest T14 revision, and the same valid inspection-result revisions. It must reject stale, cross-attempt or incomplete lineage.
- T16 final pass consumes only that validated expanded packet. If no valid inspection result exists, no expanded packet or final pass is created; the initial diagnosis and deterministic report remain usable.
- The report must preserve primary and dependency-expanded revisions, inspection failures/empty results and any change in primary candidate or scenario checkpoint status.

### T01: `decode_capture`

Purpose: Run the Go decoders and validate their output.

The implementation-ready command, schemas, file layout, failure behavior, performance requirements, proposed Go/Python files and tests are defined in `tools/T01_decode_capture.md`. That document is normative for T01.

Inputs:

- PCAP path.
- Analysis output directory.
- Decoder binary path.
- Decoder timeout.

Outputs:

- One UUID-named full JSON document per reconstructed HTTP/2 stream plus `stream_index.jsonl` mapping UUIDs to TCP/HTTP2 stream identities.
- Full NGAP/NAS and PFCP message JSONL files plus message indexes.
- Paths to retained PCAP, raw packet-level output and full reconstructed protocol output.
- Packet/message counts.
- Decoder versions and elapsed times.
- Warnings for absent protocols or malformed/truncated output.
- SHA-256 checksums and byte sizes for all retained source/full artifacts.

Full-output requirements:

- Preserve ordered duplicate HTTP headers, raw body segments, decoded body representations, request/response frames and incomplete/reset state.
- Preserve complete NGAP/NAS and PFCP trees without lean filtering.
- Retain PFCP heartbeats in full output.
- Publish artifacts atomically and publish `decoder_manifest.json` last.
- Do not classify, filter or remove NRF/UDR traffic in T01.

Failure behavior:

- Fail the run when the PCAP is unreadable or all decoders fail.
- Continue as `partial` when one protocol is absent or one decoder fails but useful data remains.

### T02: `normalize_events`

Purpose: Convert decoder-specific trees into canonical semantic events.

Requirements:

- Stream large files; do not load multi-megabyte HTTP/2 files repeatedly.
- Preserve raw references.
- Normalize timestamps and numeric values.
- Produce parser warnings rather than silently discarding unknown fields.
- Extract a compact NAS semantic representation from full NGAP output.
- Build frame, time, protocol, stream and identifier indexes that point back to full/raw records.

Outputs:

- Canonical event store.
- Protocol-specific indexes.
- Unknown-field and extraction statistics.

### T03: `build_identity_graph`

Purpose: Correlate protocol identifiers into UE and session identities.

Inputs considered:

- SUPI, SUCI, GPSI, GUTI and PEI.
- AMF/RAN UE NGAP IDs.
- PDU session ID and procedure transaction ID.
- HTTP SBI correlation headers, SUPI in URI/body, SM context references, charging IDs and NF identifiers.
- PFCP SEIDs, UE IP address, DNN, S-NSSAI and F-TEIDs.
- Timestamp proximity and direction.

Outputs:

- Internal `ue_id` values.
- Identifier aliases with confidence and supporting frames.
- Session links across NAS, NGAP, SBI and PFCP.
- Ambiguous links retained as candidates instead of forced matches.

### T04: `segment_attempts`

Purpose: Divide each UE timeline into independent procedure attempts.

Supported attempt types:

- Registration.
- Deregistration.
- Service request.
- Authentication and security establishment.
- PDU session establishment.
- PDU session modification.
- PDU session release.
- Handover/path switch.
- UE context setup/release.

Requirements:

- Start an attempt from a UE or network initiating event.
- Correlate retries into the same attempt when transaction identity and timing indicate a retry.
- Start a new attempt when a new transaction begins, even if the PDU session ID is reused.
- Close attempts as `succeeded`, `failed`, `aborted`, `timed_out`, or `incomplete_capture`.
- Assign stable attempt sequence numbers per UE and attempt type.

### T05: `get_ue_request`

Purpose: Explain what the UE requested for a selected attempt.

Output fields include:

- Procedure name.
- Registration or service request type.
- DNN.
- PDU session ID and procedure transaction ID.
- PDU type and SSC mode.
- S-NSSAI.
- QoS request.
- Requesting UE identifiers in masked form.
- Source frames and raw references.

If the request cannot be decoded, the tool must report `unknown` with the missing field reason.

### T06: `find_http_failures`

Purpose: Detect SBI failures and anomalies in the primary HTTP partition. NRF and UDR transactions are explicitly excluded.

Checks:

- HTTP `4xx` and `5xx` responses.
- `ProblemDetails` status, cause, title, detail, invalid parameters and supported features.
- Request with no response.
- Reset or incomplete HTTP/2 stream.
- Unexpected status for the API operation.
- Retry loops and repeated failure responses.
- Invalid JSON or malformed multipart body.
- Redirect or routing loop indicators.
- Dependency-suspicion signals visible in the primary flow, without reading hidden NRF/UDR events.

Output candidates must identify the service/API, producer/consumer when inferable, request frame, response frame, status, cause and attempt association.

The tool may emit an NRF/UDR suspicion reason for the model, but it must not claim that NRF or UDR caused the failure before the corresponding inspection tool runs.

HTTP errors must not automatically become call-failure candidates. Each result must also be classified as:

- `attempt_related`: directly correlated to a UE/procedure attempt.
- `dependency_related`: no UE identifier, but part of an NF dependency chain used by the attempt.
- `startup_background`: NF startup, cleanup, registration or deregistration before any UE attempt.
- `concurrent_background`: infrastructure activity occurring during a call but with no supported link to it.
- `post_call_background`: activity after the relevant attempt completed.
- `unresolved_infrastructure`: background failure that remained unresolved when a call began.

### T07: `find_nas_ngap_failures`

Purpose: Detect UE-facing and access-layer failures.

Checks:

- 5GMM and 5GSM reject messages and causes.
- NGAP unsuccessful outcomes and cause IEs.
- Error Indication and NAS Non Delivery Indication.
- PDU session resource setup/modify/release failures.
- UE context setup or release abnormalities.
- Initiating message without an expected outcome, recorded as a request-only observation for T09. T09 is the sole owner of implicit missing-transition/missing-response candidates; T07 must not emit a duplicate candidate for the same absence.
- Required NAS or NGAP transition missing within the attempt.

The tool must distinguish a final UE-facing reject from an earlier network-side cause.

### T08: `find_pfcp_failures`

Purpose: Detect N4/session-programming failures.

Checks:

- PFCP response cause other than accepted.
- Request without response.
- Retransmissions and timeout.
- SEID mismatch or unknown session.
- Failed PDR/FAR/QER/URR creation or update.
- Missing F-TEID, invalid tunnel values, or inconsistent QFI/UE address.
- Session modification or deletion anomalies.

### T09: `detect_missing_transitions`

Purpose: Find implicit failures where no explicit reject/error exists.

Requirements:

- Use procedure state-machine definitions.
- Determine the last completed stage and first missing mandatory stage.
- Differentiate capture truncation from a likely network timeout.
- Support procedure-specific configurable timeouts.

### T10: `get_attempt_timeline`

Purpose: Return a bounded, ordered timeline for one attempt.

Requirements:

- Include only events correlated to the selected attempt.
- Label each event as expected, anomalous, failure, retry, or cleanup.
- Support filters by protocol and frame/time window.
- Default to a maximum of 50 events for internal use and 20 for model evidence.
- Every timeline item must carry references that allow retrieval of the complete retained record.

### T11: `compare_attempts`

Purpose: Compare a failed attempt with prior successful attempts from the same UE.

Requirements:

- Prefer the nearest successful attempt of the same type and request parameters.
- Compare normalized stages rather than raw frame numbers.
- Report the first divergence, changed request values, changed network responses and missing stages.
- Do not treat normal dynamic values such as timestamps, sequence numbers or SEIDs as meaningful differences.

### T12: `rank_root_causes`

Purpose: Select the primary failure and classify secondary symptoms.

Ranking rules:

1. Candidate must belong to the same attempt or have a supported cross-protocol link.
2. Prefer the earliest causal failure before the terminal UE reject.
3. Prefer explicit protocol failure over inferred missing transition.
4. Prefer a candidate that explains downstream failures across protocols.
5. Penalize cleanup/release messages occurring after the attempt already failed.
6. Retain multiple candidates when evidence is ambiguous.
7. Exclude resolved startup/background failures from call root-cause ranking.
8. Promote a pre-call infrastructure failure only when its unresolved state is linked to an NF/service required by the attempt.

Outputs:

- Primary candidate.
- Alternative candidates.
- Downstream symptoms.
- Deterministic confidence and reasons.

### T13: `parse_scenario`

Purpose: Convert optional free text into structured expectations.

Requirements:

- Use the configured model when available.
- Validate model output against a strict schema.
- Allow procedure, expected DNN/S-NSSAI/PDU type, expected outcome and protocol checkpoints.
- Mark unspecified values as unconstrained; do not invent expected values.
- Preserve the original scenario text.

### T14: `validate_scenario`

Purpose: Evaluate scenario checkpoints against deterministic evidence.

Each checkpoint result must be:

- `verified`.
- `failed`.
- `inconclusive`.
- `not_applicable`.

Each result must cite frames and exact observed values. The model may explain results but may not change deterministic checkpoint status without an explicit conflict field.

### T15: `build_evidence_packet`

Purpose: Select bounded model input.

Default limits:

- Maximum five failure candidates.
- Maximum twenty timeline events.
- One UE request object.
- At most two comparison attempts.
- Target 2,000-8,000 input tokens.
- Hard limit 12,000 input tokens for local models.

The packet must contain schema descriptions, evidence IDs and no raw unbounded decoder trees.

### T16: `generate_diagnosis`

Purpose: Ask the configured model to explain deterministic findings.

Requirements:

- Use an OpenAI-compatible client for local endpoints and OpenRouter.
- Require structured JSON output when supported.
- Use low temperature (`0` to `0.2`).
- Instruct the model to use only supplied evidence.
- Validate and retry malformed output once.
- Fall back to deterministic report generation after provider failure.
- Record provider, model, latency and token usage without recording API keys.

### T17: `render_report`

Purpose: Produce `report.json` and `report.md`.

Requirements:

- Deterministic data is authoritative.
- Model narrative is clearly marked.
- Every reported root cause and UE request links to evidence IDs and frames.
- Include partial-data warnings and model/provider errors.

### T18: `lookup_full_evidence`

Purpose: Retrieve complete retained protocol evidence when compact normalization missed a field or when deeper investigation is required.

Supported lookup inputs:

- Event ID, evidence ID, attempt ID or failure-candidate ID.
- Exact frame number.
- Frame range.
- Timestamp and before/after duration.
- TCP stream and HTTP/2 stream ID.
- NGAP UE identifiers.
- PFCP sequence number or SEID.
- Protocol and field-path filters.

Required behavior:

- Resolve normalized records to full/raw records through indexes.
- Return complete HTTP headers and bodies, NGAP/NAS trees, PFCP IEs and decoder metadata.
- Preserve duplicate headers and repeated IEs.
- Return source file, byte/line offset and JSON path for every result.
- Apply configurable result-size limits for callers, while allowing paginated retrieval of the complete record.
- Never modify or replace the retained source artifact.

### T19: `get_packet_context`

Purpose: Retrieve packets before and after an issue to inspect causal context that was not assigned to the same attempt or protocol event.

Inputs:

- Anchor frame or timestamp.
- Frames/seconds before and after.
- Optional protocol/display filter.
- Detail mode: `summary`, `full_protocol`, or `raw_packet`.

Required behavior:

- Default to 20 frames before and after the anchor.
- Read retained raw output when the requested detail is already available.
- Otherwise run bounded `tshark` re-decoding against the retained PCAP.
- Include packet frame, timestamp, endpoints, protocols and complete selected protocol trees.
- Clearly identify packets not correlated to the selected UE/attempt.
- Enforce a maximum window and require pagination/continuation for larger requests.
- Store retrieved context as a derived evidence artifact with its query and source checksum.

### T20: `targeted_redecode`

Purpose: Extract a protocol-correct bounded slice from the retained PCAP and
re-run `tshark` when the original decoder did not request a required protocol
tree or field.

Inputs:

- Frame range or time range.
- Display filter.
- Protocol tree list or explicit field list.
- Decode-as rules when needed.

Required behavior:

- Operate only on the retained source PCAP.
- Use validated argument construction; callers may not supply arbitrary shell commands.
- Enforce and report result-size, decoder-resource and source-scan bounds as
  separate quantities. Pre-slicing may reduce decoder work but must not be
  represented as source-size-independent access unless a validated T01 packet
  index was used.
- Preserve TCP/HTTP2/HPACK state, SCTP/NGAP reassembly, IP fragmentation and
  pcap/pcapng interpretation context. Fail explicitly when required context is
  unavailable, unauthorized or over limit.
- Record source/index/slice checksums, source-frame mapping, extractor and
  `tshark` versions/arguments, context expansion, measured scan/decode cost,
  output checksum and query provenance.
- Remove transient slice/map staging after success or failure without deleting
  the retained source or published evidence.
- Write output under `evidence/redecode/`; never alter original decoded artifacts.
- Register new evidence references so later tools and reports can cite the result.

### T21: `classify_capture_phases`

Purpose: Separate NF/platform startup activity from UE call activity without deleting either.

Phase labels:

- `capture_preamble`: before the first observed UE procedure trigger.
- `attempt_active`: within a specific UE attempt window.
- `between_attempts`: after one attempt and before another.
- `capture_postamble`: after the final observed UE attempt.
- `unknown`: insufficient UE visibility to determine phase.

Requirements:

- Use NAS/NGAP UE procedure triggers as primary call-window anchors.
- Use configurable pre-roll and post-roll around each attempt so immediately preceding dependency calls are not lost.
- Support overlapping attempts from multiple UEs.
- Apply phase labels independently from correlation labels; an event occurring during a call is not necessarily call-related.
- Do not classify the whole capture as preamble when N1/N2 visibility is absent; use `unknown`.
- Preserve all phase-classified events for infrastructure analysis.

### T22: `build_nf_lifecycle`

Purpose: Build the observed lifecycle and readiness state for each NF instance/service throughout the capture.

Invocation: Internal helper for `inspect_nrf_flow`; it must not run as part of the default primary call-flow analysis.

Inputs:

- NRF NF registration, update, heartbeat, status, discovery and deregistration operations.
- NF instance IDs, NF types, FQDNs, IPs, service names and service status.
- SCP routing/delegated-discovery evidence.
- Relevant HTTP status and `ProblemDetails` responses.

Lifecycle states:

- `unknown`.
- `starting`.
- `registered`.
- `available`.
- `degraded`.
- `suspended`.
- `deregistering`.
- `deregistered`.
- `unavailable`.

Required behavior:

- Track state changes by NF instance and service, not only NF type.
- Build an NF readiness snapshot at the start of the selected UE attempt.
- Recognize idempotent startup cleanup patterns.
- Example: pre-call `DELETE /nf-instances/<id>` returning `404`, followed by successful registration of the same instance before the first UE request, is `benign_startup_cleanup`.
- Mark repeated deregistration/cleanup errors as background warnings when followed by healthy registration.
- Mark a pre-call failure `resolved_before_attempt` when a later successful operation restores the required state.
- Mark it `unresolved_at_attempt_start` when no recovery is observed before the attempt.
- Link unresolved state to a call only when the attempt uses, discovers or routes toward that NF/service, or when the missing NF explains a failed dependency.
- Preserve ambiguous cases as infrastructure warnings with `inconclusive` call impact.

### T23: `assess_background_impact`

Purpose: Decide whether startup/background anomalies affected a specific UE attempt.

Invocation: Run only on NRF/UDR evidence returned by an approved lazy inspection request. It must not promote hidden NRF/UDR events before that inspection occurs.

Promotion requirements: at least one strong causal condition must exist:

- The failed background transaction and call dependency reference the same NF instance ID.
- The call requests the same NF service and discovery/selection cannot find an available instance.
- The NF remained unregistered/unavailable at attempt start and the attempt failed at that dependency stage.
- A later call-time error explicitly references the earlier failed lifecycle operation.
- The failed state differs from a previous successful attempt's NF readiness state and is the first meaningful divergence.

Demotion conditions:

- The error was followed by successful registration/readiness before the call.
- It concerns an NF instance or service not used by the attempt.
- It is an expected idempotent cleanup response.
- The call completed successfully despite the anomaly.
- The only relationship is timestamp proximity.

Outputs:

- `call_impact`: `causal`, `contributing`, `unrelated`, or `inconclusive`.
- NF instance/service and lifecycle state at attempt start.
- Recovery frame when resolved.
- Supporting evidence and rationale codes.

### T24: `inspect_nrf_flow`

Purpose: Investigate whether NRF registration, discovery, status or deregistration behavior caused or contributed to a selected UE attempt failure.

Invocation requirements:

- Callable only after the first model diagnosis requests `dependency_type=NRF`.
- Require `attempt_id`, bounded frame/time window, suspicion reason and at least one target such as NF type, service name, NF instance ID, FQDN or consumer NF.
- Reject broad requests for the complete capture when narrower attempt bounds are available.
- Permit one expanded retry only when the first lookup proves a correlation boundary crosses the requested window.
- Require the request rationale to cite a symptom already present in the first evidence packet; generic capture exploration is invalid.

Required analysis:

- Retrieve NRF events from the separate NRF partition.
- Build lifecycle/readiness state only for relevant NF instances and services.
- Include pre-call startup events needed to determine whether a failure recovered before the attempt.
- Correlate discovery results, SCP delegated discovery and the consumer's selected endpoint.
- Distinguish benign startup cleanup from unresolved registration/discovery failure.

Outputs:

- Matching NRF transactions and full-record references.
- Relevant NF lifecycle and readiness at attempt start.
- Recovery status and recovery frame.
- `call_impact`: `causal`, `contributing`, `unrelated`, or `inconclusive`.
- Rationale codes and missing-evidence warnings.

### T25: `inspect_udr_flow`

Purpose: Investigate whether UDR access caused or contributed to a selected UE attempt failure.

Invocation requirements:

- Callable only after the first model diagnosis requests `dependency_type=UDR`.
- Require `attempt_id`, bounded frame/time window, suspicion reason and a target such as subscriber-data operation, resource URI, consumer NF or masked subscriber correlation key.
- Reject unbounded subscriber-wide or capture-wide retrieval.
- Never expose unmasked SUPI, GPSI, authentication material or subscription payloads to a remote provider.
- Require the request rationale to cite a symptom already present in the first evidence packet; generic subscriber-data exploration is invalid.

Required analysis:

- Retrieve UDR events from the separate UDR partition.
- Pair requests and responses and detect `4xx`, `5xx`, timeout, malformed response and retry exhaustion.
- Correlate UDM/PCF/NEF or other consumer-facing failure with the underlying UDR operation.
- Include bounded pre/post context and a prior successful equivalent operation when available.
- Determine whether an earlier startup failure recovered before the UE attempt.

Outputs:

- Matching UDR transactions and full-record references.
- Requested data category and operation, with sensitive values masked.
- Error, retry and recovery summary.
- `call_impact`: `causal`, `contributing`, `unrelated`, or `inconclusive`.
- Rationale codes and missing-evidence warnings.

## 8. Scenario and Procedure-State Requirements

V2 must use a scenario-profile registry rather than one universal call flow. A profile defines the initiating event, expected stages, optional branches, correlation fields, success terminals, failure terminals, timeout rules and capture-visibility requirements.

Every stage must have one applicability classification:

- `mandatory`: absence is a failure when the relevant interface is visible.
- `conditional`: mandatory only when its condition is observed or declared by the scenario.
- `optional`: useful evidence but not required for success.

It may additionally carry `repeatable`, `terminal_success` or `terminal_failure` flags.

The harness must never declare a stage missing solely because that interface was not captured. It must report `inconclusive` when visibility cannot be established.

### 8.1 Registration family

#### Initial registration

Trigger and UE intent:

- NAS Registration Request with registration type `initial registration`.
- Extract SUCI/5G-GUTI, requested NSSAI, UE security capability, follow-on request and access type.

Logical stages:

```text
INITIAL_REGISTRATION_REQUEST
-> AMF_SELECTION_OR_REROUTE (conditional)
-> IDENTITY_PROCEDURE (conditional)
-> AUTHENTICATION
-> NAS_SECURITY_MODE
-> SUBSCRIBER_AND_SLICE_DATA (conditional/repeatable)
-> ACCESS_AND_MOBILITY_POLICY (conditional)
-> INITIAL_CONTEXT_SETUP (conditional)
-> REGISTRATION_ACCEPT
-> REGISTRATION_COMPLETE
-> REGISTERED
```

Failures include Registration Reject, authentication reject/failure, security mode reject, subscriber-not-found, roaming restriction, slice rejection, illegal UE/ME, PLMN/TA restriction, NGAP context setup failure and missing Registration Accept/Complete.

#### Mobility registration update

Trigger and UE intent:

- NAS Registration Request with registration type `mobility registration updating`.
- Usually associated with tracking-area change, access change, capability update, changed NSSAI or inter-AMF mobility.

Logical stages:

```text
MOBILITY_REGISTRATION_REQUEST
-> OLD_CONTEXT_LOOKUP_OR_TRANSFER (conditional)
-> UE_CONTEXT_TRANSFER_BETWEEN_AMFS (conditional)
-> IDENTITY_AUTH_SECURITY_REFRESH (conditional)
-> LOCATION_AND_SUBSCRIPTION_UPDATE
-> SESSION_CONTEXT_TRANSFER_OR_UPDATE (conditional/repeatable)
-> REGISTRATION_ACCEPT
-> REGISTRATION_COMPLETE
-> OLD_CONTEXT_RELEASE (conditional)
-> REGISTERED
```

The profile must identify whether the serving AMF changed and must not interpret normal old-AMF context release as a failure.

#### Periodic registration update

Trigger and UE intent:

- NAS Registration Request with registration type `periodic registration updating`, normally following the periodic update timer.

Logical stages:

```text
PERIODIC_REGISTRATION_REQUEST
-> CONTEXT_VALIDATION
-> OPTIONAL_AUTH_OR_SECURITY_REFRESH
-> OPTIONAL_SUBSCRIPTION_OR_LOCATION_REFRESH
-> REGISTRATION_ACCEPT
-> REGISTRATION_COMPLETE (conditional by observed behavior)
-> REGISTERED
```

The tool must distinguish periodic update from initial/mobility registration and detect repeated periodic-update failures, timer-driven retry loops, context loss and unexpected full re-authentication.

#### Emergency registration

Trigger and UE intent:

- NAS Registration Request with registration type `emergency registration`.
- Extract emergency indication, identity availability, access type and whether normal registration already exists.

Logical stages:

```text
EMERGENCY_REGISTRATION_REQUEST
-> EMERGENCY_AMF_AND_ACCESS_VALIDATION
-> IDENTITY_AUTH_SECURITY (conditional; emergency policy dependent)
-> EMERGENCY_CONTEXT_CREATION
-> REGISTRATION_ACCEPT
-> EMERGENCY_REGISTERED
```

The profile must support limited-service and unauthenticated-emergency variants. Lack of normal subscription data must not automatically be treated as the root cause when emergency policy permits service.

#### Registration over non-3GPP access

The profile must distinguish trusted/untrusted non-3GPP access, N3IWF/TNGF-related context and access-specific registration state. A registration on 3GPP access and one on non-3GPP access may coexist under the same UE and must not be merged into one attempt.

#### Registration failure recovery

The engine must group retransmissions with the same active attempt, recognize a new attempt after backoff or changed registration type, and preserve TAI/PLMN/slice changes between attempts.

### 8.2 Authentication, identity and NAS security family

Supported subprocedures:

- Identity Request/Response.
- Primary authentication through AUSF/UDM.
- Authentication Failure and synchronization failure/resynchronization.
- Authentication Reject.
- Security Mode Command/Complete/Reject.
- Key or security-context refresh during mobility/service procedures.

Logical stages:

```text
AUTH_TRIGGER
-> AUTH_DATA_RETRIEVAL (conditional)
-> AUTH_REQUEST
-> AUTH_RESPONSE_OR_FAILURE
-> AUTH_CONFIRMATION
-> SECURITY_MODE_COMMAND
-> SECURITY_MODE_COMPLETE
```

The root-cause logic must separate UE credential/authentication failures from AUSF/UDM HTTP failures and from NAS security negotiation failures.

### 8.3 Service request and paging family

#### UE-triggered service request

Variants include mobile-originated signalling, mobile-originated data, emergency service request and fallback-related service request.

```text
SERVICE_REQUEST
-> UE_CONTEXT_LOOKUP
-> SECURITY_VALIDATION_OR_REFRESH (conditional)
-> SESSION_USER_PLANE_ACTIVATION (conditional)
-> NGAP_INITIAL_CONTEXT_OR_PDU_RESOURCE_SETUP (conditional)
-> SERVICE_ACCEPT_OR_IMPLICIT_SUCCESS
-> CONNECTED
```

Failures include Service Reject, context not found, security failure, failed PDU resource activation and repeated Service Request without successful transition.

#### Network-triggered service and paging

```text
DOWNLINK_TRIGGER
-> PAGING
-> UE_RESPONSE_OR_SERVICE_REQUEST
-> CONTEXT_AND_USER_PLANE_ACTIVATION
-> DOWNLINK_DELIVERY
```

The harness must correlate repeated paging, paging timeout, UE non-response and successful paging on one access while another access remains idle.

### 8.4 PDU session lifecycle family

#### PDU session establishment

```text
PDU_SESSION_ESTABLISHMENT_REQUEST
-> SMF_SELECTION_AND_SM_CONTEXT_CREATE
-> SUBSCRIPTION_SLICE_POLICY_AND_CHARGING (conditional/repeatable)
-> PFCP_SESSION_ESTABLISHMENT
-> N2_PDU_RESOURCE_SETUP
-> PDU_SESSION_ESTABLISHMENT_ACCEPT
-> USER_PLANE_ACTIVATION
-> ACTIVE
```

Request extraction must include DNN, PDU session ID, PTI, S-NSSAI, requested PDU type, SSC mode, access type, emergency indication, always-on request, QoS rules and EPCO when present.

#### Emergency PDU session establishment

This is a distinct profile, not merely a flag on normal establishment.

```text
EMERGENCY_SESSION_REQUEST
-> EMERGENCY_DNN_AND_SLICE_SELECTION
-> EMERGENCY_SMF_POLICY (conditional)
-> PFCP_SESSION_ESTABLISHMENT
-> N2_RESOURCE_SETUP
-> EMERGENCY_SESSION_ACCEPT
-> EMERGENCY_USER_PLANE_ACTIVE
```

The profile must recognize emergency DNN/configuration, emergency-registration dependency, local emergency routing and policy that differs from normal subscriber service. Normal charging or subscription behavior may be absent and must not be declared missing unless required by the deployment profile.

#### PDU session modification

Supported triggers include UE-requested modification, network-requested modification, QoS change, policy update, charging update, access/tunnel change and handover-related update.

```text
MODIFICATION_TRIGGER
-> SM_CONTEXT_UPDATE
-> POLICY_OR_CHARGING_UPDATE (conditional)
-> PFCP_SESSION_MODIFICATION (conditional)
-> NGAP_PDU_RESOURCE_MODIFY (conditional)
-> NAS_MODIFICATION_COMMAND_OR_ACCEPT
-> MODIFICATION_COMPLETE
-> ACTIVE
```

#### PDU session release

```text
UE_OR_NETWORK_RELEASE_TRIGGER
-> SM_CONTEXT_RELEASE_OR_UPDATE
-> NGAP_RESOURCE_RELEASE (conditional)
-> PFCP_SESSION_DELETION
-> NAS_RELEASE_COMMAND_OR_COMPLETE (conditional)
-> CHARGING_FINALIZATION (conditional)
-> RELEASED
```

The engine must distinguish explicit user release, network policy release, UE deregistration cleanup, handover cleanup and cleanup caused by an earlier failure.

#### SSC and multi-access variants

Profiles must allow SSC mode-specific behavior, IPv4/IPv6/IPv4v6 differences, multiple simultaneous PDU sessions, session and service continuity changes, and access-specific session legs. Dynamic tunnel and address values must be correlated but not treated as failures solely because they changed.

### 8.5 Idle-mode mobility family

Supported scenarios:

- Cell reselection with no core signalling.
- Tracking-area change followed by mobility registration update.
- Periodic registration while idle.
- Paging and UE response.
- UE context release to idle and subsequent service resume.
- Reachability loss and mobile-terminated delivery failure.

The profile must avoid claiming a missing core procedure for pure radio reselection when the PCAP contains no core signalling trigger.

### 8.6 Connected-mode mobility and handover family

#### Xn-based intra/inter-gNB handover

The N2 capture may begin at path switch because preparation occurs over Xn and is not visible.

```text
Xn_HANDOVER_TRIGGER_OR_INFERRED_START
-> TARGET_RADIO_HANDOVER (outside N2 capture; conditional)
-> PATH_SWITCH_REQUEST
-> AMF_SMF_PATH_UPDATE
-> PFCP_TUNNEL_OR_FAR_UPDATE
-> PATH_SWITCH_ACKNOWLEDGE
-> SOURCE_RESOURCE_RELEASE
-> HANDOVER_COMPLETE
```

Absence of N2 Handover Required/Command must not be called a failure for an Xn handover profile.

#### N2-based handover

```text
HANDOVER_REQUIRED
-> TARGET_AMF_SELECTION (conditional)
-> HANDOVER_REQUEST
-> HANDOVER_REQUEST_ACKNOWLEDGE
-> SMF_AND_UPF_PREPARATION (conditional/repeatable)
-> HANDOVER_COMMAND
-> UE_MOVEMENT
-> HANDOVER_NOTIFY
-> PATH_OR_SESSION_UPDATE
-> SOURCE_RESOURCE_RELEASE
-> HANDOVER_COMPLETE
```

Failure branches must include Handover Preparation Failure, Handover Failure, Handover Cancel, target resource failure, tunnel update failure and rollback to source.

#### Inter-AMF handover

```text
HANDOVER_REQUIRED
-> TARGET_AMF_SELECTION
-> UE_CONTEXT_TRANSFER
-> TARGET_HANDOVER_PREPARATION
-> SM_CONTEXT_TRANSFER_OR_UPDATE
-> TARGET_UP_PATH_PREPARATION
-> HANDOVER_COMMAND_AND_NOTIFY
-> REGISTRATION_OR_CONTEXT_CONFIRMATION (conditional)
-> SOURCE_AMF_CONTEXT_RELEASE
-> COMPLETE
```

The identity graph must preserve one UE across source and target AMF UE identifiers and must time-bound identifier reuse.

#### Path switch and tunnel update

The profile must correlate NGAP Path Switch, SBI SM-context update and PFCP FAR/PDR/F-TEID changes. It must detect accepted radio handover followed by failed core path update and distinguish that from radio handover failure.

#### Handover cancellation and rollback

Cancellation or rollback is successful recovery when acknowledged and the source path remains usable. It must not automatically be reported as call failure. Failure is reported when rollback is incomplete, session state is lost or UE service is not restored.

### 8.7 Inter-system and access mobility family

Profiles must support, when visible in the capture:

- 5GS to EPS mobility with N26.
- 5GS to EPS mobility without N26.
- EPS fallback for voice/service continuity.
- Return from EPS to 5GS.
- 3GPP to non-3GPP access mobility and the reverse.
- Access type change while retaining, transferring or re-establishing a PDU session.

The state engine must allow context transfer, mapped EPS/5GS identities, bearer/session conversion and temporary absence of one protocol family. Unsupported or invisible radio-side stages must be marked `not_observed`, not failed.

### 8.8 Roaming family

The harness must first classify the serving context:

- Non-roaming/home PLMN.
- Visited PLMN roaming.
- Home-routed roaming.
- Local breakout roaming.
- Unknown/inconclusive roaming topology.

Classification evidence may include serving/home PLMN, SUCI home network identity, GUAMI/TAI PLMN, NRF/UDM/AUSF/SMF domains, selected DNN/S-NSSAI and SBI routing headers.

#### Roaming registration

```text
VISITED_NETWORK_REGISTRATION_REQUEST
-> V_AMF_SELECTION
-> HOME_AUSF_UDM_AUTH_AND_SUBSCRIPTION (conditional by topology)
-> ROAMING_AND_ACCESS_RESTRICTION_CHECK
-> SLICE_AND_POLICY_RESOLUTION
-> REGISTRATION_ACCEPT_OR_REJECT
-> REGISTERED_IN_VISITED_NETWORK
```

Failures include roaming-not-allowed, PLMN/TA restriction, authentication routing failure, home-network subscriber-data failure, unsupported slice and visited/home policy conflict.

#### Home-routed PDU session

```text
PDU_SESSION_REQUEST_IN_VPLMN
-> V_SMF_SELECTION
-> H_SMF_SELECTION_AND_CONTEXT_CREATE
-> HOME_POLICY_SUBSCRIPTION_AND_CHARGING
-> HOME_AND_VISITED_USER_PLANE_SETUP
-> N9_OR_INTERMEDIATE_PATH_SETUP (conditional)
-> N2_RESOURCE_SETUP
-> PDU_SESSION_ACCEPT
```

The root-cause engine must identify whether failure occurred in the visited network, home network or inter-PLMN path.

#### Local breakout PDU session

```text
PDU_SESSION_REQUEST_IN_VPLMN
-> VISITED_SMF_SELECTION
-> HOME_AUTHORIZATION_OR_SUBSCRIPTION (conditional)
-> VISITED_POLICY_AND_UPF_SETUP
-> N2_RESOURCE_SETUP
-> PDU_SESSION_ACCEPT
```

The profile must not expect H-SMF/N9 stages for local breakout unless evidence indicates their use.

#### Roaming mobility and handover

Handover profiles must remain valid during roaming and account for V-AMF changes, home-routed session anchoring, N9 updates, visited UPF changes and roaming restrictions at the target location.

### 8.9 Deregistration and context-release family

Supported scenarios:

- UE-initiated deregistration.
- Network-initiated deregistration.
- Deregistration for 3GPP access, non-3GPP access or both.
- Implicit deregistration after reachability/context expiry.
- UE context release without deregistration.
- AMF relocation cleanup.

The engine must distinguish successful cleanup from unexpected context loss during an active attempt.

### 8.10 Policy, charging, slice and NF-dependency scenarios

These are correlated subprocedures and may become the primary root cause:

- NRF discovery and NF selection.
- UDM subscriber/session-management data retrieval.
- AUSF authentication.
- NSSF slice selection.
- PCF AM/SM policy association and update.
- CHF charging create/update/release.
- SCP routing and delegated discovery.
- NF timeout, overload, retry and alternate-NF selection.

All dependency traffic is retained in its protocol partition. Detailed NRF and UDR traffic, including failures, is excluded from first-pass model evidence and becomes visible only through an approved inspection request. Other dependency traffic follows the normal evidence compression rules.

When NRF inspection is requested, NF lifecycle/startup traffic must be reported separately from UE-call failures. A pre-call NRF `4xx` is not a call failure solely because it occurred earlier in the capture. It becomes call-relevant only when `inspect_nrf_flow` invokes `assess_background_impact` and establishes the causal link.

Expected startup examples include:

- Deregistering a stale NF instance and receiving `404` because it does not exist.
- Repeated registration/update while an NF process initializes.
- Discovery before all NF services are available, followed by successful readiness before the UE call.

Potentially causal examples include:

- An NF registration fails and never succeeds before the call.
- The required NF service remains suspended or unavailable at attempt start.
- NRF discovery during the call fails because no healthy instance was registered.
- UDR or another dependency starts but remains unavailable when the correlated UE attempt reaches it.

### 8.11 Scenario-profile matching

The engine selects profiles using observed protocol evidence before using free-text scenario input. The optional scenario may constrain or prioritize a profile but must not force evidence into an incompatible flow.

When multiple profiles remain possible, the report must show alternatives, for example:

- Xn handover versus incomplete N2 handover capture.
- Periodic registration versus mobility registration when registration type is unavailable.
- Home-routed versus local-breakout roaming when only the visited side is visible.

### 8.12 Configurability and standards references

Procedure definitions must be data-driven and versioned by 3GPP release/deployment profile. Primary reference families are TS 23.502 for system procedures, TS 24.501 for NAS, TS 38.413 for NGAP and the applicable 29-series SBI/PFCP specifications.

Vendor-specific ordering, optional NF calls and capture-point visibility must be configurable without changing the attempt engine.

## 9. Multiple Attempt Behavior

For a UE that establishes and deletes a session nine times and fails on the tenth establishment:

- Ten establishment attempts must be produced.
- Previous successful attempts must remain separate.
- The tenth attempt must be analyzed using its own NAS transaction, timing and correlated network sessions.
- The nearest equivalent successful attempt should be used as the baseline.
- The report should identify the first stage where attempt ten diverged.
- Later NAS rejection and cleanup should be marked as downstream unless they are the first explicit failure.

## 10. Model Provider Requirements

V2.1 uses an OpenAI-compatible provider contract:

```yaml
provider: local | openrouter | none
base_url: string
api_key_env: string
model: string
timeout_seconds: 120
temperature: 0.1
max_output_tokens: 2000
max_input_tokens: 12000
```

Provider behavior:

- `local`: API key optional; suitable for vLLM, Ollama OpenAI endpoint or LM Studio.
- `openrouter`: API key mandatory.
- `none`: deterministic tools and report only.

No provider-specific logic may leak into protocol tools.

## 11. Non-Functional Requirements

### Performance

- Decoder processing must remain streaming.
- Normalization must parse each decoder output once per run.
- Model input generation must not depend on total PCAP size after indexing.
- One-PCAP analysis must not require the full decoded data in model context.
- Retaining full data must not require repeatedly parsing it; indexes must support bounded lookup by frame, stream and identifier.
- Targeted re-decoding must be bounded and invoked only when retained output is insufficient.

### Reliability

- A model outage must not discard deterministic findings.
- Partial protocol visibility must be reported explicitly.
- Re-running the same PCAP and configuration must produce the same deterministic findings.
- Full/raw artifacts must be checksummed and immutable after finalization.
- Missing or corrupted retained artifacts must be reported before evidence lookup.

### Security and privacy

- Mask SUPI, GPSI, PEI and IP addresses in model evidence by default.
- Allow unmasked local-only analysis through explicit configuration.
- Never send data to OpenRouter unless the provider is explicitly selected.
- Never log API keys or authorization headers.
- Remove HTTP authorization and client-certificate headers from model evidence.

### Observability

Record timings and counts for:

- Decode.
- Normalize.
- Correlate.
- Attempt segmentation.
- Failure detection.
- Evidence building.
- Model inference.
- Report rendering.

## 12. Acceptance Criteria

V2.1 is accepted when it can:

1. Analyze a PCAP containing HTTP/2, NGAP/NAS and PFCP.
2. Identify more than one UE in a capture without mixing their attempts.
3. Separate repeated PDU session establishment/release cycles for one UE.
4. Correctly describe DNN, S-NSSAI, PDU type and session ID requested by the UE when present.
5. Detect explicit HTTP, NAS/NGAP and PFCP failures.
6. Detect an unanswered request or missing mandatory transition.
7. Identify the tenth failed attempt independently from nine prior successes.
8. Compare the failed attempt with the nearest successful equivalent attempt.
9. Produce useful deterministic output when no model is configured.
10. Produce the same report schema using a local OpenAI-compatible model or OpenRouter.
11. Cite frame-level evidence for all major conclusions.
12. Keep local-model evidence within the configured token budget.
13. Distinguish initial, mobility, periodic, emergency and non-3GPP registration attempts.
14. Apply emergency-specific conditional requirements without treating absent normal subscription/charging stages as automatic failure.
15. Distinguish Xn, N2 and inter-AMF handover and classify successful rollback separately from failed mobility.
16. Correlate path-switch NGAP, SBI and PFCP tunnel updates and identify the first failed domain.
17. Classify home, visited, home-routed and local-breakout roaming sufficiently to avoid applying the wrong expected stages.
18. Return `inconclusive`, rather than a false failure, when a mandatory stage belongs to an interface that was not visible in the capture.
19. Retrieve the complete original decoded record for any report evidence or failure candidate.
20. Retrieve configurable pre/post packet context around an issue without loading the complete capture into model context.
21. Perform a bounded targeted re-decode from the retained PCAP when a required field was not present in the initial decoder output.
22. Keep detailed NRF and UDR transactions out of the first model evidence packet, regardless of success or failure.
23. Allow the first model pass to request `inspect_nrf_flow` or `inspect_udr_flow` only through a schema-valid, bounded and justified evidence request.
24. Keep pre-call NRF/NF lifecycle `4xx` responses as background evidence when an NRF inspection shows that they recovered before the attempt.
25. Promote an unresolved pre-call NF or UDR failure only after the requested inspection links the same dependency to the failed attempt.
26. Produce an NRF readiness snapshot only for the NF instances/services selected by an approved NRF inspection request.
27. Complete diagnosis without reading detailed NRF/UDR flows when the model makes no dependency evidence request.
