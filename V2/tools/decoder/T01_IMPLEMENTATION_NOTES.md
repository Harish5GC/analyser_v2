# T01 `decode_capture` — Implementation Notes & Reference-Code Review

> **Who this is for.** A developer who has *not* worked on this codebase before
> and may be new to Go and/or to PCAP decoding. Read this top-to-bottom before
> writing any code. It tells you what the tool must do, exactly how much of the
> old (reference) decoder you can reuse, and gives line-anchored review comments
> on the old code so you know what to keep, change, move, or delete.
>
> **Normative source.** The contract you must satisfy is
> [`T01_decode_capture.md`](./T01_decode_capture.md). If anything here disagrees
> with that file, that file wins. These notes are the "how", that file is the
> "what".
>
> **Old code.** The previous working decoder lives in `../reference/`:
> `AnalyseCapture.go`, `http2_decoder.go`, `ngap_decoder.go`, `pfcp_decoder.go`.
> It *works* and decodes the same protocols, but it was built for a different
> output shape (one model prompt) and is **not** spec-compliant. We reuse its
> decoding plumbing and throw away its output/filtering layer.

---

## 0. The one paragraph you must internalize

T01 is a **dumb, faithful decoder**. It takes a PCAP, runs `tshark` three times
(HTTP/2, NGAP/NAS, PFCP), and writes **everything tshark saw** to disk in a
fixed directory tree, plus a checksummed `decoder_manifest.json` that lists what
it wrote. It does **not** interpret, filter, classify, mask, drop heartbeats,
strip fields, decide what is NRF vs UDR traffic, or call any AI model. Every
"this looks unimportant, let me clean it up" instinct from the old code is a
**bug** in V2 — that cleanup is somebody else's job (normalization / T02+).
Our job is *lossless capture of the decode* + *provable integrity* of the files.

The single biggest mental shift from the reference code: the old code's whole
reason to exist was to produce a small "lean" JSON for an LLM prompt. **V2 deletes
that entire lean/sanitize layer.** What's left — the tshark streaming loop, the
packet-walking helpers, the HTTP/2 stream state machine — is the part we keep.

---

## 1. Big-picture data flow

```
                Python (V2/harness/decoder/)                 Go binary (V2/tools/*.go)
                ─────────────────────────────                ─────────────────────────
  caller ──▶ runner.py
              │  validate request (DecodeCaptureRequest)
              │  copy PCAP → run/source/capture.pcap (+ source_manifest.json)
              │  build argv (NO shell)            ──────────▶ decode_command.go
              │                                                │  parse flags → DecodeConfig
              │                                                │  check tshark present + version
              │                                                │  for each protocol (concurrently):
              │                                                │     tshark_runner.go streams JSON
              │                                                │     <proto>_decoder.go parses packets
              │                                                │       → raw/<proto>.packets.jsonl   (tee, verbatim)
              │                                                │       → full/... documents
              │                                                │     artifact_writer.go: staging→atomic rename
              │                                                │  mint T01 revision (RevisionEnvelope)
              │   read & VALIDATE  ◀──────────────────────────┤  write decoder_manifest.json LAST
              │   decoder_manifest.json                        │  exit 0 / 2 / 3 / 4 / 5 / 6
              ▼
        DecodeCaptureResult (status success|partial|failed)
```

Two processes, one contract file (`decoder_manifest.json`). **Python never
trusts the Go exit code alone** — it re-reads the manifest, re-checksums every
file the manifest references, and rejects anything that doesn't match.

### 1.1 Output tree you must produce (spec §6)

```
run/
  source/
    capture.pcap
    source_manifest.json
  decoder/
    decoder_manifest.json          ← written LAST, after everything else validates
    raw/
      http2.packets.jsonl          ← one raw tshark packet per line, verbatim
      ngap.packets.jsonl
      pfcp.packets.jsonl
    full/
      http2/
        streams/<uuid>.json        ← ONE file per HTTP/2 stream (the big change)
        stream_index.jsonl         ← lookup table; consumers read this, not the dir
      ngap/
        messages.jsonl             ← one NGAP message per line
        message_index.jsonl
      pfcp/
        messages.jsonl             ← one PFCP message per line
        message_index.jsonl
    indexes/
      packet_access_index.bin      ← OPTIONAL (only if --packet-access-index=true)
      packet_access_index.json
  staging/                         ← write here first, then atomic-rename into decoder/
```

---

## 2. Reuse verdict at a glance

Legend:
- **KEEP** — copy almost as-is (maybe rename/move to a shared file).
- **ADAPT** — the skeleton is good, change the body to meet the new schema.
- **MOVE** — this logic is correct *but belongs in normalization (T02+), not T01*. Delete it from the decoder; it is not your job.
- **DELETE** — not needed in V2 at all.
- **NEW** — no reference equivalent; you write it from scratch.

| Reference location | What it does | Verdict | Why |
|---|---|---|---|
| `AnalyseCapture.go` `main`/`printUsage` dispatch | CLI command switch | **ADAPT → `decode_command.go`** | Need a real `decode` subcommand with flags (§5), not positional args. Keep old commands as thin compat wrappers during migration (spec §19). |
| `AnalyseCapture.go` `runAnalyze` goroutine fan-out | runs 3 decoders concurrently | **KEEP (pattern)** | Concurrency model is fine. But collect a **per-protocol status**; never `os.Exit` on the first protocol error (§5.1, §14). |
| `AnalyseCapture.go` `runCommand`, `run_openrouter.py` call | invokes the model | **DELETE** | T01 must not invoke a provider (spec §1, §19, AC#10). |
| `AnalyseCapture.go` `writeCombinedJSON`/`readJSONFile` | merges lean outputs into `combined.json` | **DELETE** | Aggregate combined output is not in the V2 tree. |
| `AnalyseCapture.go` `exec.Command("tshark", …)` | spawns tshark | **ADAPT → `tshark_runner.go`** | Must use `exec.CommandContext` so the Python wall-clock timeout can kill the child process group (§5, §16). |
| `http2_decoder.go` streaming loop (`json.Decoder.Token()` + `decoder.More()`) | streams tshark JSON without loading it all | **KEEP** | This is the correct low-memory pattern (§15). Reuse verbatim. |
| `http2_decoder.go` `streamState` machine | tracks req/resp per stream | **ADAPT → keep idea, new fields** | Add UUID, frames, times, both end_stream flags, rst_stream, completion state (§8, §9, §9.3). |
| `http2_decoder.go` `StreamHTTPMapToJSONMap` + `ConvertNDJSONToJSONMaps` | temp NDJSON → aggregate JSON map (2 passes) | **DELETE** | Spec forbids the temp-file + second aggregate pass (§15). Replace with one atomic UUID document per stream (§7, `http2_stream_writer.go`). |
| `http2_decoder.go` `extractHeaders` (→ `map[string]string`) | collects headers | **ADAPT** | Must become **ordered `[]Header` preserving duplicates and frame** (§9.1). A map silently drops duplicate header names — that's a data-loss bug in V2. |
| `http2_decoder.go` `extractBody` | decodes JSON, returns decoded only | **ADAPT** | Must keep **raw bytes (hex) per segment + sha256 + byte_length**, and store `decoded_json` only as an *extra* field, never as a replacement (§9.2). |
| `http2_decoder.go` `extractMultipartJSON`/`parseMultipart*` | splits multipart, keeps JSON parts | **ADAPT** | Keep the boundary-splitting logic, but retain **every** part body (incl. binary) + part metadata; record parse failures as warnings, don't drop bytes (§9.2). |
| `http2_decoder.go` `buildLeanConversation`, `dropHeaders`, `requestHeaderDrop`, `responseHeaderDrop`, `extraLean*`, lean structs | strips headers, drops NRF/UDR non-error flows | **MOVE → normalization** | This literally filters `/nnrf-`/`/nudr-` traffic and removes auth/SBI headers. Spec §1 says NRF/UDR partitioning happens later; §9.1 says never remove auth/SBI from full output. **Delete from T01.** |
| `http2_decoder.go` `epochToTimeOnly`/`trimTimestamp` | turns epoch into time-of-day string | **DELETE** | Throws away the date! Spec requires the **full absolute Unix-epoch decimal string with source precision** (§9, §10, §11, §13). Keep `frame.time_epoch` verbatim. |
| `http2_decoder.go` helpers: `getPacketLayers`, `getTCPStreamFromLayers`, `getHTTP2Entries`, `getStreamID`, `getEndStreamFlag`, `isPushPromise`, `findNestedKey`, `stringifyLayerValue`, `getLayerString`, `decodeHexColon` | packet-tree navigation | **KEEP → move to `tshark_layers.go` (shared)** | Pure, reusable tree-walking utilities. NGAP/PFCP decoders already call some of them. |
| `http2_decoder.go` `isResponseBody` (port 80/443 heuristic) | guesses which side a bare DATA frame belongs to | **ADAPT (low-confidence)** | Keep as a fallback, but when guessing, attach a completion warning rather than asserting. |
| `ngap_decoder.go` streaming loop | streams NGAP packets | **KEEP** | Same good streaming pattern. |
| `ngap_decoder.go` writes `[ ... ]` array | aggregate JSON array | **ADAPT** | Must become `messages.jsonl` (one object/line) + `message_index.jsonl` (§10). |
| `ngap_decoder.go` `sanitizeNGAPMapFull` | strips `ngap.` prefix, `[Grouped IE]`, regroups keys | **MOVE → normalization** | "Full" must be the **complete, untouched tshark NGAP tree** (§10: "must not strip PER blocks or unknown IEs"). Renaming keys is lossy. Write the raw layer. |
| `ngap_decoder.go` `stripPERBlocksMap`/`mapLeanKey`/`shouldDropLeanKey`/`filterFlagOnes`/`shouldDropColonValue` | the "lean" NGAP, drops NAS PDUs and PER | **MOVE → normalization / DELETE from T01** | §10 forbids stripping; embedded NAS must be **retained**. This is the opposite of what T01 must do. |
| `pfcp_decoder.go` streaming loop | streams PFCP packets | **KEEP** | Same pattern. |
| `pfcp_decoder.go` `isPFCPHeartbeat` *skip* | drops heartbeat msg_type 1/2 | **DELETE the skip** | §11: heartbeats must remain in full output. You may still *detect* a heartbeat, but never drop it. |
| `pfcp_decoder.go` `sanitizePFCPMap`/`applySpecialIETransforms`/`enumLabelOrValue`/`pfcpMsgTypeName`/`buildFlagOnes` | semantic IE cleanup + enum naming | **MOVE → normalization** | §11: preserve the complete tshark PFCP tree; preserve msg type/cause/SEID **as observed**. Translating `msg_type` 1→"HbReq" is interpretation — not T01's job. |
| `ngap`/`pfcp` `extractFlowMeta` use | builds `{frame,time,src,dst}` | **ADAPT** | Need full epoch (not time-only), src+dst IP, and transport ports / SCTP / SEID per protocol (§9/§10/§11). |
| — | manifest, descriptors, checksums, revision, atomic writer, packet-access index, config parsing, Python wrapper | **NEW** | None of this exists in the reference. This is the bulk of the new work. |

**Rough split:** ~30% of the reference code is reused (streaming loops + tree
helpers + HTTP/2 state-machine skeleton). ~30% is deleted/moved (the entire
lean/sanitize/filter/model layer). ~40% is brand-new (manifest, descriptors,
revision, atomic publication, per-stream UUID docs, raw retention, packet-access
index, Python wrapper).

---

## 3. Files you will create

### 3.1 Go (in `V2/tools/`)

Matches spec §17. Suggested order of creation is the order below.

| File | Responsibility | Start from |
|---|---|---|
| `version.go` | build version, schema version `"2.0"`, `go_version`. | NEW (tiny) |
| `tshark_layers.go` | shared packet-tree helpers. | KEEP from `http2_decoder.go` (move the helper funcs here) |
| `tshark_runner.go` | `exec.CommandContext` wrapper; stream stdout JSON tokens; capture bounded stderr; report tshark version. | ADAPT from the 3 decoders' tshark setup |
| `decode_config.go` | validated `DecodeConfig` (paths, protocols, flags). | NEW |
| `decode_command.go` | parse argv → `DecodeConfig`; orchestrate decoders concurrently; collect per-protocol status; set exit code. | ADAPT from `AnalyseCapture.go` |
| `artifact_writer.go` | `staging/` write, flush, fsync, atomic rename, sha256 + byte size + record count; build `ArtifactDescriptor`/`CollectionDescriptor`. | NEW |
| `decoder_manifest.go` | manifest struct + `RevisionEnvelope` digest + manifest-last publication. | NEW |
| `http2_decoder.go` | parse HTTP/2 packets into `streamState`; tee raw; emit completed/incomplete streams. | ADAPT from reference |
| `http2_stream_writer.go` | turn a finished `streamState` into a `<uuid>.json` document + a `stream_index.jsonl` entry. | NEW |
| `ngap_decoder.go` | stream NGAP/NAS; write `messages.jsonl` + `message_index.jsonl`; tee raw. | ADAPT |
| `pfcp_decoder.go` | stream PFCP; write `messages.jsonl` + `message_index.jsonl`; tee raw; keep heartbeats. | ADAPT |
| `packet_access_index.go` | OPTIONAL frame/time/offset index for T20. | NEW (do last) |
| `AnalyseCapture.go` | keep `http2`/`ngap`/`pfcp`/`analyze` as compat wrappers during migration, minus the model call. | ADAPT |

### 3.2 Python (in `V2/harness/decoder/`)

Matches spec §18.

| File | Responsibility |
|---|---|
| `runner.py` | `DecodeCaptureRequest → DecodeCaptureResult`; the only thing the orchestrator imports. |
| `command.py` | build the Go argv as a list (never a shell string). |
| `manifest.py` | Pydantic models mirroring `decoder_manifest.json`. |
| `validation.py` | path-safety, checksum, byte-size, record-count, schema-version, collection-member checks. |
| `errors.py` | typed fatal vs partial decoder errors. |

---

## 4. Step-by-step build order (do it in this sequence)

You can demo progress at each step. Don't try to write everything at once.

1. **`version.go` + `tshark_runner.go`** — get a context-aware tshark spawn that
   streams JSON and reports `tshark --version`. Prove you can read packets.
2. **Move helpers to `tshark_layers.go`** — lift the KEEP-marked helper funcs out
   of the reference `http2_decoder.go` unchanged. Compile.
3. **`decode_config.go` + `decode_command.go`** — parse the flags from spec §5,
   resolve+validate `--output-dir`, create `staging/`. No decoding yet; just
   prove arg parsing and exit codes 2/6.
4. **`artifact_writer.go`** — staging write → fsync → atomic rename → sha256.
   Unit-test it in isolation (write a file, check the descriptor).
5. **`pfcp_decoder.go`** (do PFCP first — it's the simplest: flat per-packet
   records). Stream → build a full record per packet → write `messages.jsonl`
   via the writer → emit `message_index.jsonl`. Tee `raw/pfcp.packets.jsonl`.
6. **`ngap_decoder.go`** — same shape as PFCP but keep the embedded NAS subtree.
7. **`http2_decoder.go` + `http2_stream_writer.go`** — the hard one. Port the
   state machine, add the new fields and completion states, write one UUID doc
   per stream + `stream_index.jsonl`.
8. **`decoder_manifest.go`** — gather all descriptors, mint the revision, write
   the manifest **last**.
9. **Python wrapper** (`runner.py` etc.) — drive the binary, read + validate the
   manifest, return `DecodeCaptureResult`.
10. **`packet_access_index.go`** — only after everything else passes; it's gated
    behind the `bounded_targeted_redecode` capability and is optional.

---

## 5. The Go structs you need (target schema, not reference)

These mirror spec §8–§13. Use Go structs with `json` tags; field names below are
the JSON keys.

```go
// ---- shared ----
type Endpoint struct {
    IP   string `json:"ip"`
    Port int    `json:"port"`
}

type Header struct {
    Name  string `json:"name"`
    Value string `json:"value"`
    Frame int    `json:"frame"`
}

type BodySegment struct {
    Frame  int    `json:"frame"`
    RawHex string `json:"raw_hex"`
}

type Body struct {
    ByteLength  int           `json:"byte_length"`
    SHA256      string        `json:"sha256"`
    ContentType string        `json:"content_type,omitempty"`
    Segments    []BodySegment `json:"segments"`
    DecodedJSON any           `json:"decoded_json,omitempty"` // EXTRA, never a replacement
}

// ---- HTTP/2 full document (spec §9) ----
type HTTP2Transport struct {
    TCPStream     *int     `json:"tcp_stream"`
    HTTP2StreamID *int     `json:"http2_stream_id"`
    OriginalKey   string   `json:"original_key"`
    Client        Endpoint `json:"client"`
    Server        Endpoint `json:"server"`
}

type HTTP2Side struct {
    StartFrame     int      `json:"start_frame"`
    EndFrame       int      `json:"end_frame"`
    StartTimeEpoch string   `json:"start_time_epoch"` // decimal STRING, full precision
    EndTimeEpoch   string   `json:"end_time_epoch"`
    Headers        []Header `json:"headers"`
    Method         string   `json:"method,omitempty"`  // request only
    URI            string   `json:"uri,omitempty"`      // request only
    Status         *int     `json:"status,omitempty"`   // response only
    Body           *Body    `json:"body,omitempty"`
}

type HTTP2Completion struct {
    State            string   `json:"state"` // see §9.3 enum
    RequestEndStream bool     `json:"request_end_stream"`
    ResponseEndStream bool    `json:"response_end_stream"`
    RstStream        bool     `json:"rst_stream"`
    CaptureTruncated bool     `json:"capture_truncated"`
    Warnings         []string `json:"warnings"`
}

type HTTP2Document struct {
    SchemaVersion string          `json:"schema_version"` // "2.0"
    DocumentID    string          `json:"document_id"`    // UUIDv4 == filename
    Protocol      string          `json:"protocol"`       // "HTTP2"
    Transport     HTTP2Transport  `json:"transport"`
    Request       *HTTP2Side      `json:"request,omitempty"`
    Response      *HTTP2Side      `json:"response,omitempty"`
    Completion    HTTP2Completion `json:"completion"`
    SourceFrames  []int           `json:"source_frames"`
}
```

For NGAP/PFCP `messages.jsonl`, each line is a record with: a record UUID, frame
number, full epoch timestamp **string** + precision metadata, src/dst IP, the
transport block (SCTP for NGAP, UDP ports for PFCP), the **complete untouched**
protocol tree (`ngap`/`pfcp` layer exactly as tshark emitted), embedded NAS for
NGAP when present, decode warnings, and a reference to the raw record. Define a
small `MessageRecord` struct and put the raw tshark layer in an `any` field —
do **not** run it through any sanitize function.

The index-entry struct for HTTP/2 is given verbatim in spec §8
(`HTTP2StreamIndexEntry`); mirror it. NGAP/PFCP index entries are simpler:
`{record_id, relative_path?, frame, time_epoch, message_type, ...key fields..., sha256}`.

---

## 6. Inline review comments on the reference code

These are written as if reviewing a PR that proposed copying the reference files
into `tools/` unchanged. Each comment is anchored to a file + line so you can
open it side by side.

### 6.1 `reference/AnalyseCapture.go`

- **L18–58 `main` (positional args):** ⚠️ *Change required.* V2 needs a `decode`
  subcommand with the flags in spec §5 (`--analysis-id`, `--output-dir`,
  `--protocol`, `--format`, `--retain-raw`, `--packet-access-index`,
  `--parallel`, `--tshark`). Move parsing into `decode_command.go`/`decode_config.go`.
  Keep `http2`/`ngap`/`pfcp`/`analyze` cases as compat wrappers (spec §19) but
  strip the model call.
- **L33–48 fixed filenames (`decoded_http2_httpmap.json`, …):** 🔴 *Blocker.*
  Spec §2 explicitly calls this out. All output paths derive from validated
  `--output-dir`/`decoder/`. No filenames in the CWD.
- **L84–137 `runAnalyze`:** ✅ Keep the `sync.WaitGroup` + 3 goroutines pattern.
  🔴 But **L110–121** `os.Exit(1)` on the first protocol error violates §14
  ("one protocol fails while another succeeds → publish valid artifacts, mark
  `partial`"). Collect a `ProtocolResult{status, counts, warnings}` per protocol
  instead; decide the overall exit code after all three return.
- **L123–136 offline/openrouter branch:** 🔴 *Delete.* No model invocation, no
  `combined.json` (spec §1, §19, AC#10).
- **L139–144 `runCommand`:** 🔴 *Delete* (only used to call the model).
- **L146–189 `readJSONFile`/`writeCombinedJSON`:** 🔴 *Delete.*
- **General:** the three `exec.Command("tshark", …)` calls have **no
  `context.Context`** → the Python timeout can't cleanly kill tshark. Move to
  `exec.CommandContext` in `tshark_runner.go` (§5, §16) and ensure child
  processes die on cancel (`cmd.Cancel` / process-group kill).

### 6.2 `reference/http2_decoder.go`

- **L22–30 `leanIncludeRequestEpochMeta`, `extraLean`, `extraLeanHeaderDrop`
  (drops `authorization`, `3gpp-sbi-*`):** 🔴 *Delete from T01.* §9.1: never
  remove authorization or 3GPP SBI headers from full output. Masking happens only
  when model evidence is built (a different tool).
- **L36–65 `HTTPMessage`/`FlowMeta`/`HTTPConversation`/lean structs:** ⚠️
  *Replace.* `Headers map[string]string` drops duplicate header names and order
  (§9.1 forbids this). `FlowMeta` only has request-side `frame/time/src/dst`;
  §9 needs both client and server endpoints **with ports**, and both
  request and response timing. Use the structs in §5 above.
- **L78–93 `StreamHTTPMapToJSONMap` (temp NDJSON → aggregate):** 🔴 *Delete.*
  §15: "Do not create a temporary NDJSON file followed by a second aggregate
  conversion pass." Replace with: on stream completion, hand the `streamState`
  to `http2_stream_writer.Publish()` which writes one `<uuid>.json` atomically.
- **L95–172 `streamHTTPMapToNDJSON`:** ✅ Keep the streaming spine
  (`json.NewDecoder(stdout)`, `decoder.Token()`, `for decoder.More()`). 🔴 Add:
  tee each raw packet to `raw/http2.packets.jsonl` **before** semantic
  processing (§12). ⚠️ The `-Y` filter at **L99** intentionally selects only
  HEADERS/DATA/RST/etc.; double-check it still admits RST_STREAM (type 3) and
  GOAWAY if you need to detect `reset`/`truncated` states (§9.3).
- **L174–298 `ConvertNDJSONToJSONMaps`:** 🔴 *Delete entirely* (second pass +
  aggregate map + inline lean build).
- **L300–400 `processPacketForHTTPMap`:** ⚠️ *Adapt — this is the keeper logic.*
  Good: per-`tcp.stream:streamid` keying (§8), req/resp classification by
  `:method`/`:status`, end_stream tracking. Changes:
  - **L316** keep `key` as `original_key`, but the **filename is a fresh UUIDv4**
    (§6). Never name the file after the key.
  - **L323 `extractHeaders`** must return ordered `[]Header` with frame, keeping
    duplicates (see L507 comment).
  - **L329–344** capture `request.start_frame/start_time_epoch` from the first
    request frame and `end_*` from the last; same for response. Right now only a
    single `Meta` is stored.
  - **L349 `extractBody`** must preserve raw segments (see L563 comment).
  - **L395–398 completion rule** (`RespEnded && (ReqEnded || !ReqBodySeen)`) is a
    rough "done" heuristic. Replace with explicit completion-state assignment
    (§9.3): `complete`, `request_only`, `response_only`, `reset`,
    `truncated_capture`, `incomplete`. Track `rst_stream` and both `end_stream`
    flags separately.
- **L411–416 `writeHTTPMapEntry`:** 🔴 *Delete* (writes the aggregate entry).
  Replaced by the stream writer.
- **L427–445 `extractFlowMeta` + use of `epochToTimeOnly`:** 🔴 *Bug for V2.*
  `epochToTimeOnly` (L897) discards the **date** and keeps only time-of-day.
  §9/§10/§11/§13 require the full absolute Unix-epoch decimal string with source
  precision. Read `frame.time_epoch` and store it **verbatim** as a string.
- **L447–505 `getPacketLayers`/`getTCPStreamFromLayers`/`getHTTP2Entries`/
  `getStreamID`:** ✅ *Keep, move to `tshark_layers.go`.*
- **L507–528 `extractHeaders`:** ⚠️ *Rewrite.* It returns `map[string]string`,
  collapsing duplicate header names and losing order/frame. Iterate the
  `http2.header` list in order, emit one `Header{name,value,frame}` per entry,
  keep duplicates and pseudo-headers (§9.1).
- **L563–605 `extractBody`:** 🔴 *Rewrite (data loss).* It returns only decoded
  JSON / a string and **discards the original bytes**. §9.2: keep raw bytes as
  hex per segment, compute `byte_length` + `sha256`, and store `decoded_json`
  only as an additional field. Keep `decodeHexColon` (L768) to get raw bytes,
  but hex-encode and store them; don't throw them away after JSON-parsing.
- **L617–633 `isResponseBody`:** ⚠️ *Adapt.* Port 80/443 heuristic is fragile.
  Keep as a last resort and, when used, append a completion warning (§8 "must
  not invent a high-confidence key").
- **L635–703 `isPushPromise`/`findPromisedStreamID`/`findStringByKeyContains`:**
  ✅ Keep push-promise skip; the promised-stream-id helpers are fine to keep but
  unused unless you choose to model pushes.
- **L705–774 `getLayerString`/`stringifyLayerValue`/`findNestedKey`/
  `decodeHexColon`:** ✅ *Keep, move to `tshark_layers.go`.*
- **L776–852 multipart parsing:** ⚠️ *Adapt.* Logic for finding the boundary and
  splitting parts is reusable, but it only keeps JSON parts and drops the rest.
  §9.2: retain **every** part body (including binary) and part metadata; record
  malformed parts as warnings; never drop bytes.
- **L854–895 `buildLeanConversation`:** 🔴 *Delete / move to normalization.*
  **L862–866** filters out `/nnrf-` and `/nudr-` non-error flows — this is NRF/UDR
  partitioning, which §1 explicitly defers to `normalize.partition_router`.
- **L897–949 `epochToTimeOnly`/`trimTimestamp`/`isEmptyHTTPMessage`/
  `requestHeaderDrop`/`responseHeaderDrop`:** 🔴 *Delete* (timestamp truncation +
  header dropping are both forbidden in full output).
- **L951–1000 `dropHeaders`/`getHeaderValueIgnoreCase`/`getEnvBool`:** 🔴
  *Delete `dropHeaders`* (header stripping). `getHeaderValueIgnoreCase` may be
  reused. `getEnvBool` is fine but prefer explicit flags over env vars in V2.

### 6.3 `reference/ngap_decoder.go`

- **L35–52 tshark setup (`-Y ngap`, `-J frame ip ipv6 sctp ngap`):** ✅ Keep the
  field set; move spawn to `tshark_runner.go` with context. Confirm SCTP fields
  needed for §10 transport metadata are included.
- **L94–101, L173–180 array framing `[ … ]`:** 🔴 *Change.* Write `messages.jsonl`
  (one object per line) + `message_index.jsonl`, not one big array (§10). JSONL
  lets each line be independently addressable and lets you checksum/count
  cheaply.
- **L120 `fullLayer := sanitizeNGAPMapFull(ngapLayer)`:** 🔴 *Remove the
  sanitize for the full output.* §10: "The full writer must not strip PER blocks
  or unknown IEs." Write the **raw** `ngapLayer` as the complete tree. Move
  `sanitizeNGAPMapFull` (L216–270) to normalization if it's still wanted there.
- **L121 `leanLayer := stripPERBlocksMap(...)` + L146–168 lean writer:** 🔴
  *Delete from T01.* A derived lean/compat file is allowed only when explicitly
  requested and must never replace full output (§10). Don't produce it by default.
- **L123–126 entry shape `{meta, ngap}`:** ⚠️ *Expand* to the §10 required
  fields: record UUID, frame, full epoch + precision, src/dst IP + SCTP, raw
  record reference, decode warnings, and the embedded NAS subtree **retained**.
- **L272–445 `stripPERBlocksMap`/`mapLeanKey`/`shouldDropLeanKey`/
  `filterFlagOnes`/`normalizeFlagValue`/`shouldDropColonValue`:** 🔴 *Move to
  normalization.* **L401–410** explicitly drops `nas_pdu`/`nas-5gs` etc. — the
  exact opposite of §10's "preserve embedded NAS." None of this belongs in T01.
- 🔴 *Add* raw tee to `raw/ngap.packets.jsonl` (§12) and a record UUID per message.

### 6.4 `reference/pfcp_decoder.go`

- **L37–45 tshark setup:** ✅ Keep `-J frame ip ipv6 udp pfcp`; move to context
  runner. Make sure UDP src/dst ports survive for §11.
- **L84–86, L133–135 array framing:** 🔴 *Change to `messages.jsonl` +
  `message_index.jsonl`* (§11), same reason as NGAP.
- **L104–106 `if isPFCPHeartbeat(...) { continue }`:** 🔴 *Blocker — remove the
  drop.* §11: "Heartbeat requests and responses must remain in full output."
  You may set a boolean like `is_heartbeat` for downstream convenience, but never
  `continue`/skip.
- **L107 `sanitizePFCPMap(...)`:** 🔴 *Remove from full output.* §11: preserve the
  complete tshark PFCP tree; preserve msg type/cause/SEID/seq **as observed**.
  Move `sanitizePFCPMap` (L167–248), `applySpecialIETransforms` (L250–348),
  `enumLabelOrValue`/`pfcpEnumLabels`, and especially `pfcpMsgTypeName`
  (L469–520, which translates `msg_type` 50→"SessEstReq") to normalization.
  §11 is explicit: T01 "must not translate unknown or unsupported PFCP outcomes
  into `inconclusive`" — keep the raw codes.
- **L108–111 entry `{meta, pfcp}`:** ⚠️ *Expand* to §11 required fields: record
  UUID, frame, full epoch + precision, src/dst IP + UDP ports, message type,
  sequence number, SEID, response linkage when available, decode warnings, raw
  ref.
- **L150–165 `isPFCPHeartbeat`:** ✅ Keep the *detector* (handy for a non-lossy
  `is_heartbeat` flag), just don't act on it by dropping.
- 🔴 *Add* raw tee to `raw/pfcp.packets.jsonl` (§12) + record UUID per message.

---

## 7. The brand-new pieces explained simply

These have no reference equivalent, so here's the beginner version.

### 7.1 Atomic writer (`artifact_writer.go`)

The rule (spec §7): **never let a half-written file appear in `decoder/`.**
Pattern for every file:

1. Create `staging/T01-<uuid>/<name>.tmp`.
2. Write bytes through a `sha256.New()` + byte counter so you get the checksum
   and size *for free* as you write (§15).
3. `f.Sync()` then `f.Close()`.
4. `os.Rename(tmp, finalPathInsideStaging)` — rename is atomic on the same fs.
5. After **all** files for a protocol validate, move/rename them into `decoder/`.
6. Return an `ArtifactDescriptor` (see §2 of LLD: `artifact_id`, `relative_path`,
   `artifact_type`, `protocol`, `media_type`, `format_schema_version`, `sha256`,
   `byte_size`, `record_count`, `creation_stage`, `parent_source_sha256`,
   `revision`).

For the many HTTP/2 stream docs, don't list each in the manifest — build a
`CollectionDescriptor` (LLD §23.2): the `stream_index.jsonl` is the
`index_artifact`, `members_sha256` is the checksum over the **ordered** index
entries, and `members` carries each doc's checksum/size. Python re-validates
every member.

`relative_path` rules (§7, §13, §16): always run-root relative, always under
`source/` or `decoder/`, reject absolute paths, `..`, symlink crossings, or
anything resolving outside the run root.

### 7.2 Revision (`decoder_manifest.go`)

The `revision` is a content hash that proves "these exact inputs + options
produced these exact outputs." Build a `RevisionEnvelope` (LLD §25.1) from:
source descriptor, command options, enabled capabilities, decoder/tshark
versions, policy versions, and the artifact/collection descriptors. Then
`revision = "sha256:" + sha256(canonical_json(envelope_without_revision))`.
**Canonical JSON** = sorted keys, Decimal-as-string, stable list order — this is
what makes two machines produce byte-identical revisions (AC#14). The caller
never mints this for you (§7, LLD §25.2).

### 7.3 Manifest-last publication

`decoder/decoder_manifest.json` is written **dead last**, and it may reference
**only files that are already published and validated** (§7, §13). If the
process dies before the manifest exists, Python treats the run as **failed** and
the half-finished `decoder/` is ignored. This is why publication order matters.

### 7.4 Protocol & overall status (§13, §14)

Per protocol: `success` / `absent` (no matching packets — *not* an error) /
`partial` (some records but recoverable errors) / `failed` / `not_requested`.
Overall: all-fail → `failed` + nonzero exit; mixed → `partial`; else `success`.
Exit codes are in §5.1 — wire them exactly.

### 7.5 Packet-access index (do last, optional — §13.1)

Only build when `--packet-access-index=true` **and** the
`bounded_targeted_redecode` capability is enabled (Python rejects the request
otherwise, before Go runs). One streaming O(source-size) pass recording per
packet: frame number, timestamp, packet/block offset + length, captured/original
length, pcapng section/interface identity, and the metadata-block key needed to
reconstruct a valid slice. For pcapng you must also be able to copy the section
header + interface description blocks, or you may **not** advertise the index as
T20-capable. If this optional index fails, mark it failed/absent and the run
`partial` — don't fail the whole decode (unless policy *requires* indexed T20
access, then it's fatal).

---

## 8. Common mistakes to avoid (the "noob trap" list)

1. **Naming the HTTP/2 file after `tcp.stream:streamid`.** No — filename is a
   fresh UUIDv4; the key lives *inside* the doc + index (§6, §8).
2. **Using `map[string]string` for headers.** Drops duplicates + order. Use an
   ordered slice (§9.1).
3. **Storing only decoded JSON for a body.** Keep raw hex + sha256 + length;
   decoded JSON is an *extra* (§9.2).
4. **Truncating timestamps to time-of-day** (the reference `epochToTimeOnly`
   bug). Store the full epoch decimal string with source precision.
5. **Dropping PFCP heartbeats** / **stripping NGAP NAS** / **filtering NRF/UDR.**
   All forbidden in T01. That's normalization's job.
6. **Translating codes** (msg_type → "SessEstReq", enum labels). Keep raw values.
7. **`os.Exit` on first protocol failure.** Collect status, decide at the end.
8. **Writing files directly into `decoder/`.** Always stage → validate → rename;
   manifest last.
9. **Building a shell string for tshark.** Use `exec.CommandContext` with an
   argv slice; never interpolate user input into a shell (§16).
10. **Trusting the Go exit code in Python.** Re-read and re-validate the manifest
    + every artifact checksum (§4, AC#8).
11. **File permissions `0644`/`0755`.** Spec §16 wants `≤0640` files, `≤0750`
    dirs.
12. **Logging bodies / auth headers / SUPIs.** Forbidden (§16).

---

## 9. Definition of done (maps to spec §21)

Tick every box before calling T01 complete:

- [ ] One `decode` Go subcommand parses §5 flags; exit codes 0/2/3/4/5/6 wired.
- [ ] Writes only inside the run dir under `source/`, `decoder/`, `staging/`.
- [ ] Every HTTP/2 stream → a UUID-named JSON doc **and** a `stream_index.jsonl`
      entry; consumers can find a transaction without scanning the dir.
- [ ] Duplicate/ordered headers, raw body bytes, frame refs, and incomplete
      streams are all retained; completion states assigned (§9.3).
- [ ] Full NGAP/NAS + PFCP records streamed as JSONL with **no** lean filtering
      and **no** heartbeat removal.
- [ ] `raw/<proto>.packets.jsonl` retained when `--retain-raw=true`.
- [ ] `decoder_manifest.json` has protocol status, counts, versions,
      capabilities, policy versions, timings, warnings, checksums, sizes,
      artifacts, collections, and the T01 revision — written last.
- [ ] Python validates every referenced artifact (paths, checksums, counts,
      schema, collection members, symlink/traversal) before returning.
- [ ] Partial protocol failure still publishes the good protocols (`partial`).
- [ ] No NRF/UDR filtering, diagnosis, masking, or model call anywhere in T01.
- [ ] Benchmarked against the ~3,500 pkt/s baseline; records pkt/s, elapsed,
      peak RSS, stream count, artifact count; >20% regression investigated.
- [ ] (If enabled) packet-access index is immutable, source-checksummed,
      pcap/pcapng reconstruction-capable, and independently benchmarked.
- [ ] Descriptor validation rejects abs paths, traversal, symlink escape,
      checksum drift, count mismatch, missing/extra members.
- [ ] Identical inputs/options → byte-identical revisions + manifest descriptor
      content across machines.

---

## 10. Quick reference — where the shared models live

These are defined once in `../LLD.md`; don't redefine them per tool:

- `ArtifactDescriptor`, `CollectionDescriptor`, `CollectionMemberDescriptor` — LLD §23.2.
- `RevisionEnvelope` (and the `revision = sha256:…` rule) — LLD §25.
- `Issue` (the real type behind `DecodeWarning`) + code namespacing — LLD §26.
- `CapabilityName` literal (incl. `bounded_targeted_redecode`, `jsonl_run_store`) — LLD §3.1.
- Canonical artifact layout — LLD §6 (near line 788) and spec §6 here.

`DecodeWarning` is just `Issue` with T01-owned codes (e.g. a future
`T01_*` namespace). Completion-state strings (`complete`, `reset`, …) are
**state values, not issue codes** (LLD §26 note).
