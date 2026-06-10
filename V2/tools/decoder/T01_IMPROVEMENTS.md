# T01 `decode_capture` — Improvements & Tests

Tracking doc for the fixes raised in code review (2026-06-10). Each item lists
the problem, the fix, the files touched, and the test that proves it.

Status legend: `[ ]` todo · `[~]` in progress · `[x]` done

---

## 🔴 C1 — Deterministic output (fails AC#14)

**Problem (empirically reproduced):** three runs of the same PCAP produce three
different `revision` values and three different per-artifact checksums. Root
causes:

1. **Random UUIDs embedded in artifact content.** `newUUIDv4()` (crypto/rand)
   mints `record_id` (ngap/pfcp), `document_id` (http2) and these are written
   *into* the artifact bytes → every file's SHA-256 changes per run.
2. **`analysis_id` is in the revision envelope** (`decoder_manifest.go`), but
   spec §7 does not list it and it is unique per run.
3. **HTTP/2 EOF flush iterates the state map in random order**
   (`http2_decoder.go`), randomising `stream_index.jsonl` and `members_sha256`.

**Fix:**
- [x] C1.1 New `ids.go`: deterministic v5-style UUID derived from
  `source_sha256 + kind + stable-key` (`deterministicUUID`).
- [x] C1.2 Replace content-embedded `newUUIDv4()` with deterministic IDs:
  `record_id` (ngap/pfcp), `document_id` + `collection_id` (http2),
  `artifact_id` (all descriptors), source descriptor id.
  (`newUUIDv4` stays for the per-invocation staging dir + compat analysis id.)
- [x] C1.3 Drop `AnalysisID` from `revisionEnvelopeInput`.
- [x] C1.4 Sort HTTP/2 EOF-flush keys before writing.
- [x] C1.5 Sort manifest `artifacts`/`collections` arrays by relative path for
  byte-stable descriptor content.

**Tests:**
- [x] `ids_test.go`: stable across calls, distinct for distinct keys, valid v5 format.
- [x] `revision_test.go`: revision identical for identical inputs; **independent
  of `analysis_id`**; changes when `source_sha256` changes.
- [x] `http2_logic_test.go`: `sortedStreamKeys` returns lexically sorted keys.
- [x] `integration_test.go`: run the built binary twice on the reference PCAP →
  byte-identical `revision`, `members_sha256`, and all artifact checksums.

---

## 🟠 M1 — Overall status swallows protocol-level `partial`

**Problem:** `overallStatus` counts `partial` as success; a protocol that
decoded with recoverable errors yields manifest `status: success`.

**Fix:** [x] if any protocol is `partial`, overall is at least `partial`.
**Test:** [x] `status_test.go::TestOverallStatus` (one-partial, failed+partial cases).

---

## 🟠 M2 — `DecodeCaptureResult` diverges from §4 contract

**Problem:** missing `collections`, has `manifest_path` instead of
`manifest: ArtifactDescriptor`, `warnings` is `list[dict]` not `list[DecodeWarning]`.

**Fix:** [x] add `manifest` descriptor (sha/size computed in Python),
`collections`, typed `warnings`; keep `manifest_path` as a convenience extra;
use the manifest's `ProtocolDecodeResult` model.
**Test:** [x] covered by the Python end-to-end run in `run_smoketest.py`.

---

## 🟠 M3 — No panic recovery in protocol goroutines

**Problem:** an unchecked panic in one decoder crashes the whole process (no
manifest, all protocols lost) instead of isolating to one `failed` protocol.

**Fix:** [x] per-goroutine `defer recover()` → emit a `failed` `ProtocolRun`.
**Test:** [x] `recover_test.go::TestSafeDecodeRecoversPanic` + pass-through.

---

## 🟡 LOW

- [x] **L1** `getNGAPLayer` returns only the first NGAP PDU when tshark emits an
  array → store the raw `ngap` value (map *or* array) so bundled PDUs survive.
  Test: `ngap_logic_test.go`.
- [x] **L2** Remove dead `findStringByKeyContains`, `parseIntStr`.
- [x] **L3** Status `success` when `inputPackets>0 && written==0` → `partial`
  (ngap/pfcp/http2). Test: `status_test.go`.
- [x] **L4** Append each artifact immediately after successful `Close()` so a
  later close failure never orphans a published file.
- [x] **L5** Python timeout path: if a manifest exists after timeout, validate
  and continue (spec §14); remove the dead `pass` branch.
- [x] **L6** Gate `RawRecordIndex` on `--retain-raw` (no dangling reference).
- [x] **L7** rune-safe `truncate`; `10*time.Second`; move the http2 `-d`
  decode-as out of the shared `stream()` into http2-only args.

---

## Test runner

- [x] `go test ./...` (unit + gated integration) green.
- [x] `run_smoketest.py` (Python wrapper end-to-end) green.
- [x] manual 3× determinism re-check shows identical revisions.
