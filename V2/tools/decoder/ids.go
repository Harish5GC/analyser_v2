package main

import (
	"crypto/sha1"
	"fmt"
)

// ---------------------------------------------------------------------------
// Deterministic identifiers (spec §7, AC#14)
//
// T01 must produce byte-identical revisions and descriptor content for
// identical inputs. Random (crypto/rand) UUIDs embedded in artifact content
// (record_id, document_id, ...) break that, because they change every run and
// cascade into each artifact's SHA-256, the collection digest, and the
// revision.
//
// deterministicUUID derives a stable RFC-4122 v5-style UUID from the source
// checksum plus a stable key (e.g. a stream key or frame index), so the same
// PCAP always yields the same identifiers. It is NOT used for the per-run
// staging directory name, which is intentionally random and never written into
// any artifact.
// ---------------------------------------------------------------------------

// t01IDNamespace is a fixed, project-specific namespace for derived UUIDs.
// (Changing it would change every derived id and therefore every revision.)
var t01IDNamespace = [16]byte{
	0x54, 0x30, 0x31, 0xde, 0xc0, 0xde, 0x4f, 0xa1,
	0x9c, 0x5e, 0x70, 0x01, 0x5a, 0xfe, 0xbe, 0xef,
}

// deterministicUUID returns a v5-style UUID over the namespace and the ordered
// parts. Parts are separated by an unambiguous unit separator so that
// ("a","bc") and ("ab","c") never collide.
func deterministicUUID(parts ...string) string {
	h := sha1.New()
	h.Write(t01IDNamespace[:])
	for i, p := range parts {
		if i > 0 {
			h.Write([]byte{0x1f}) // ASCII unit separator
		}
		h.Write([]byte(p))
	}
	sum := h.Sum(nil) // 20 bytes
	var b [16]byte
	copy(b[:], sum[:16])
	b[6] = (b[6] & 0x0f) | 0x50 // version 5
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
