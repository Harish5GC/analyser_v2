package main

import (
	"regexp"
	"testing"
)

var uuidV5Re = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// C1.1 — derived ids must be stable for identical inputs.
func TestDeterministicUUIDStable(t *testing.T) {
	a := deterministicUUID("sha", "http2_stream", "12:37")
	b := deterministicUUID("sha", "http2_stream", "12:37")
	if a != b {
		t.Fatalf("expected identical UUIDs, got %q and %q", a, b)
	}
}

// C1.1 — distinct keys must produce distinct ids (no trivial collisions).
func TestDeterministicUUIDDistinct(t *testing.T) {
	cases := [][]string{
		{"sha", "http2_stream", "12:37"},
		{"sha", "http2_stream", "12:38"},
		{"sha", "ngap", "12:37"},
		{"other-sha", "http2_stream", "12:37"},
		{"sha", "http2_stream", "1", "237"}, // separator must matter vs "12:37"
	}
	seen := map[string]string{}
	for _, c := range cases {
		id := deterministicUUID(c...)
		if prev, ok := seen[id]; ok {
			t.Fatalf("collision: %v and %v both produced %s", prev, c, id)
		}
		seen[id] = id
	}
}

// The separator must disambiguate ("a","bc") from ("ab","c").
func TestDeterministicUUIDSeparator(t *testing.T) {
	if deterministicUUID("a", "bc") == deterministicUUID("ab", "c") {
		t.Fatal("parts must not be ambiguously concatenated")
	}
}

func TestDeterministicUUIDFormat(t *testing.T) {
	id := deterministicUUID("sha", "x", "y")
	if !uuidV5Re.MatchString(id) {
		t.Fatalf("not a valid v5 UUID: %q", id)
	}
}
