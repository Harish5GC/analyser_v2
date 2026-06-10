package main

import (
	"context"
	"fmt"
)

// ---------------------------------------------------------------------------
// Packet-access index — spec §13.1
//
// This is an OPTIONAL artifact, enabled only when:
//   --packet-access-index=true AND the bounded_targeted_redecode capability
//   is present in the run configuration.
//
// When the capability is absent the Python wrapper rejects the request before
// invoking Go (spec §4). This Go-side check is a defence-in-depth guard.
//
// The full implementation (one O(source-size) streaming pass over the retained
// PCAP, pcapng section-header/IDB reconstruction, binary index file) is a
// separate milestone. This stub correctly reports the index as absent and
// records a warning so the calling Python can distinguish "not built" from
// "not requested".
// ---------------------------------------------------------------------------

const capBoundedRedecode = "bounded_targeted_redecode"

// buildPacketAccessIndex conditionally builds the T20 packet-access index.
// Returns a ProtocolRun-shaped result (reuses the same pattern for simplicity).
func buildPacketAccessIndex(ctx context.Context, cfg *DecodeConfig, sink *ArtifactSink) (ArtifactDescriptor, error) {
	if !cfg.PacketAccessIndex {
		return ArtifactDescriptor{}, nil
	}

	if !hasCapability(cfg, capBoundedRedecode) {
		return ArtifactDescriptor{}, fmt.Errorf(
			"packet_access_index=true but %s capability not enabled; Python should have rejected this request",
			capBoundedRedecode,
		)
	}

	// TODO: implement the streaming pcap/pcapng scan and binary index write.
	// For now, mark as not-yet-built and return an absent descriptor with a
	// registered warning. This does NOT fail the overall decode (spec §13.1:
	// "index failure does not invalidate otherwise usable protocol decode when
	// the index was optional").
	return ArtifactDescriptor{
		ArtifactType: "packet_access_index",
		Revision:     "absent",
	}, fmt.Errorf("packet_access_index: not yet implemented in this build")
}

func hasCapability(cfg *DecodeConfig, cap string) bool {
	for _, c := range cfg.EnabledCapabilities {
		if c == cap {
			return true
		}
	}
	return false
}
