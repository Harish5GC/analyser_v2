// Copyright (c) 2026 Harish5GC. All rights reserved.
// Unauthorized copying, distribution, or modification of this file, via any
// medium, is strictly prohibited without prior written permission from Harish5GC.
package main

import (
	"fmt"
	"os"
)

// main dispatches to the decode subcommand (V2) or the legacy compat commands.
// The legacy http2/ngap/pfcp/analyze commands are retained as migration
// helpers but stripped of the model invocation (spec §19).
func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	switch cmd {
	case "decode":
		os.Exit(runDecode(os.Args[2:]))

	// ---------------------------------------------------------------------------
	// Legacy compat wrappers — spec §19.
	// These print a deprecation notice and exit. Replace with full compat
	// wrappers if downstream consumers still drive the binary directly.
	// ---------------------------------------------------------------------------
	case "http2", "ngap", "pfcp", "analyze":
		fmt.Fprintf(os.Stderr,
			"[DEPRECATED] The '%s' subcommand is a legacy compat wrapper.\n"+
				"Use: 5g_call decode <pcap> --analysis-id <uuid> --output-dir <dir> --protocol %s\n",
			cmd, compatProtocol(cmd))
		// For minimal backward compatibility, attempt a decode into a temp run dir.
		os.Exit(runCompatDecode(cmd, os.Args[2:]))

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n", cmd)
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  5g_call decode <pcap> --analysis-id <uuid> --output-dir <path> [options]")
	fmt.Fprintln(os.Stderr, "  5g_call decode --help")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "legacy (deprecated):")
	fmt.Fprintln(os.Stderr, "  5g_call http2 <pcap>")
	fmt.Fprintln(os.Stderr, "  5g_call ngap  <pcap>")
	fmt.Fprintln(os.Stderr, "  5g_call pfcp  <pcap>")
	fmt.Fprintln(os.Stderr, "  5g_call analyze <pcap>")
}

func compatProtocol(cmd string) string {
	if cmd == "analyze" {
		return "all"
	}
	return cmd
}

// runCompatDecode wraps the legacy single-protocol commands by synthesising a
// decode invocation into a temporary directory. The output is written under
// /tmp/5gcall_compat_<proto>/ for inspection, not a canonical run tree.
func runCompatDecode(cmd string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: 5g_call %s <pcap>\n", cmd)
		return 2
	}
	pcapPath := args[0]

	// Mint a temporary analysis ID and run dir.
	analysisID, err := newUUIDv4()
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate analysis id:", err)
		return 2
	}
	runDir := fmt.Sprintf("/tmp/5gcall_compat_%s_%s", cmd, analysisID)
	outputDir := runDir + "/decoder"
	if mkErr := os.MkdirAll(runDir+"/source", 0750); mkErr != nil {
		fmt.Fprintln(os.Stderr, "mkdir:", mkErr)
		return 5
	}

	decodeArgs := []string{
		pcapPath,
		"--analysis-id", analysisID,
		"--output-dir", outputDir,
		"--protocol", compatProtocol(cmd),
	}

	code := runDecode(decodeArgs)
	if code == 0 {
		fmt.Fprintf(os.Stderr, "[compat] output written to %s\n", runDir)
	}
	return code
}
