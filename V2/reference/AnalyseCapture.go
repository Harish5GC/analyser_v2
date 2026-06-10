// Copyright (c) 2026 Harish5GC. All rights reserved.
// Unauthorized copying, distribution, or modification of this file, via any medium,
// is strictly prohibited without prior written permission from Harish5GC.
// No license is granted, and no rights are implied beyond this notice.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

func main() {
	if len(os.Args) < 3 {
		printUsage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	pcapPath := os.Args[2]
	offline := false

	if cmd == "analyze" {
		offline = parseOfflineFlag(os.Args[3:])
	}

	switch cmd {
	case "http2":
		outPath := "decoded_http2_httpmap.json"
		leanPath := "http2_lean.json"
		if err := RunHTTP2Decode(pcapPath, outPath, leanPath); err != nil {
			fmt.Fprintln(os.Stderr, "http2 decode failed:", err)
			os.Exit(1)
		}
	case "pfcp":
		outPath := "decoded_pfcp.json"
		if err := RunPFCPDecode(pcapPath, outPath); err != nil {
			fmt.Fprintln(os.Stderr, "pfcp decode failed:", err)
			os.Exit(1)
		}
	case "ngap":
		outPath := "decoded_ngap.json"
		leanPath := "ngap_lean.json"
		if err := RunNGAPDecode(pcapPath, outPath, leanPath); err != nil {
			fmt.Fprintln(os.Stderr, "ngap decode failed:", err)
			os.Exit(1)
		}
	case "analyze":
		runAnalyze(pcapPath, offline)
	default:
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  5g_call http2 <pcap_path>")
	fmt.Fprintln(os.Stderr, "  5g_call pfcp <pcap_path>")
	fmt.Fprintln(os.Stderr, "  5g_call ngap <pcap_path>")
	fmt.Fprintln(os.Stderr, "  5g_call analyze <pcap_path> [--offline]")
}

func parseOfflineFlag(args []string) bool {
	for _, arg := range args {
		if arg == "--offline" {
			return true
		}
		if strings.HasPrefix(arg, "--offline=") {
			val := strings.TrimPrefix(arg, "--offline=")
			parsed, err := strconv.ParseBool(val)
			if err == nil {
				return parsed
			}
		}
	}
	return false
}

func runAnalyze(pcapPath string, offline bool) {
	http2Out := "decoded_http2_httpmap.json"
	leanOut := "http2_lean.json"
	pfcpOut := "decoded_pfcp.json"
	ngapOut := "decoded_ngap.json"
	ngapLeanOut := "ngap_lean.json"

	var wg sync.WaitGroup
	var http2Err, pfcpErr error
	var ngapErr error

	wg.Add(3)
	go func() {
		defer wg.Done()
		http2Err = RunHTTP2Decode(pcapPath, http2Out, leanOut)
	}()
	go func() {
		defer wg.Done()
		pfcpErr = RunPFCPDecode(pcapPath, pfcpOut)
	}()
	go func() {
		defer wg.Done()
		ngapErr = RunNGAPDecode(pcapPath, ngapOut, ngapLeanOut)
	}()
	wg.Wait()

	if http2Err != nil {
		fmt.Fprintln(os.Stderr, "http2 decode failed:", http2Err)
		os.Exit(1)
	}
	if pfcpErr != nil {
		fmt.Fprintln(os.Stderr, "pfcp decode failed:", pfcpErr)
		os.Exit(1)
	}
	if ngapErr != nil {
		fmt.Fprintln(os.Stderr, "ngap decode failed:", ngapErr)
		os.Exit(1)
	}

	if offline {
		fmt.Fprintln(os.Stderr, "[Offline] Skipping OpenRouter analysis")
		if err := writeCombinedJSON(leanOut, ngapLeanOut, pfcpOut); err != nil {
			fmt.Fprintln(os.Stderr, "offline combined json failed:", err)
			os.Exit(1)
		}
		return
	}

	args := []string{"run_openrouter.py", "--input", leanOut, "--pfcp", pfcpOut, "--ngap", ngapLeanOut}
	if err := runCommand("python3", args...); err != nil {
		fmt.Fprintln(os.Stderr, "openrouter analysis failed:", err)
		os.Exit(1)
	}
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func readJSONFile(path string) (interface{}, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var payload interface{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func writeCombinedJSON(http2LeanPath, ngapLeanPath, pfcpPath string) error {
	http2Data, err := readJSONFile(http2LeanPath)
	if err != nil {
		return fmt.Errorf("read http2 lean: %w", err)
	}
	ngapData, err := readJSONFile(ngapLeanPath)
	if err != nil {
		return fmt.Errorf("read ngap lean: %w", err)
	}
	pfcpData, err := readJSONFile(pfcpPath)
	if err != nil {
		return fmt.Errorf("read pfcp: %w", err)
	}

	combined := map[string]interface{}{
		"http2": http2Data,
		"ngap":  ngapData,
		"pfcp":  pfcpData,
	}

	outDir := filepath.Dir(http2LeanPath)
	outPath := filepath.Join(outDir, "combined.json")
	blob, err := json.Marshal(combined)
	if err != nil {
		return fmt.Errorf("marshal combined: %w", err)
	}
	if err := os.WriteFile(outPath, blob, 0o644); err != nil {
		return fmt.Errorf("write combined: %w", err)
	}
	fmt.Fprintln(os.Stderr, "[Offline] Combined JSON written to:", outPath)
	return nil
}

func RunHTTP2Decode(pcapPath, outPath, leanPath string) error {
	decoder := NewHTTP2Decoder(pcapPath)
	fmt.Fprintln(os.Stderr, "[HTTP2] Decoding from pcap:", pcapPath)
	if err := decoder.StreamHTTPMapToJSONMap(outPath, leanPath); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "[HTTP2] Decode complete. JSON:", outPath, "Lean JSON:", leanPath)
	return nil
}
