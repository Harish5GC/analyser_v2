package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// ---------------------------------------------------------------------------
// decode command — main orchestration (spec §5, §14, §15)
// ---------------------------------------------------------------------------

// runDecode is the entry point for the `5g_call decode` subcommand.
// It validates inputs, runs protocol decoders concurrently, publishes
// artifacts, and writes the manifest last.
// The returned int is the process exit code (spec §5.1).
func runDecode(args []string) int {
	cfg, err := parseDecodeArgs(args)
	if err != nil {
		if ec, ok := err.(*exitCodeError); ok {
			fmt.Fprintln(os.Stderr, "[decode] error:", ec.msg)
			return ec.code
		}
		fmt.Fprintln(os.Stderr, "[decode] error:", err)
		return 2
	}

	if err := cfg.validate(); err != nil {
		if ec, ok := err.(*exitCodeError); ok {
			fmt.Fprintln(os.Stderr, "[decode] error:", ec.msg)
			return ec.code
		}
		fmt.Fprintln(os.Stderr, "[decode] error:", err)
		return 2
	}

	// Compute source checksum before any decoding (needed for descriptors).
	if err := cfg.computeSourceSHA256(); err != nil {
		if ec, ok := err.(*exitCodeError); ok {
			fmt.Fprintln(os.Stderr, "[decode] error:", ec.msg)
			return ec.code
		}
		fmt.Fprintln(os.Stderr, "[decode] error:", err)
		return 3
	}

	// Resolve tshark runner (exit 6 if unavailable).
	runner, err := newTsharkRunner(cfg.TsharkPath)
	if err != nil {
		if ec, ok := err.(*exitCodeError); ok {
			fmt.Fprintln(os.Stderr, "[decode]", ec.msg)
			return ec.code
		}
		fmt.Fprintln(os.Stderr, "[decode] tshark error:", err)
		return 6
	}

	tsharkVer, err := runner.version()
	if err != nil {
		fmt.Fprintln(os.Stderr, "[decode] tshark version check failed:", err)
		return 6
	}
	fmt.Fprintln(os.Stderr, "[decode] tshark:", tsharkVer)

	// Initialise staging and decoder output directories.
	if err := os.MkdirAll(cfg.OutputDir, 0750); err != nil {
		fmt.Fprintln(os.Stderr, "[decode] create output-dir:", err)
		return 5
	}

	sourceSHA := cfg.SourceSHA256
	sink, err := newArtifactSink(cfg.RunRoot, cfg.StagingDir, sourceSHA)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[decode] init artifact sink:", err)
		return 5
	}
	defer sink.cleanup() // no-op once staging is empty after successful publish

	startedAt := time.Now()
	fmt.Fprintf(os.Stderr, "[decode] analysis_id=%s protocols=%v retain_raw=%v\n",
		cfg.AnalysisID, enabledProtocols(cfg), cfg.RetainRaw)

	// ---- run protocol decoders ------------------------------------------
	var runs []ProtocolRun
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	if cfg.Parallel {
		runs = runParallel(ctx, cfg, sink, runner)
	} else {
		runs = runSerial(ctx, cfg, sink, runner)
	}

	if ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, "[decode] cancelled:", ctx.Err())
		sink.abortPublished()
		return 5
	}

	// ---- check overall outcome ------------------------------------------
	allFailed := true
	for _, r := range runs {
		if r.Result.Status != "failed" {
			allFailed = false
			break
		}
	}
	if allFailed && len(runs) > 0 {
		fmt.Fprintln(os.Stderr, "[decode] all protocol decoders failed")
		return 4
	}

	// ---- optional packet-access index -----------------------------------
	var manifestWarnings []DecodeWarning
	if cfg.PacketAccessIndex {
		if _, err := buildPacketAccessIndex(ctx, cfg, sink); err != nil {
			fmt.Fprintln(os.Stderr, "[decode] packet-access index:", err)
			manifestWarnings = append(manifestWarnings, warnT01("PACKET_ACCESS_INDEX", err.Error()))
		}
	}
	if ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, "[decode] cancelled:", ctx.Err())
		sink.abortPublished()
		return 5
	}

	// ---- source descriptor ----------------------------------------------
	sourceDesc, err := sourceArtifactDescriptor(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[decode] source descriptor:", err)
		return 5
	}

	// ---- write manifest last --------------------------------------------
	completedAt := time.Now()
	_, err = writeManifest(cfg, sink, tsharkVer, sourceDesc, runs, manifestWarnings, startedAt, completedAt)
	if err != nil {
		if ec, ok := err.(*exitCodeError); ok {
			fmt.Fprintln(os.Stderr, "[decode] manifest:", ec.msg)
			return ec.code
		}
		fmt.Fprintln(os.Stderr, "[decode] manifest:", err)
		return 5
	}

	elapsed := completedAt.Sub(startedAt)
	fmt.Fprintf(os.Stderr, "[decode] complete in %v — status: %s\n", elapsed, overallStatus(runs, len(manifestWarnings) > 0))
	return 0
}

// ---------------------------------------------------------------------------
// Concurrent and serial orchestration
// ---------------------------------------------------------------------------

// safeDecode runs a protocol decoder and converts any panic into a "failed"
// ProtocolRun, so one decoder crashing on untrusted input (spec §16) isolates
// to that protocol instead of taking down the whole process and losing every
// artifact (M3).
func safeDecode(name string, fn func() ProtocolRun) (run ProtocolRun) {
	defer func() {
		if r := recover(); r != nil {
			run = ProtocolRun{
				Name: name,
				Result: ProtocolDecodeResult{
					Status:   "failed",
					Warnings: []DecodeWarning{warnT01("PANIC", fmt.Sprintf("%s decoder panicked: %v", name, r))},
				},
				Err: fmt.Errorf("%s panic: %v", name, r),
			}
		}
	}()
	return fn()
}

func runParallel(ctx context.Context, cfg *DecodeConfig, sink *ArtifactSink, runner *tsharkRunner) []ProtocolRun {
	type result struct {
		run ProtocolRun
	}
	ch := make(chan result, 3)
	var wg sync.WaitGroup

	if cfg.Protocols["http2"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch <- result{run: safeDecode("http2", func() ProtocolRun { return decodeHTTP2(ctx, cfg, sink, runner) })}
		}()
	}
	if cfg.Protocols["ngap"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch <- result{run: safeDecode("ngap", func() ProtocolRun { return decodeNGAP(ctx, cfg, sink, runner) })}
		}()
	}
	if cfg.Protocols["pfcp"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch <- result{run: safeDecode("pfcp", func() ProtocolRun { return decodePFCP(ctx, cfg, sink, runner) })}
		}()
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	var runs []ProtocolRun
	for r := range ch {
		logProtocolResult(r.run)
		runs = append(runs, r.run)
	}
	return runs
}

func runSerial(ctx context.Context, cfg *DecodeConfig, sink *ArtifactSink, runner *tsharkRunner) []ProtocolRun {
	var runs []ProtocolRun
	if cfg.Protocols["http2"] {
		r := safeDecode("http2", func() ProtocolRun { return decodeHTTP2(ctx, cfg, sink, runner) })
		logProtocolResult(r)
		runs = append(runs, r)
	}
	if cfg.Protocols["ngap"] {
		r := safeDecode("ngap", func() ProtocolRun { return decodeNGAP(ctx, cfg, sink, runner) })
		logProtocolResult(r)
		runs = append(runs, r)
	}
	if cfg.Protocols["pfcp"] {
		r := safeDecode("pfcp", func() ProtocolRun { return decodePFCP(ctx, cfg, sink, runner) })
		logProtocolResult(r)
		runs = append(runs, r)
	}
	return runs
}

func logProtocolResult(run ProtocolRun) {
	fmt.Fprintf(os.Stderr, "[decode] %s: status=%s input_packets=%d records=%d elapsed_ms=%d\n",
		run.Name, run.Result.Status, run.Result.InputPackets,
		run.Result.RecordsWritten, run.Result.ElapsedMS)
	for _, w := range run.Result.Warnings {
		fmt.Fprintf(os.Stderr, "[decode] %s warning: [%s] %s\n", run.Name, w.Code, w.Message)
	}
}

func enabledProtocols(cfg *DecodeConfig) []string {
	var p []string
	for _, name := range []string{"http2", "ngap", "pfcp"} {
		if cfg.Protocols[name] {
			p = append(p, name)
		}
	}
	return p
}
