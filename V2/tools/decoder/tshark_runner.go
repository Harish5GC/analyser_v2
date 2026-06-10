package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const maxStderrBytes = 8192

// tsharkRunner provides a context-aware wrapper around tshark processes.
type tsharkRunner struct {
	binary string // resolved tshark path
}

// newTsharkRunner resolves the tshark binary path and verifies it is executable.
// Returns exit code 6 sentinel error when tshark is not available.
func newTsharkRunner(tsharkPath string) (*tsharkRunner, error) {
	if tsharkPath == "" {
		resolved, err := exec.LookPath("tshark")
		if err != nil {
			return nil, &exitCodeError{code: 6, msg: "tshark not found in PATH: " + err.Error()}
		}
		tsharkPath = resolved
	} else {
		if _, err := os.Stat(tsharkPath); err != nil {
			return nil, &exitCodeError{code: 6, msg: "tshark not executable at " + tsharkPath + ": " + err.Error()}
		}
	}
	return &tsharkRunner{binary: tsharkPath}, nil
}

// version runs tshark --version and returns the first line.
func (r *tsharkRunner) version() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.binary, "--version")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("tshark --version: %w", err)
	}
	line, _, _ := strings.Cut(string(out), "\n")
	return strings.TrimSpace(line), nil
}

// streamSession holds a running tshark process and its streaming JSON decoder.
type streamSession struct {
	decoder   *json.Decoder
	cmd       *exec.Cmd
	stderrBuf *boundedBuf
	waitFn    func() error
}

// Wait calls cmd.Wait; returns the process error (non-zero exit, signal, etc.).
func (s *streamSession) Wait() error { return s.waitFn() }

// StderrText returns any captured stderr, truncated at maxStderrBytes.
func (s *streamSession) StderrText() string { return s.stderrBuf.String() }

// stream starts tshark with the given display filter and field set and returns
// a streamSession whose Decoder is positioned past the opening JSON array '['.
// The caller must call session.Wait() after consuming all records.
func (r *tsharkRunner) stream(
	ctx context.Context,
	pcapPath string,
	displayFilter string,
	fieldSet string,
	extraArgs ...string,
) (*streamSession, error) {
	// Note: the http2 decode-as directive (-d tcp.port==...,http2) is NOT applied
	// globally; it is passed via extraArgs by the http2 decoder only, since it is
	// meaningless for the SCTP/UDP-based ngap and pfcp jobs.
	args := []string{
		"-r", pcapPath,
		"-Y", displayFilter,
		"-T", "json",
		"-J", fieldSet,
		"--no-duplicate-keys",
	}
	args = append(args, extraArgs...)

	cmd := exec.CommandContext(ctx, r.binary, args...)
	// Kill the entire process group on context cancellation so child tshark
	// processes do not linger after a Python-imposed wall-clock timeout.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			// Negative PID kills the whole process group.
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderrR, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start tshark: %w", err)
	}

	stderrBuf := &boundedBuf{max: maxStderrBytes}
	go func() {
		_, _ = io.CopyN(stderrBuf, stderrR, maxStderrBytes)
		// Drain any remaining stderr to avoid blocking the child.
		_, _ = io.Copy(io.Discard, stderrR)
	}()

	dec := json.NewDecoder(bufio.NewReaderSize(stdout, 256*1024))
	// Consume the opening '[' of the JSON array tshark always emits.
	tok, err := dec.Token()
	if err != nil {
		// Empty output or tshark error — drain and wait.
		cmd.Wait() //nolint:errcheck
		return nil, fmt.Errorf("read opening token: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '[' {
		cmd.Wait() //nolint:errcheck
		return nil, fmt.Errorf("unexpected first token %v, want '['", tok)
	}

	return &streamSession{
		decoder:   dec,
		cmd:       cmd,
		stderrBuf: stderrBuf,
		waitFn:    cmd.Wait,
	}, nil
}

// ---------------------------------------------------------------------------
// boundedBuf collects at most max bytes from a reader (stderr capture).
// ---------------------------------------------------------------------------

type boundedBuf struct {
	mu  bytes.Buffer
	max int
	n   int
}

func (b *boundedBuf) Write(p []byte) (int, error) {
	remaining := b.max - b.n
	if remaining <= 0 {
		return len(p), nil
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	n, err := b.mu.Write(p)
	b.n += n
	return n, err
}

func (b *boundedBuf) String() string { return b.mu.String() }

// ---------------------------------------------------------------------------
// exitCodeError carries an intended process exit code alongside a message.
// decode_command.go inspects this to set the correct exit code.
// ---------------------------------------------------------------------------

type exitCodeError struct {
	code int
	msg  string
}

func (e *exitCodeError) Error() string { return e.msg }
