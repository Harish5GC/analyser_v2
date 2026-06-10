package main

import (
	"path/filepath"
	"testing"
)

// §7, §16 — output paths must stay inside the run root.
func TestValidateRunRelPath(t *testing.T) {
	root := "/run/abc"
	if err := validateRunRelPath(root, filepath.Join(root, "decoder")); err != nil {
		t.Errorf("legit decoder dir rejected: %v", err)
	}
	if err := validateRunRelPath(root, "/etc/passwd"); err == nil {
		t.Error("escape to /etc/passwd not rejected")
	}
	if err := validateRunRelPath(root, "/run/abcd/decoder"); err == nil {
		t.Error("sibling-prefix escape (/run/abcd) not rejected")
	}
}

// §7, §13 — manifest relative paths must reject traversal and absolute paths.
func TestValidateDecoderRelPath(t *testing.T) {
	root := "/run/abc"
	if err := validateDecoderRelPath(root, "full/http2/streams/x.json"); err != nil {
		t.Errorf("legit rel path rejected: %v", err)
	}
	if err := validateDecoderRelPath(root, "../../etc/passwd"); err == nil {
		t.Error("traversal not rejected")
	}
	if err := validateDecoderRelPath(root, "/abs/path"); err == nil {
		t.Error("absolute path not rejected")
	}
}
