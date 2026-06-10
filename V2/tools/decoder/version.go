package main

import "runtime"

const (
	DecoderName    = "5g_call"
	DecoderVersion = "v2.0.0"
	SchemaVersion  = "2.0"
)

func goVersion() string { return runtime.Version() }
