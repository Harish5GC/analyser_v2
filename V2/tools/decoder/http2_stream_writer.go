package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// writeHTTP2Stream serialises a completed (or EOF-flushed) stream state to a
// UUID-named JSON document under decoder/full/http2/streams/ and returns both
// a CollectionMemberDescriptor (for the manifest) and an HTTP2StreamIndexEntry
// (for stream_index.jsonl) — spec §6, §7, §8, §9.
func writeHTTP2Stream(
	state *http2StreamState,
	sink *ArtifactSink,
	streamsDecoderRelDir string, // "full/http2/streams"
	atEOF bool,
) (CollectionMemberDescriptor, HTTP2StreamIndexEntry, error) {
	docRelPath := streamsDecoderRelDir + "/" + state.documentID + ".json"

	doc := buildHTTP2Document(state, atEOF)

	stgPath := sink.stagingPath(docRelPath)
	if err := os.MkdirAll(filepath.Dir(stgPath), 0750); err != nil {
		return CollectionMemberDescriptor{}, HTTP2StreamIndexEntry{}, fmt.Errorf("mkdir: %w", err)
	}
	tmpPath := stgPath + ".tmp"

	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		return CollectionMemberDescriptor{}, HTTP2StreamIndexEntry{}, err
	}

	h := sha256.New()
	cw := &countWriter{}
	mw := io.MultiWriter(f, h, cw)
	bw := bufio.NewWriter(mw)
	enc := json.NewEncoder(bw)

	if err := enc.Encode(doc); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return CollectionMemberDescriptor{}, HTTP2StreamIndexEntry{}, fmt.Errorf("encode stream doc: %w", err)
	}
	if err := bw.Flush(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return CollectionMemberDescriptor{}, HTTP2StreamIndexEntry{}, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return CollectionMemberDescriptor{}, HTTP2StreamIndexEntry{}, err
	}
	f.Close()

	sha256hex := hex.EncodeToString(h.Sum(nil))
	byteSize := cw.n

	if err := os.Rename(tmpPath, stgPath); err != nil {
		return CollectionMemberDescriptor{}, HTTP2StreamIndexEntry{}, err
	}
	if err := sink.publish(stgPath, docRelPath); err != nil {
		return CollectionMemberDescriptor{}, HTTP2StreamIndexEntry{}, err
	}

	runRelDoc := runRelPath(docRelPath)

	member := CollectionMemberDescriptor{
		RelativePath:        runRelDoc,
		SHA256:              sha256hex,
		ByteSize:            byteSize,
		ArtifactType:        "http2_stream_document",
		MediaType:           "application/json",
		FormatSchemaVersion: SchemaVersion,
	}

	var reqFramePtr, respFramePtr *int
	var methodPtr, uriPtr, srcIPPtr, dstIPPtr *string
	var origKeyPtr *string

	origKeyPtr = strPtr(state.originalKey)
	if state.reqStart.frame != 0 {
		reqFramePtr = intPtr(state.reqStart.frame)
	}
	if state.respStart.frame != 0 {
		respFramePtr = intPtr(state.respStart.frame)
	}
	if state.reqMethod != "" {
		methodPtr = strPtr(state.reqMethod)
	}
	if state.reqURI != "" {
		uriPtr = strPtr(state.reqURI)
	}
	if state.clientIP != "" {
		srcIPPtr = strPtr(state.clientIP)
		dstIPPtr = strPtr(state.serverIP)
	}

	firstFrame, lastFrame := boundsOfFrames(state.frames)

	idxEntry := HTTP2StreamIndexEntry{
		DocumentID:      state.documentID,
		RelativePath:    runRelDoc,
		TCPStream:       state.tcpStream,
		HTTP2StreamID:   state.streamID,
		OriginalKey:     origKeyPtr,
		FirstFrame:      firstFrame,
		LastFrame:       lastFrame,
		RequestFrame:    reqFramePtr,
		ResponseFrame:   respFramePtr,
		Method:          methodPtr,
		URI:             uriPtr,
		Status:          state.respStatus,
		SrcIP:           srcIPPtr,
		DstIP:           dstIPPtr,
		CompletionState: doc.Completion.State,
		SHA256:          sha256hex,
		ByteSize:        byteSize,
	}

	return member, idxEntry, nil
}

// buildHTTP2Document converts the mutable stream state into the immutable
// HTTP2Document that is written to disk.
func buildHTTP2Document(state *http2StreamState, atEOF bool) HTTP2Document {
	doc := HTTP2Document{
		SchemaVersion: SchemaVersion,
		DocumentID:    state.documentID,
		Protocol:      "HTTP2",
		Transport: HTTP2Transport{
			TCPStream:     state.tcpStream,
			HTTP2StreamID: state.streamID,
			OriginalKey:   state.originalKey,
			Client:        Endpoint{IP: state.clientIP, Port: state.clientPort},
			Server:        Endpoint{IP: state.serverIP, Port: state.serverPort},
		},
		Completion: HTTP2Completion{
			State:             completionState(state, atEOF),
			RequestEndStream:  state.reqEndStream,
			ResponseEndStream: state.respEndStream,
			RstStream:         state.rstStream,
			CaptureTruncated:  atEOF,
			Warnings:          state.warnings,
		},
		SourceFrames: state.frames,
	}
	if doc.Completion.Warnings == nil {
		doc.Completion.Warnings = []string{}
	}
	if doc.SourceFrames == nil {
		doc.SourceFrames = []int{}
	}

	if len(state.reqHeaders) > 0 || len(state.reqSegments) > 0 {
		side := &HTTP2Side{
			StartFrame:     state.reqStart.frame,
			EndFrame:       state.reqEnd.frame,
			StartTimeEpoch: state.reqStart.epoch,
			EndTimeEpoch:   state.reqEnd.epoch,
			Headers:        state.reqHeaders,
			Method:         state.reqMethod,
			URI:            state.reqURI,
		}
		if side.Headers == nil {
			side.Headers = []Header{}
		}
		side.Body = assembleBody(state.reqSegments, state.reqHeaders)
		doc.Request = side
	}

	if len(state.respHeaders) > 0 || len(state.respSegments) > 0 {
		side := &HTTP2Side{
			StartFrame:     state.respStart.frame,
			EndFrame:       state.respEnd.frame,
			StartTimeEpoch: state.respStart.epoch,
			EndTimeEpoch:   state.respEnd.epoch,
			Headers:        state.respHeaders,
			Status:         state.respStatus,
		}
		if side.Headers == nil {
			side.Headers = []Header{}
		}
		side.Body = assembleBody(state.respSegments, state.respHeaders)
		doc.Response = side
	}

	return doc
}

// ---------------------------------------------------------------------------
// Pointer helpers
// ---------------------------------------------------------------------------

func intPtr(n int) *int       { return &n }
func strPtr(s string) *string { return &s }

func boundsOfFrames(frames []int) (first, last int) {
	if len(frames) == 0 {
		return 0, 0
	}
	first, last = frames[0], frames[0]
	for _, f := range frames[1:] {
		if f < first {
			first = f
		}
		if f > last {
			last = f
		}
	}
	return first, last
}
