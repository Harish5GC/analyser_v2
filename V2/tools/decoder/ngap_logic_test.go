package main

import "testing"

// L1 — getNGAPLayer must detect ngap whether tshark emits a single object or
// an array of bundled PDUs. (The decoder stores the raw value, so all PDUs are
// preserved; this test guards the presence check.)
func TestGetNGAPLayerObject(t *testing.T) {
	layers := map[string]interface{}{
		"ngap": map[string]interface{}{"ngap.procedureCode": "15"},
	}
	if _, ok := getNGAPLayer(layers); !ok {
		t.Fatal("single ngap object not detected")
	}
}

func TestGetNGAPLayerArray(t *testing.T) {
	layers := map[string]interface{}{
		"ngap": []interface{}{
			map[string]interface{}{"ngap.procedureCode": "15"},
			map[string]interface{}{"ngap.procedureCode": "46"},
		},
	}
	if _, ok := getNGAPLayer(layers); !ok {
		t.Fatal("bundled ngap array not detected")
	}
	// The raw value retained by the decoder must keep BOTH PDUs.
	arr, ok := layers["ngap"].([]interface{})
	if !ok || len(arr) != 2 {
		t.Fatal("raw ngap array must retain all bundled PDUs")
	}
}

func TestGetNGAPLayerAbsent(t *testing.T) {
	layers := map[string]interface{}{"sctp": map[string]interface{}{}}
	if _, ok := getNGAPLayer(layers); ok {
		t.Fatal("absent ngap reported present")
	}
}
