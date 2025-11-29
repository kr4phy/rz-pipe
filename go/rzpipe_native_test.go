// rizin - LGPL - Copyright 2017 - pancake

package rzpipe

import "testing"

func TestNativeCmd(t *testing.T) {
	rzp, err := NewNativePipe("/bin/ls")
	if err != nil {
		t.Fatal(err)
	}
	defer rzp.Close()
	version, err := rzp.Cmd("pd 10 @ entry0")
	if err != nil {
		t.Fatal(err)
	}
	if version == "" {
		t.Error("expected non-empty output from pd command")
	}
}

func TestNativeCmdj(t *testing.T) {
	rzp, err := NewNativePipe("/bin/ls")
	if err != nil {
		t.Fatal(err)
	}
	defer rzp.Close()

	// Test JSON output with ij (info about current binary)
	result, err := rzp.Cmdj("ij")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Error("expected non-nil result from Cmdj")
	}

	// Verify the result is a map (JSON object)
	if _, ok := result.(map[string]interface{}); !ok {
		t.Errorf("expected map[string]interface{}, got %T", result)
	}
}

func TestNativeDoubleClose(t *testing.T) {
	rzp, err := NewNativePipe("/bin/ls")
	if err != nil {
		t.Fatal(err)
	}

	// First close should succeed
	if err := rzp.Close(); err != nil {
		t.Fatal(err)
	}

	// Second close should not panic or error
	if err := rzp.Close(); err != nil {
		t.Fatal(err)
	}
}
