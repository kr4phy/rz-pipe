// rizin - LGPL - Copyright 2015 - nibble

package rzpipe

import "testing"

func TestCmd(t *testing.T) {
	rzp, err := NewPipe("malloc://256")
	if err != nil {
		t.Fatal(err)
	}
	defer rzp.Close()

	check := "Hello World"

	_, err = rzp.Cmd("w " + check)
	if err != nil {
		t.Fatal(err)
	}
	buf, err := rzp.Cmd("ps")
	if err != nil {
		t.Fatal(err)
	}
	if buf != check {
		t.Errorf("buf=%v; want=%v", buf, check)
	}
}

func TestCmdj(t *testing.T) {
	rzp, err := NewPipe("malloc://256")
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
