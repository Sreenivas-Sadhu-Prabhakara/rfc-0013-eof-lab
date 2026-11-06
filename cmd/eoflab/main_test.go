package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLIEncodeVerify(t *testing.T) {
	var wire, output bytes.Buffer
	if err := run([]string{"encode"}, strings.NewReader("abc"), &wire); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify", "-sha256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}, &wire, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"bytes":3`) {
		t.Fatal(output.String())
	}
}

func TestCLIVerifyRejectsWithoutSuccessReport(t *testing.T) {
	var output bytes.Buffer
	if err := run([]string{"verify"}, strings.NewReader("\x00\x00"), &output); err == nil || output.Len() != 0 {
		t.Fatalf("err = %v, output = %q", err, output.String())
	}
	if err := run([]string{"verify", "-sha256", "not-hex"}, strings.NewReader(""), &output); err == nil {
		t.Fatal("accepted bad digest")
	}
}
