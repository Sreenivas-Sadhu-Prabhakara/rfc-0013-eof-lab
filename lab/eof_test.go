package lab

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestEOFRoundTrip(t *testing.T) {
	for _, input := range []string{"", "ABC\x00DEF", strings.Repeat("x", EOFFrameBytes), strings.Repeat("y", EOFFrameBytes+1)} {
		var stream bytes.Buffer
		if err := EncodeEOF(&stream, iotest.OneByteReader(strings.NewReader(input))); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(input))
		result, err := VerifyEOF(iotest.OneByteReader(&stream), &sum)
		if err != nil || !result.EndSeen || result.Bytes != len(input) || result.Frames != (len(input)+EOFFrameBytes-1)/EOFFrameBytes || result.SHA256 != hex.EncodeToString(sum[:]) {
			t.Fatalf("size %d: %+v, %v", len(input), result, err)
		}
	}
}

func TestEOFRejectsBrokenStreams(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire []byte
		err  error
	}{
		{"no marker", []byte{0, 0, 0, 1, 'A'}, ErrMissingEnd},
		{"partial header", []byte{0, 0, 0}, ErrPartialHeader},
		{"partial payload", []byte{0, 0, 0, 2, 'A'}, ErrPartialPayload},
		{"trailing byte", []byte{0, 0, 0, 0, 1}, ErrTrailingData},
		{"second marker", make([]byte, 8), ErrTrailingData},
		{"oversize", []byte{0, 0, 16, 1}, ErrFrameLimit},
		{"too many frames", bytes.Repeat([]byte{0, 0, 0, 1, 'A'}, EOFFrameLimit+1), ErrFrameLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyEOF(bytes.NewReader(tc.wire), nil)
			if !errors.Is(err, tc.err) {
				t.Fatalf("got %v, want %v", err, tc.err)
			}
		})
	}
}

func TestEOFMarkerDoesNotProveExpectedContent(t *testing.T) {
	wire := []byte{0, 0, 0, 0}
	expected := sha256.Sum256([]byte("expected nonempty data"))
	if _, err := VerifyEOF(bytes.NewReader(wire), nil); err != nil {
		t.Fatal(err)
	}
	result, err := VerifyEOF(bytes.NewReader(wire), &expected)
	if !errors.Is(err, ErrDigestMismatch) || !result.EndSeen {
		t.Fatalf("%+v, %v", result, err)
	}
}

type shortEOFWriter struct{}

func (shortEOFWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestEOFEncodeLimitsAndOutputFailure(t *testing.T) {
	if err := EncodeEOF(shortEOFWriter{}, strings.NewReader("data")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	input := strings.Repeat("a", EOFFileBytes+1)
	if err := EncodeEOF(io.Discard, strings.NewReader(input)); !errors.Is(err, ErrFrameLimit) {
		t.Fatal(err)
	}
}
