package lab

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const (
	EOFFrameBytes = 4096
	EOFFileBytes  = 8 << 20
	EOFFrameLimit = 4096
)

var (
	ErrMissingEnd     = errors.New("missing end marker")
	ErrPartialHeader  = errors.New("partial frame header")
	ErrPartialPayload = errors.New("partial frame payload")
	ErrTrailingData   = errors.New("data after end marker")
	ErrFrameLimit     = errors.New("transfer limit exceeded")
	ErrDigestMismatch = errors.New("payload digest differs from expected digest")
)

// EOFReport counts fully read data frames and records a digest after clean framing.
type EOFReport struct {
	Frames  int    `json:"frames"`
	Bytes   int    `json:"bytes"`
	EndSeen bool   `json:"end_seen"`
	SHA256  string `json:"sha256,omitempty"`
}

// EncodeEOF writes a bounded stream of big-endian length prefixes and payloads.
// A zero length terminates the stream. A failed encode may leave partial output.
func EncodeEOF(dst io.Writer, src io.Reader) error {
	var payload [EOFFrameBytes]byte
	var header [4]byte
	total := 0
	for {
		n, err := io.ReadFull(src, payload[:])
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return fmt.Errorf("read source: %w", err)
		}
		total += n
		if total > EOFFileBytes {
			return ErrFrameLimit
		}
		if n > 0 {
			binary.BigEndian.PutUint32(header[:], uint32(n))
			if err := writeEOFBytes(dst, header[:]); err != nil {
				return err
			}
			if err := writeEOFBytes(dst, payload[:n]); err != nil {
				return err
			}
		}
		if err != nil {
			binary.BigEndian.PutUint32(header[:], 0)
			return writeEOFBytes(dst, header[:])
		}
	}
}

func writeEOFBytes(dst io.Writer, data []byte) error {
	n, err := dst.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return err
}

// VerifyEOF consumes exactly one finite stream. It requires physical EOF after
// the end marker to detect trailing bytes. A trusted digest is optional.
func VerifyEOF(src io.Reader, expected *[sha256.Size]byte) (EOFReport, error) {
	var result EOFReport
	var header [4]byte
	var payload [EOFFrameBytes]byte
	digest := sha256.New()
	for {
		n, err := io.ReadFull(src, header[:])
		switch {
		case err == io.EOF && n == 0:
			return result, ErrMissingEnd
		case err == io.ErrUnexpectedEOF:
			return result, ErrPartialHeader
		case err != nil:
			return result, fmt.Errorf("read header: %w", err)
		}
		size := binary.BigEndian.Uint32(header[:])
		if size == 0 {
			result.EndSeen = true
			if _, err := io.ReadFull(src, header[:1]); err != io.EOF {
				if err != nil {
					return result, fmt.Errorf("check trailing data: %w", err)
				}
				return result, ErrTrailingData
			}
			sum := digest.Sum(nil)
			result.SHA256 = hex.EncodeToString(sum)
			if expected != nil && [sha256.Size]byte(sum) != *expected {
				return result, ErrDigestMismatch
			}
			return result, nil
		}
		if size > EOFFrameBytes || result.Frames >= EOFFrameLimit || result.Bytes+int(size) > EOFFileBytes {
			return result, ErrFrameLimit
		}
		chunk := payload[:int(size)]
		if _, err := io.ReadFull(src, chunk); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return result, ErrPartialPayload
			}
			return result, fmt.Errorf("read payload: %w", err)
		}
		digest.Write(chunk)
		result.Bytes += len(chunk)
		result.Frames++
	}
}
