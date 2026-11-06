# RFC 13 — Zero text length EOF message

Covered **RFC 13**. Next **RFC 14**. The series progress was verified against
RFC 12 in the public shared suite at commit
`ff0b3158591102d1127bf0bf9b364bf3e7fd3486`.

Vint Cerf proposed an explicit file boundary for RFC 11 auxiliary connections
on 20 August 1969 at UCLA. The proposed EOF message carries zero text bytes
while retaining its leader, marking, checksum and padding. The RFC Editor
lists RFC 13 in the Legacy stream with category **Unknown**. Its official
catalog has empty updates, updated-by, obsoletes and obsoleted-by lists,
checked on 6 November 2026. RFC 11 is a reference in the text.

- [RFC Editor text](https://www.rfc-editor.org/rfc/rfc13.txt)
- [RFC Editor catalog record](https://www.rfc-editor.org/info/rfc13/)
- [Machine-readable catalog metadata](https://www.rfc-editor.org/rfc/rfc13.json)

An explicit boundary lets a receiver distinguish a complete framed transfer
from one that loses its connection. Content verification adds a separate
check against the file the receiver expected.

1. **Banking batch transfer verification.** Catch incomplete statement or
   reconciliation exports before ingestion. This is the exercise implemented here.
2. **Backup import validation.** Reject a cut-off archive before handing it
   to a restore process.
3. **Gateway fault injection.** Exercise truncated headers, partial payloads,
   and extra bytes in fixtures for a framing parser.

## Run the Go lab

Requires Go 1.22 or newer. The encoder reads standard input and emits binary
frames. The verifier reads a finite stream and prints one JSON report on success.
It exits nonzero for malformed framing, read failures, or digest mismatches.

```sh
go build -o /tmp/eoflab ./cmd/eoflab
printf abc | /tmp/eoflab encode > /tmp/rfc13.framed
/tmp/eoflab verify -sha256 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad < /tmp/rfc13.framed
/tmp/eoflab demo > docs/index.html
go test -race ./...
go vet ./...
go build ./...
```

The example yields one frame and three payload bytes with the end marker seen.
Open `docs/index.html` to compare six saved verifier outcomes.

The educational format uses a 4-byte unsigned big-endian payload length and
reserves zero for end-of-file. It accepts an empty file represented by the marker
alone. A zero-valued byte inside a positive-length payload is ordinary data.
This teaching format replaces the historical ARPANET wire fields with a small
length prefix. Its scope is a local verifier and static demonstration.

The verifier caps payloads at 4 KiB per frame, 8 MiB per transfer, and 4,096
data frames. It requires transport EOF after the marker to reject trailing
bytes. This deliberate finite-input rule suits files and closed pipes.
Persistent connections need a separately defined multiplexing and timeout
policy. To catch a clean but premature marker, pass an expected SHA-256 digest
from a trusted source. The marker alone declares a boundary and supplies no
content identity. The digest check covers the payload only. Discard partial
encoder output if encoding returns an error.

Tests cover short reads, empty files, binary data, exact chunk boundaries,
missing end markers, partial headers and payloads, duplicate markers,
trailing data, size limits, short writes, and trusted digest mismatches.
The lab is MIT licensed.
