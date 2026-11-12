package zed

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// A ZED! Free 2024.4 container (version bytes 0200) encrypts each file's name
// and chunks with IV = files_iv XOR file_id, not the global IV the 2017
// document describes. The numbers are from that container (an IV and a file_id
// are random bytes, not secrets): its file name's first block decrypts to
// "Capture " only with this IV.
func TestPerFileIVOfVersion0200(t *testing.T) {
	filesIV, _ := hex.DecodeString("471c3e5158aad0181b3c40086f2a0f8d")
	var id [16]byte
	copy(id[:], mustHex(t, "45fb4ff274a04b5d5812344e42029a00"))
	want := mustHex(t, "02e771a32c0a9b45432e74462d28958d")

	d, err := newDecryptor(bytes.Repeat([]byte{7}, 16), filesIV, modeCTS)
	if err != nil {
		t.Fatal(err)
	}
	if got := d.withFile(id); got != d || !bytes.Equal(got.iv[:], filesIV) {
		t.Fatal("a version 0100 archive keeps the global IV")
	}
	d.perFile = true
	got := d.withFile(id)
	if !bytes.Equal(got.iv[:], want) {
		t.Fatalf("per-file IV %x, want %x", got.iv, want)
	}
	if !bytes.Equal(d.iv[:], filesIV) {
		t.Fatal("withFile changed the archive's IV")
	}
	if bytes.Equal(got.chunkIV(0), d.chunkIV(0)) {
		t.Fatal("the chunk IVs must follow the per-file IV")
	}
}

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The rule is by version: 0200 archives mix the file_id in, 0100 archives do
// not; each round-trips with its own rule.
func TestPerFileIVRoundTrips(t *testing.T) {
	for _, version := range []string{"0100", "0200"} {
		a := defaultArchive()
		a.version = version
		a.root = []*tNode{{name: "dir", kids: []*tNode{{name: "file.txt", data: bytes.Repeat([]byte("x"), 2000)}}}}
		arch, err := open(t, a.bytes(t), "s3cret")
		if err != nil {
			t.Fatal(err)
		}
		if got, err := arch.ReadFile(entry(t, arch, "dir/file.txt")); err != nil || len(got) != 2000 {
			t.Fatalf("version %s: %v", version, err)
		}
	}
}

// What reading a 0200 archive written with the global IV looks like: the
// archive opens, but a wrong CBC IV spoils exactly the first block (8
// characters) of every name and the first chunk of every file. This is the
// symptom the real container showed before the per-file IV was found.
func TestGlobalIVInA0200ArchiveGarblesTheFirstBlockOnly(t *testing.T) {
	const name = "a-long-enough-file-name.txt"
	a := defaultArchive()
	a.globalIV = true
	a.root = []*tNode{{name: name, data: bytes.Repeat([]byte("y"), 3000)}}
	arch, err := open(t, a.bytes(t), "s3cret")
	if err != nil {
		t.Fatalf("a garbled name should still open: %v", err)
	}
	es := arch.Entries()
	if len(es) != 1 {
		t.Fatalf("%d entries", len(es))
	}
	got := es[0].Name
	if got == name || arch.Lookup(name) != nil {
		t.Fatalf("the name came out intact: %q", got)
	}
	if !strings.HasSuffix(got, name[8:]) { // only the first 8 characters are lost
		t.Fatalf("%q does not end with %q", got, name[8:])
	}
	if _, err := arch.ReadFile(&es[0]); !errors.Is(err, ErrFormat) { // zlib header of the first chunk
		t.Fatalf("reading the file: %v", err)
	}
}
