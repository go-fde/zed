package zed

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// fuzzLimits keep every fuzz iteration cheap.
func fuzzLimits() Option {
	return WithLimits(Limits{MaxIterations: 1000, MaxUsers: 4, MaxEntries: 1000, MaxMetadata: 1 << 20, MaxFileSize: 1 << 20})
}

func fuzzArchive(t testing.TB) tArchive {
	a := defaultArchive()
	a.users = append(a.users, tUser{login: "rsa", rsa: true})
	a.root = []*tNode{
		{name: "a.txt", data: bytes.Repeat([]byte("zed "), 300)},
		{name: "dir", kids: []*tNode{{name: "b.bin", data: random(700, 1)}}},
	}
	return a
}

// TestWriteSeeds regenerates testdata/*.zed (ZED_WRITE_SEEDS=1 go test -run
// WriteSeeds): the committed fuzz corpus of FuzzOpen.
func TestWriteSeeds(t *testing.T) {
	if os.Getenv("ZED_WRITE_SEEDS") == "" {
		t.Skip("set ZED_WRITE_SEEDS=1 to regenerate testdata/*.zed")
	}
	a := fuzzArchive(t)
	for name, mod := range map[string]func(*tArchive){
		"cts-sha256.zed": func(*tArchive) {},
		"stream-sha1.zed": func(a *tArchive) {
			a.mode, a.version, a.users[0].hash, a.key = modeStream, "0100", hashSHA1, random(32, 3)
		},
		"nodict.zed": func(a *tArchive) { a.opts = olepsOpts{noDict: true} },
	} {
		x := a
		x.users = append([]tUser(nil), a.users...)
		mod(&x)
		data := x.bytes(t)
		if err := os.WriteFile(filepath.Join("testdata", name), data, 0o644); err != nil {
			t.Fatal(err)
		}
		writeFuzzSeed(t, "FuzzOpen", strings.TrimSuffix(name, ".zed"), data)
	}
	// Hostile shapes for the other parsers.
	d := testDecryptor(t)
	writeFuzzSeed(t, "FuzzControl", "valid", a.control(t))
	writeFuzzSeed(t, "FuzzControl", "pba-8k", small().with(ed{"user", tagPBAChecksum, make([]byte, 8<<10)}).control(t))
	writeFuzzSeed(t, "FuzzControl", "pba-empty", small().with(ed{"user", tagPBAChecksum, []byte{}}).control(t))
	writeFuzzSeed(t, "FuzzControl", "version-0100-empty", obfuscate("0100", make([]byte, 16), nil))
	writeFuzzSeed(t, "FuzzCatalog", "chain-5", chain(5, 3))
	writeFuzzSeed(t, "FuzzCatalog", "chain-300", chain(300, 2))
	writeFuzzSeed(t, "FuzzCatalog", "cycle", cat(halfEntry(0, 1, "a", true), halfEntry(1, 0, "b", true)))
	writeFuzzSeed(t, "FuzzCatalog", "same-path", cat(halfEntry(1, -1, "x", false), halfEntry(2, -1, "x", false)))
	writeFuzzSeed(t, "FuzzCatalog", "reserved-name", halfEntry(1, -1, "CON.txt", false))
	writeFuzzSeed(t, "FuzzCatalog", "real-shape", cat(put(0x80100200, be32(4)), catEntry(d, 1, 0, "dir", true, 0), catEntry(d, 2, 1, "file", false, 5)))
	for name, o := range map[string]olepsOpts{"dictionary": {}, "no-dictionary": {noDict: true}, "cp1252": {codepage: 1252, cpLast: true}, "seal": {extraBlob: true, dictLast: true}} {
		writeFuzzSeed(t, "FuzzMetadata", name, oleps([]byte("ctl"), []byte("cat"), o))
	}
}

// writeFuzzSeed stores one input of a fuzz target in testdata/fuzz, the
// corpus `go test` replays and the fuzzer starts from.
func writeFuzzSeed(t testing.TB, target, name string, data []byte) {
	t.Helper()
	dir := filepath.Join("testdata", "fuzz", target)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("go test fuzz v1\n[]byte(%s)\n", strconv.Quote(string(data)))
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSeedArchives(t *testing.T) {
	files, _ := filepath.Glob("testdata/*.zed")
	if len(files) != 3 {
		t.Fatalf("%d seed archives, want 3", len(files))
	}
	for target, want := range map[string]int{"FuzzOpen": 3, "FuzzControl": 4, "FuzzCatalog": 6, "FuzzMetadata": 4} {
		if got, _ := filepath.Glob(filepath.Join("testdata", "fuzz", target, "*")); len(got) != want {
			t.Errorf("testdata/fuzz/%s holds %d inputs, want %d", target, len(got), want)
		}
	}
	for _, p := range files {
		a, err := OpenFile(p, "s3cret")
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		for _, e := range a.Entries() {
			if !e.Dir {
				if _, err := a.ReadFile(&e); err != nil {
					t.Fatalf("%s: %s: %v", p, e.Path, err)
				}
			}
		}
		a.Close()
	}
}

func okErr(err error) bool {
	return err == nil || errors.Is(err, ErrFormat) || errors.Is(err, ErrPassword) || errors.Is(err, ErrUnsupported) || errors.Is(err, ErrLimit)
}

func FuzzOpen(f *testing.F) {
	seeds, _ := filepath.Glob("testdata/*.zed")
	for _, p := range seeds {
		if b, err := os.ReadFile(p); err == nil {
			f.Add(b)
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := Open(bytes.NewReader(b), int64(len(b)), "s3cret", fuzzLimits())
		if !okErr(err) {
			t.Fatalf("unexpected error %v", err)
		}
		if err != nil {
			return
		}
		for _, e := range a.Entries() {
			e := e
			if e.Dir {
				continue
			}
			if _, err := a.ReadFile(&e); !okErr(err) {
				t.Fatalf("%s: unexpected error %v", e.Path, err)
			}
		}
	})
}

func FuzzControl(f *testing.F) {
	a := fuzzArchive(f)
	f.Add(a.control(f))
	f.Add(obfuscate("0100", make([]byte, 16), []byte{}))
	f.Fuzz(func(t *testing.T, b []byte) {
		g, err := parseControl(b, DefaultLimits())
		if !okErr(err) {
			t.Fatalf("unexpected error %v", err)
		}
		if err == nil {
			// Never derive: the fuzzer must not pay iteration counts.
			if _, err := g.unlock("x", Limits{MaxIterations: 1000, MaxUsers: 4}.withDefaults()); !okErr(err) {
				t.Fatalf("unlock: %v", err)
			}
		}
	})
}

func FuzzCatalog(f *testing.F) {
	d, _ := newDecryptor(defaultArchive().key, defaultArchive().iv, modeCTS)
	f.Add(cat(catEntry(d, 1, 0, "dir", true, 0), catEntry(d, 2, 1, "file", false, 5)))
	f.Add(put(0x80100200, be32(4)))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, mode := range []uint32{modeStream, modeCTS} {
			dec, _ := newDecryptor(defaultArchive().key, defaultArchive().iv, mode)
			if _, err := parseCatalog(b, dec, Limits{MaxEntries: 100}.withDefaults()); !okErr(err) {
				t.Fatalf("unexpected error %v", err)
			}
		}
	})
}

func FuzzMetadata(f *testing.F) {
	f.Add(oleps([]byte("ctl"), []byte("cat"), olepsOpts{}))
	f.Add(oleps([]byte("ctl"), []byte("cat"), olepsOpts{noDict: true}))
	f.Add(oleps([]byte("ctl"), []byte("cat"), olepsOpts{codepage: 1252, cpLast: true}))
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, _, err := blobs(b); !okErr(err) {
			t.Fatalf("unexpected error %v", err)
		}
	})
}
