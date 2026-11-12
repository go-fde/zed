package zed

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
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
		if err := os.WriteFile(filepath.Join("testdata", name), x.bytes(t), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSeedArchives(t *testing.T) {
	files, _ := filepath.Glob("testdata/*.zed")
	if len(files) != 3 {
		t.Fatalf("%d seed archives, want 3", len(files))
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
			if _, err := parseCatalog(b, dec, Limits{MaxEntries: 100}); !okErr(err) {
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
