package zed

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func random(n int, seed uint64) []byte {
	r := rand.New(rand.NewPCG(seed, 7))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

func sampleFiles() []*tNode {
	return []*tNode{
		{name: "empty.txt"},
		{name: "one", data: []byte("x")},
		{name: "text.txt", data: bytes.Repeat([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ"), 400)},
		{name: "noise.bin", data: random(100_000, 1)},
		{name: "été \U0001F600.txt", data: random(512, 2)},
		{name: "docs", kids: []*tNode{
			{name: "a.txt", data: random(511, 3)},
			{name: "b.txt", data: random(513, 4)},
			{name: "deep", kids: []*tNode{{name: "c.bin", data: random(5000, 5)}}},
		}},
		{name: "emptydir", dir: true},
	}
}

func open(t testing.TB, data []byte, pw string, opts ...Option) (*Archive, error) {
	t.Helper()
	return Open(bytes.NewReader(data), int64(len(data)), pw, opts...)
}

func TestRoundTrip(t *testing.T) {
	for _, version := range []string{"0100", "0200"} {
		for _, mode := range []uint32{modeStream, modeCTS} {
			for _, keyLen := range []int{16, 24, 32} {
				for _, hash := range []uint32{hashSHA1, hashSHA256} {
					name := fmt.Sprintf("v%s/mode%d/key%d/hash%d", version, mode, keyLen, hash)
					t.Run(name, func(t *testing.T) {
						a := defaultArchive()
						a.version, a.mode, a.key = version, mode, random(keyLen, uint64(keyLen))
						a.users = []tUser{{login: "alice", password: "pässwörd ✓", hash: hash, iter: 7}}
						a.root = sampleFiles()
						arch, err := open(t, a.bytes(t), "pässwörd ✓")
						if err != nil {
							t.Fatal(err)
						}
						in := arch.Info()
						if in.Version != version || in.EncryptionMode != int(mode) || in.KeyBytes != keyLen || in.PathName != "(none)" ||
							in.CreatedWith != "{00000018-A040-3CA8-8868-36F59DEFD14D}" || !in.Created.Equal(a.created) {
							t.Fatalf("info %+v", in)
						}
						if len(in.Users) != 1 || in.Users[0] != (User{Login: "alice", Method: "password", Admin: true, HashFunc: int(hash), Iter: 7}) {
							t.Fatalf("users %+v", in.Users)
						}
						checkFiles(t, arch, a.root, "")
					})
				}
			}
		}
	}
}

func checkFiles(t *testing.T, arch *Archive, nodes []*tNode, prefix string) {
	t.Helper()
	for _, n := range nodes {
		path := prefix + n.name
		e := arch.Lookup(path)
		if e == nil {
			t.Fatalf("%s: missing", path)
		}
		isDir := n.dir || len(n.kids) > 0
		if e.Dir != isDir || e.Name != n.name || e.Path != path || !e.Created.Equal(time.Date(2026, 11, 11, 15, 9, 17, 0, time.UTC)) ||
			!e.Modified.Equal(e.Created.Add(time.Hour)) || !e.Accessed.Equal(e.Created) {
			t.Fatalf("%s: entry %+v", path, e)
		}
		if isDir {
			if _, err := arch.Open(e); err == nil {
				t.Fatalf("%s: a directory opened", path)
			}
			checkFiles(t, arch, n.kids, path+"/")
			continue
		}
		got, err := arch.ReadFile(e)
		if err != nil || !bytes.Equal(got, n.data) || e.Size != int64(len(n.data)) {
			t.Fatalf("%s: %d bytes, err %v", path, len(got), err)
		}
	}
}

func TestEntriesAndLookup(t *testing.T) {
	a := defaultArchive()
	a.root = sampleFiles()
	arch, err := open(t, a.bytes(t), "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	es := arch.Entries()
	if len(es) != 11 {
		t.Fatalf("%d entries", len(es))
	}
	es[0].Name = "mutated" // a copy
	if arch.Entries()[0].Name == "mutated" {
		t.Fatal("Entries exposes its storage")
	}
	if arch.Lookup("/docs/deep/") == nil || arch.Lookup("nope") != nil {
		t.Fatal("Lookup")
	}
	if err := arch.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStreaming(t *testing.T) {
	a := defaultArchive()
	a.root = []*tNode{{name: "noise", data: random(70_000, 9)}}
	arch, _ := open(t, a.bytes(t), "s3cret")
	r, err := arch.Open(arch.Lookup("noise"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var got []byte
	buf := make([]byte, 1000)
	for {
		n, err := r.Read(buf)
		got = append(got, buf[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(got, a.root[0].data) {
		t.Fatal("streamed content differs")
	}
}

func TestUsers(t *testing.T) {
	a := defaultArchive()
	a.users = []tUser{
		{login: "rsa", rsa: true},
		{login: "alice", password: "one", hash: 21, iter: 3},
		{login: "bob", password: "two", hash: 22, iter: 4},
	}
	a.root = []*tNode{{name: "f", data: []byte("hello")}}
	data := a.bytes(t)
	for _, pw := range []string{"one", "two"} {
		arch, err := open(t, data, pw)
		if err != nil {
			t.Fatalf("%s: %v", pw, err)
		}
		if b, _ := arch.ReadFile(arch.Lookup("f")); string(b) != "hello" {
			t.Fatalf("%s: %q", pw, b)
		}
		in := arch.Info()
		if len(in.Users) != 3 || in.Users[0].Method != "rsa" || in.Users[0].Login != "rsa" {
			t.Fatalf("users %+v", in.Users)
		}
	}
	if _, err := open(t, data, "three"); !errors.Is(err, ErrPassword) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := open(t, data, ""); !errors.Is(err, ErrPassword) {
		t.Fatalf("empty password: %v", err)
	}
	// An empty password is a password like another.
	a.users = []tUser{{login: "anon", password: "", hash: 22, iter: 2}}
	if _, err := open(t, a.bytes(t), ""); err != nil {
		t.Fatalf("empty password user: %v", err)
	}

	a.users = []tUser{{login: "rsa", rsa: true}}
	if _, err := open(t, a.bytes(t), "x"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("RSA only: %v", err)
	}
	a.users = nil
	if _, err := open(t, a.bytes(t), "x"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("no users: %v", err)
	}
}

func TestMetadataLayouts(t *testing.T) {
	for name, o := range map[string]olepsOpts{
		"ids 3 and 4, no dictionary":     {noDict: true},
		"dictionary after the blobs":     {dictLast: true, extraBlob: true},
		"byte names, code page 1252":     {codepage: 1252},
		"code page after the dictionary": {cpLast: true, codepage: 1252},
	} {
		a := defaultArchive()
		a.opts = o
		a.root = []*tNode{{name: "f", data: []byte("x")}}
		arch, err := open(t, a.bytes(t), "s3cret")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if b, err := arch.ReadFile(arch.Lookup("f")); err != nil || string(b) != "x" {
			t.Fatalf("%s: %q %v", name, b, err)
		}
	}
}

func TestOpenFile(t *testing.T) {
	a := defaultArchive()
	a.root = []*tNode{{name: "f", data: []byte("on disk")}}
	p := filepath.Join(t.TempDir(), "x.zed")
	if err := os.WriteFile(p, a.bytes(t), 0o600); err != nil {
		t.Fatal(err)
	}
	arch, err := OpenFile(p, "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := arch.ReadFile(arch.Lookup("f")); string(b) != "on disk" {
		t.Fatalf("%q", b)
	}
	if err := arch.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(p, "wrong"); !errors.Is(err, ErrPassword) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := OpenFile(filepath.Join(t.TempDir(), "absent"), "x"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("absent: %v", err)
	}
	old := fileSize
	defer func() { fileSize = old }()
	fileSize = func(*os.File) (int64, error) { return 0, errors.New("no size") }
	if _, err := OpenFile(p, "s3cret"); err == nil || err.Error() != "no size" {
		t.Fatalf("stat failure: %v", err)
	}
}

func TestNotAZed(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty":     nil,
		"text":      bytes.Repeat([]byte("not a compound file. "), 100),
		"truncated": func() []byte { b := defaultArchive().bytes(t); return b[:len(b)/2] }(),
	} {
		if _, err := open(t, data, "x"); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A valid compound file without the metadata stream.
	if _, err := open(t, bareCFB(t), "x"); !errors.Is(err, ErrFormat) {
		t.Errorf("no metadata: %v", err)
	}
}

func TestDefaultLimits(t *testing.T) {
	l := (Limits{MaxEntries: 5}).withDefaults()
	d := DefaultLimits()
	if l.MaxEntries != 5 || l.MaxIterations != d.MaxIterations || l.MaxUsers != d.MaxUsers || l.MaxMetadata != d.MaxMetadata || l.MaxFileSize != d.MaxFileSize {
		t.Fatalf("%+v", l)
	}
	if d.MaxIterations != 10_000_000 {
		t.Fatal("the documented iteration limit changed")
	}
}
