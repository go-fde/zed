package zed

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// corpus returns the .zed files of the ZEDFREE corpus and the password in its
// README.md. The containers are never committed: ZED_CORPUS names a folder
// that holds them, and the test skips, loudly, without it.
func corpus(t *testing.T) (files []string, password string) {
	t.Helper()
	dir := os.Getenv("ZED_CORPUS")
	if dir == "" {
		t.Skip("SKIPPED: ZED_CORPUS is not set; real ZEDFREE containers were NOT tested")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.zed"))
	if err != nil || len(files) == 0 {
		t.Fatalf("ZED_CORPUS=%s holds no .zed file", dir)
	}
	b, err := os.ReadFile(filepath.Join(dir, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	line, _, _ := strings.Cut(string(b), "\n")
	return files, strings.TrimRight(line, "\r")
}

func TestCorpus(t *testing.T) {
	files, pw := corpus(t)
	opened := 0
	for _, p := range files {
		a, err := OpenFile(p, pw)
		if err != nil {
			t.Fatalf("%s: %v", filepath.Base(p), err)
		}
		in := a.Info()
		t.Logf("%s: version %s, mode %d, key %d bytes, createdwith %q, created %v, path %q", filepath.Base(p), in.Version, in.EncryptionMode, in.KeyBytes, in.CreatedWith, in.Created, in.PathName)
		for _, u := range in.Users {
			t.Logf("  user: method %s admin %v hash %d iter %d", u.Method, u.Admin, u.HashFunc, u.Iter)
		}
		for _, e := range a.Entries() {
			t.Logf("  entry %q dir=%v size=%d modified=%v", e.Path, e.Dir, e.Size, e.Modified)
			if !e.Dir {
				e := e
				b, err := a.ReadFile(&e)
				if err != nil || int64(len(b)) != e.Size {
					t.Errorf("  %s: read %d bytes: %v", e.Path, len(b), err)
				}
			}
		}
		a.Close()
		if _, err := OpenFile(p, pw+"x"); !errors.Is(err, ErrPassword) {
			t.Errorf("%s: a wrong password gave %v", filepath.Base(p), err)
		}
		opened++
	}
	// A green run that opened nothing would say nothing about interoperability.
	if opened == 0 || opened != len(files) {
		t.Fatalf("opened %d of %d containers", opened, len(files))
	}
	t.Logf("opened %d real container(s)", opened)
}
