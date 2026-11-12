package zed

import (
	"bytes"
	"errors"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "golang.org/x/image/bmp"
	_ "golang.org/x/image/webp"
	"golang.org/x/text/unicode/norm"

	"github.com/go-filesystems/cfb"
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

// catalogSizes reads the sizes of the two metadata blobs, which the API does not
// expose, to report what the container holds.
func catalogSizes(t *testing.T, path string) (ctl, cat int) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := cfb.Open(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	meta, err := cf.ReadAll(cf.Lookup(metadataStream), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	c, k, err := blobs(meta)
	if err != nil {
		t.Fatal(err)
	}
	return len(c), len(k)
}

var imageExt = map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".bmp": true, ".webp": true}

// TestCorpus opens every real container and extracts every entry. A file must
// come out at the size the catalog gives, inside the folder its
// parent_directory_id names, and an image must decode: with a wrong key, IV or
// chunk the bytes are random and cannot.
func TestCorpus(t *testing.T) {
	files, pw := corpus(t)
	opened, extracted, inFolders, images, compared := 0, 0, 0, 0, 0
	for _, p := range files {
		a, err := OpenFile(p, pw)
		if err != nil {
			t.Fatalf("%s: %v", filepath.Base(p), err)
		}
		in := a.Info()
		ctl, cat := catalogSizes(t, p)
		t.Logf("%s: version %s, mode %d, key %d bytes, createdwith %q, created %v, path %q, _ctlfile %d bytes, _catalog %d bytes",
			filepath.Base(p), in.Version, in.EncryptionMode, in.KeyBytes, in.CreatedWith, in.Created, in.PathName, ctl, cat)
		for _, u := range in.Users {
			t.Logf("  user: method %s admin %v hash %d iter %d", u.Method, u.Admin, u.HashFunc, u.Iter)
		}
		entries := a.Entries()
		byID := map[[16]byte]*Entry{}
		for i := range entries {
			byID[entries[i].ID] = &entries[i]
		}
		var zero [16]byte
		for i := range entries {
			e := &entries[i]
			t.Logf("  entry %q dir=%v size=%d parent-set=%v modified=%v", e.Path, e.Dir, e.Size, e.parent != zero, e.Modified)
			if e.parent != zero {
				par := byID[e.parent]
				if par == nil || !par.Dir || e.Path != par.Path+"/"+e.Name {
					t.Errorf("  %s: path does not sit under its parent_directory_id", e.Path)
				}
			} else if e.Path != e.Name {
				t.Errorf("  %s: a top-level entry whose path is not its name", e.Path)
			}
			if e.Dir {
				continue
			}
			b, err := a.ReadFile(e)
			if err != nil {
				t.Errorf("  %s: %v", e.Path, err)
				continue
			}
			if int64(len(b)) != e.Size {
				t.Errorf("  %s: extracted %d bytes, the catalog says %d", e.Path, len(b), e.Size)
			}
			extracted++
			if e.parent != zero {
				inFolders++
			}
			if ref, found := referenceFor(t, e.Name); found {
				form := "neither NFC nor NFD"
				switch {
				case norm.NFC.IsNormalString(e.Name) && norm.NFD.IsNormalString(e.Name):
					form = "NFC and NFD alike (ASCII)"
				case norm.NFC.IsNormalString(e.Name):
					form = "NFC"
				case norm.NFD.IsNormalString(e.Name):
					form = "NFD"
				}
				t.Logf("  %s: the catalog stores its name in %s form", e.Path, form)
				if !bytes.Equal(b, ref) {
					t.Errorf("  %s: %d bytes extracted, the reference file has %d and differs", e.Path, len(b), len(ref))
				}
				compared++
			}
			if ext := strings.ToLower(filepath.Ext(e.Name)); imageExt[ext] {
				img, format, err := image.Decode(bytes.NewReader(b))
				if err != nil {
					t.Errorf("  %s: an image that does not decode (a wrong key, IV or chunk?): %v", e.Path, err)
					continue
				}
				t.Logf("  %s: %s image, %dx%d, %d bytes", e.Path, format, img.Bounds().Dx(), img.Bounds().Dy(), len(b))
				images++
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
	if extracted == 0 {
		t.Fatal("no file was extracted: the file-stream path was not exercised")
	}
	if inFolders == 0 {
		t.Fatal("no extracted file sits in a folder: parent_directory_id was not exercised")
	}
	if os.Getenv("ZED_CORPUS_REFERENCE") != "" && compared == 0 {
		t.Fatal("ZED_CORPUS_REFERENCE is set but no extracted file matched a file there by name")
	}
	t.Logf("opened %d container(s), extracted %d file(s), %d in folders, %d image(s) decoded, %d compared byte for byte", opened, extracted, inFolders, images, compared)
}

// referenceFor returns the content of the original of an extracted file: a file
// of the folder named by ZED_CORPUS_REFERENCE whose name equals name once both
// are Unicode-normalised (macOS and the archive may disagree on NFC and NFD).
// The originals may be private (a screen capture): they are only read here, at
// run time, and never copied anywhere.
func referenceFor(t *testing.T, name string) ([]byte, bool) {
	t.Helper()
	dir := os.Getenv("ZED_CORPUS_REFERENCE")
	if dir == "" {
		return nil, false
	}
	list, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := norm.NFC.String(name)
	for _, f := range list {
		if !f.IsDir() && norm.NFC.String(f.Name()) == want {
			b, err := os.ReadFile(filepath.Join(dir, f.Name()))
			if err != nil {
				t.Fatal(err)
			}
			return b, true
		}
	}
	return nil, false
}
