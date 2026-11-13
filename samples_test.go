package zed

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// samplePassword is the password of the archives TestWriteSamples writes. It is
// a throwaway: the archives hold nothing private.
const samplePassword = "zed-sample-2026"

type exampleFile struct {
	path string
	data []byte
}

func samplePNG() []byte {
	img := image.NewRGBA(image.Rect(0, 0, 300, 200))
	for y := 0; y < 200; y++ {
		for x := 0; x < 300; x++ {
			img.Set(x, y, color.RGBA{uint8(x * 255 / 299), uint8(y * 255 / 199), uint8((x + y) % 256), 255})
		}
	}
	var b bytes.Buffer
	_ = png.Encode(&b, img)
	return b.Bytes()
}

func exampleFiles() []exampleFile {
	return []exampleFile{
		{"hello.txt", []byte("Hello from go-fde/zed.\n")},
		{"empty.txt", nil},
		{"Documents/notes.txt", bytes.Repeat([]byte("A note, repeated to make it compress. "), 300)},
		{"Documents/random.bin", random(100_000, 77)},
		{"Documents/picture.png", samplePNG()},
		{"Documents/Accents/éàü ✓ ünïcode.txt", []byte("Unicode names: NFC, UTF-16 in the archive.\n")},
		{"Big/one-mebibyte.bin", random(1<<20, 78)},
	}
}

// TestWriteSamples writes archives for opening in ZED! (ZED_SAMPLES_DIR=dir go
// test -run WriteSamples). The tests that need ZED! itself cannot run in CI:
// a person opens these and checks the tree and the files.
func TestWriteSamples(t *testing.T) {
	dir := os.Getenv("ZED_SAMPLES_DIR")
	if dir == "" {
		t.Skip("set ZED_SAMPLES_DIR to write the sample archives")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	variants := []struct {
		name, what string
		opts       []CreateOption
		files      bool
	}{
		{"aes128-seal.zed", "AES-128 (what ZED! Free 2026.3 writes), the seal with placeholders for the values not known", nil, true},
		{"aes256-seal.zed", "AES-256 (ZED! Enterprise), the seal with placeholders", []CreateOption{WithStrength(32)}, true},
		{"aes128-noseal.zed", "AES-128, no seal at all (no _seals property, no seal stream)", []CreateOption{WithSeal(SealNone)}, true},
		{"aes128-sealproperty-only.zed", "AES-128, the _seals property but no seal stream", []CreateOption{WithSeal(SealPropertyOnly)}, true},
		{"aes128-nowatermark-noseal.zed", "AES-128, no seal and no watermark storage", []CreateOption{WithSeal(SealNone), WithoutWatermark()}, true},
		{"aes128-empty.zed", "AES-128, nothing in it (the tree is empty)", nil, false},
	}
	var readme strings.Builder
	readme.WriteString("# Archives written by go-fde/zed\n\nPassword of every archive: `" + samplePassword + "`\n\n")
	readme.WriteString("Open each in ZED! Free 2026.3 and in ZED! Limited Edition 2026.3 and tell which open, which refuse (and the message), and whether the tree and the files are right.\n\n")
	readme.WriteString("## Expected contents (except the empty archive)\n\n| path | bytes | SHA-256 |\n|---|---:|---|\n")
	for _, f := range exampleFiles() {
		s := sha256.Sum256(f.data)
		fmt.Fprintf(&readme, "| `%s` | %d | `%x` |\n", f.path, len(f.data), s)
	}
	readme.WriteString("\nFolders: `Documents`, `Documents/Accents`, `Big`. `Documents/picture.png` is a 300 x 200 colour gradient.\n\n## The archives\n\n")
	for _, v := range variants {
		var out bytes.Buffer
		w, err := Create(&out, samplePassword, append([]CreateOption{WithLogin("zed-sample")}, v.opts...)...)
		if err != nil {
			t.Fatal(err)
		}
		if v.files {
			for _, d := range []string{"Documents", "Documents/Accents", "Big"} {
				mustMkdir(t, w, d)
			}
			for _, f := range exampleFiles() {
				mustAdd(t, w, f.path, f.data)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, v.name), out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		a := mustOpen(t, out.Bytes(), samplePassword) // our own reader reads it back
		n := 0
		for _, e := range a.Entries() {
			if !e.Dir {
				n++
			}
		}
		fmt.Fprintf(&readme, "- `%s` (%d bytes): %s. Our reader: %d files.\n", v.name, out.Len(), v.what, n)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(readme.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
