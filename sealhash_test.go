package zed

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/go-filesystems/cfb"
)

// These tests hold the writer to the descriptions in seal.go with code that
// shares nothing with it: the digests are recomputed here from the raw image.

// sealKeyOf returns the seal key of an archive written for pw.
func sealKeyOf(t *testing.T, cf *cfb.File, pw string) (key, catBlob []byte) {
	t.Helper()
	e := cf.Lookup(metadataStream)
	meta, err := cf.ReadAll(e, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	ctlBlob, catBlob, err := blobs(meta)
	if err != nil {
		t.Fatal(err)
	}
	g, err := parseControl(ctlBlob, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	fileKey, err := g.unlock(pw, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	sb, _ := aes.NewCipher(staticKey)
	top, err := parseTLV(decryptStream(sb, ctlBlob[18:34], ctlBlob[34:len(ctlBlob)-36]))
	if err != nil {
		t.Fatal(err)
	}
	sk, _ := top.first(0x801c0600)
	in, _ := parseTLV(sk)
	ct, _ := in.first(0x00e00500)
	iv, _ := in.first(0x00e20500)
	blk, _ := aes.NewCipher(fileKey)
	p := make([]byte, len(ct))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(p, ct)
	return p[:len(p)-int(p[len(p)-1])], catBlob
}

// refDigest is blockXOR written the plain way, on a whole string.
func refDigest(id [16]byte, data []byte) []byte {
	acc := make([]byte, sha256.Size)
	for i := 0; i*fileBlock < len(data); i++ {
		blk := data[i*fileBlock : min(len(data), (i+1)*fileBlock)]
		var idx [8]byte
		binary.LittleEndian.PutUint64(idx[:], uint64(i))
		s := sha256.Sum256(append(append(idx[:], id[:]...), blk...))
		for k := range acc {
			acc[k] ^= s[k]
		}
	}
	return acc
}

func refHMAC(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

func TestBlockXOR(t *testing.T) {
	id := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	if got := newBlockXOR(id).sum(); !bytes.Equal(got, make([]byte, 32)) {
		t.Errorf("empty string: %x", got)
	}
	data := random(5*fileBlock+37, 9)
	want := refDigest(id, data)
	for _, step := range []int{1, 7, 100, 511, 512, 513, 1000, len(data)} {
		b := newBlockXOR(id)
		for p := data; len(p) > 0; {
			k := min(step, len(p))
			b.Write(p[:k])
			p = p[k:]
		}
		if got := b.sum(); !bytes.Equal(got, want) {
			t.Errorf("pieces of %d: %x, want %x", step, got, want)
		}
	}
	// A block is a unit: the digest of 512 bytes is not that of 511.
	if bytes.Equal(refDigest(id, data[:512]), refDigest(id, data[:511])) {
		t.Error("the digest ignores the last byte of a block")
	}
}

func TestFileSealsRecomputable(t *testing.T) {
	const pw = "file-seal-password"
	files := map[string][]byte{
		"empty":   {},
		"short":   []byte("hello"),
		"exact":   random(fileBlock, 1),
		"text":    bytes.Repeat([]byte("zed "), 3000),
		"noise":   random(70_000, 2),
		"nested/": nil,
	}
	img := build(t, pw, nil, func(w *Writer) {
		mustMkdir(t, w, "nested")
		for name, d := range files {
			if name == "nested/" {
				continue
			}
			mustAdd(t, w, name, d)
		}
	})
	cf, err := cfb.Open(bytes.NewReader(img), int64(len(img)))
	if err != nil {
		t.Fatal(err)
	}
	key, catBlob := sealKeyOf(t, cf, pw)
	a, err := Open(bytes.NewReader(img), int64(len(img)), pw)
	if err != nil {
		t.Fatal(err)
	}
	top, err := parseTLV(catBlob)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, it := range top {
		if it.tag != 0x80110600 {
			continue
		}
		props, _ := parseTLV(it.val)
		idb, _ := props.first(tagFileID)
		var id [16]byte
		copy(id[:], idb)
		h40, has := props.first(0x00400500)
		h41, _ := props.first(0x00410500)
		if _, dir := props.first(tagIsDir); dir {
			if has {
				t.Errorf("directory %x carries file values", id)
			}
			continue
		}
		var e *Entry
		for i := range a.Entries() {
			if a.Entries()[i].ID == id {
				e = &a.Entries()[i]
			}
		}
		content, err := a.ReadFile(e)
		if err != nil {
			t.Fatal(err)
		}
		se := cf.Lookup(streamName(id))
		stream, err := cf.ReadAll(se, 1<<30)
		if err != nil {
			t.Fatal(err)
		}
		if want := refHMAC(key, id[:], refDigest(id, content)); !bytes.Equal(h40, want) {
			t.Errorf("%s: 0x00400500 is not the HMAC of the content digest", e.Path)
		}
		if want := refHMAC(key, id[:], refDigest(id, stream)); !bytes.Equal(h41, want) {
			t.Errorf("%s: 0x00410500 is not the HMAC of the stream digest", e.Path)
		}
		checked++
	}
	if checked != len(files)-1 {
		t.Errorf("checked %d files, want %d", checked, len(files)-1)
	}
}

// The seal stream's hash, recomputed from the image alone.
func TestGlobalSealRecomputable(t *testing.T) {
	const pw = "global-seal-password"
	for _, size := range []int{0, 5_000, 1_500_000, 3_300_000} { // one block, then several
		img := build(t, pw, nil, func(w *Writer) {
			if size > 0 {
				mustAdd(t, w, "data.bin", random(size, uint64(size)))
			}
		})
		cf, err := cfb.Open(bytes.NewReader(img), int64(len(img)))
		if err != nil {
			t.Fatal(err)
		}
		key, _ := sealKeyOf(t, cf, pw)
		stream, err := cf.ReadAll(cf.Lookup(sealStreamName), 1<<30)
		if err != nil {
			t.Fatal(err)
		}
		off := bytes.Index(img, stream)
		if off < 0 {
			t.Fatalf("size %d: the seal stream is not one run of bytes", size)
		}
		le := binary.LittleEndian
		n := 8 + int(le.Uint32(stream[4:]))
		outer, err := parseTLV(stream[8:n])
		if err != nil {
			t.Fatal(err)
		}
		ts, _ := outer.first(0x80110500)
		algo, _ := outer.first(0x80120600)
		ap, _ := parseTLV(algo)
		if bs, _, _ := ap.u32(0x80220200); bs != 1<<20 {
			t.Errorf("size %d: the stream states block size %d, want %d", size, bs, 1<<20)
		}
		inner, _ := outer.first(0x80130600)
		ip, _ := parseTLV(inner)
		hp, _ := ip.first(0x80120600)
		hh, _ := parseTLV(hp)
		got, _ := hh.first(0x80300500)

		masked := append([]byte(nil), img...)
		for i := off; i < off+n; i++ {
			masked[i] = 0xA5
		}
		var table []byte
		for p := 0; p < len(masked); p += 1 << 20 {
			s := sha256.Sum256(masked[p:min(len(masked), p+1<<20)])
			table = append(table, s[:]...)
		}
		want := refHMAC(key, table, ts)
		if !bytes.Equal(got, want) {
			t.Errorf("size %d (%d bytes in %d blocks): the stream's hash is not the recomputed one", size, len(img), len(table)/32)
		}
		// Any other byte of the image matters; the record's own bytes do not.
		flipped := append([]byte(nil), img...)
		flipped[len(flipped)-1] ^= 1
		if h, err := globalSeal(flipped, off, n, key, ts); err != nil || bytes.Equal(h, want) {
			t.Errorf("size %d: changing the last byte of the image leaves the hash unchanged (%v)", size, err)
		}
	}
}

func TestGlobalSealRefusesAnUnplaceableStream(t *testing.T) {
	img := make([]byte, 3<<20)
	for _, c := range []struct {
		name   string
		off, n int
	}{
		{"at zero", 0, 100},
		{"on a block boundary", 1 << 20, 100},
		{"across a boundary", 1<<20 - 50, 100},
		{"past the end", len(img) - 10, 100},
	} {
		if _, err := globalSeal(img, c.off, c.n, []byte("k"), make([]byte, 8)); err == nil {
			t.Errorf("%s: no error", c.name)
		}
	}
	// The image is left as it was after a refusal and after a success.
	if _, err := globalSeal(img, 4096, 148, []byte("k"), make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(img, make([]byte, len(img))) {
		t.Error("globalSeal changed the image")
	}
}
