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

// The seal of a written archive: each of the three inputs (_ctlfile, _catalog,
// the watermark stream) is followed by the HMAC-SHA-256 of its SHA-256 under
// the seal key stored in the _ctlfile. The relation was found on two real
// ZED! Free 2026.3 containers; this test holds the writer to it.
func TestSealHMACsAreRecomputable(t *testing.T) {
	const pw = "seal-test-password"
	var buf bytes.Buffer
	w, err := Create(&buf, pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.AddFile("a.txt", bytes.NewReader([]byte("hello"))); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	cf, err := cfb.Open(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) []byte {
		e := cf.Lookup(name)
		if e == nil {
			t.Fatalf("no stream %q", name)
		}
		b, err := cf.ReadAll(e, 1<<30)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	meta := read(metadataStream)
	ctlBlob, catBlob, err := blobs(meta)
	if err != nil {
		t.Fatal(err)
	}
	var seal []byte
	le := binary.LittleEndian
	for s := uint32(0); s < le.Uint32(meta[24:]); s++ {
		set, err := parseSet(meta, le.Uint32(meta[28+20*s+16:]))
		if err != nil {
			t.Fatal(err)
		}
		if b := set.blob("_seals", 6); b != nil {
			seal = b
		}
	}
	items, err := parseTLV(seal)
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
	sealKey := p[:len(p)-int(p[len(p)-1])]

	sum := func(b []byte) []byte { s := sha256.Sum256(b); return s[:] }
	mac := func(d []byte) []byte { m := hmac.New(sha256.New, sealKey); m.Write(d); return m.Sum(nil) }
	for _, c := range []struct {
		name       string
		hash, hmac uint32
		input      []byte
	}{
		{"_ctlfile", 0x80120500, 0x80130500, ctlBlob},
		{"_catalog", 0x80140500, 0x80150500, catBlob},
		{"watermark", 0x00160500, 0x00170500, read(watermarkStorage + "/prop0005")},
	} {
		h, _ := items.first(c.hash)
		m, _ := items.first(c.hmac)
		if !bytes.Equal(h, sum(c.input)) {
			t.Errorf("%s: the digest is not the SHA-256 of the input", c.name)
		}
		if !bytes.Equal(m, mac(sum(c.input))) {
			t.Errorf("%s: the second value is not the HMAC-SHA-256 of the digest under the seal key", c.name)
		}
	}
}
