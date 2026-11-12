package zed

// The test vectors of Sylvain Beucler's ".zed archive file format" (2017) are
// read from testdata/beucler-zed-format.html, a verbatim copy that keeps the
// notice permitting it. Reading them from the document avoids transcribing a
// thousand hex digits by hand.

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

type vector struct {
	h3, h4, label string
	f             map[string]string
}

var (
	reH3    = regexp.MustCompile(`^<h3>([^<]*)`)
	reH4    = regexp.MustCompile(`^<h4>([^<]*)`)
	reP     = regexp.MustCompile(`^<p>(.*)</p>$`)
	reField = regexp.MustCompile(`^(Key|IV|Ciphertext|Expected result|Archive encryption|Chunk): ?(.*)$`)
)

func loadVectors(t testing.TB) []vector {
	t.Helper()
	raw, err := os.ReadFile("testdata/beucler-zed-format.html")
	if err != nil {
		t.Fatal(err)
	}
	var out []vector
	var h3, h4, label string
	var cur *vector
	field := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "<pre><code>") {
			cur = &vector{h3: h3, h4: h4, label: label, f: map[string]string{}}
			field = ""
			line = strings.TrimPrefix(line, "<pre><code>") // the first field is on this line
		}
		switch {
		case cur != nil && strings.Contains(line, "</code></pre>"):
			out = append(out, *cur)
			cur = nil
		case cur != nil:
			s := strings.TrimSpace(line)
			if m := reField.FindStringSubmatch(s); m != nil {
				field = m[1]
				cur.f[field] += strings.ReplaceAll(m[2], " ", "")
				if field == "Expected result" || field == "Archive encryption" {
					cur.f[field] = m[2] // keep spaces: "'ABC' (ascii) 5 times"
				}
			} else if field != "" {
				cur.f[field] += s
			}
		case reH3.MatchString(line):
			h3, h4 = reH3.FindStringSubmatch(line)[1], ""
			h3 = strings.TrimSpace(h3)
		case reH4.MatchString(line):
			h4 = strings.TrimSpace(reH4.FindStringSubmatch(line)[1])
		case reP.MatchString(line):
			label = reP.FindStringSubmatch(line)[1]
		}
	}
	return out
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("%q: %v", s, err)
	}
	return b
}

func section(t testing.TB, h3 string) []vector {
	t.Helper()
	var out []vector
	for _, v := range loadVectors(t) {
		if strings.HasPrefix(v.h3, h3) {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		t.Fatalf("no vector under %q", h3)
	}
	return out
}

func TestVectorFilenames(t *testing.T) {
	vs := section(t, "Filename encryption")
	if len(vs) != 4 {
		t.Fatalf("%d filename vectors, want 4", len(vs))
	}
	for _, v := range vs {
		mode := uint32(modeStream)
		if strings.Contains(v.f["Archive encryption"], "CTS") {
			mode = modeCTS
		}
		d, err := newDecryptor(unhex(t, v.f["Key"]), unhex(t, v.f["IV"]), mode)
		if err != nil {
			t.Fatal(err)
		}
		got, err := utf16le(d.decrypt(d.iv[:], unhex(t, v.f["Ciphertext"])))
		if err != nil || got != v.f["Expected result"] {
			t.Errorf("%s: got %q (%v), want %q", v.label, got, err, v.f["Expected result"])
		}
	}
}

func TestVectorChunkIV(t *testing.T) {
	vs := section(t, "IV derivation")
	v := vs[0]
	d, err := newDecryptor(unhex(t, v.f["Key"]), unhex(t, v.f["IV"]), modeCTS)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(d.chunkIV(2)); got != v.f["Expected result"] {
		t.Fatalf("chunk IV %s, want %s", got, v.f["Expected result"])
	}
}

var reExpected = regexp.MustCompile(`^'([^']*)' \(ascii\)(?: (\d+) times)?`)

func expectedPlain(t testing.TB, s string) []byte {
	t.Helper()
	if strings.HasPrefix(s, "empty string") {
		return nil
	}
	m := reExpected.FindStringSubmatch(s)
	if m == nil {
		t.Fatalf("cannot read expected result %q", s)
	}
	n := 1
	if m[2] != "" {
		n, _ = strconv.Atoi(m[2])
	}
	return bytes.Repeat([]byte(m[1]), n)
}

func TestVectorFileStreams(t *testing.T) {
	vs := section(t, "File encryption")
	count := map[string]int{}
	for _, v := range vs {
		mode := uint32(modeStream)
		if strings.Contains(v.h4, "CTS") {
			mode = modeCTS
		}
		d, err := newDecryptor(unhex(t, v.f["Key"]), unhex(t, v.f["IV"]), mode)
		if err != nil {
			t.Fatal(err)
		}
		ct := unhex(t, v.f["Ciphertext"])
		var zdata []byte
		for i := uint64(0); len(ct) > 0; i++ {
			n := min(len(ct), chunkSize)
			zdata = append(zdata, d.decryptChunk(i, ct[:n])...)
			ct = ct[n:]
		}
		zr, err := zlib.NewReader(bytes.NewReader(zdata))
		if err != nil {
			t.Errorf("%s / %s: %v", v.h4, v.label, err)
			continue
		}
		got, err := io.ReadAll(zr)
		want := expectedPlain(t, v.f["Expected result"])
		if strings.Contains(v.h4, "CTS") && v.label == "2.x blocks" && v.f["Expected result"] != "" && len(v.f["Ciphertext"]) == 68 {
			// Erratum of the 2017 document: these two CTS vectors say "160
			// times", but the 34 ciphertext bytes (the same length as the STREAM
			// vector, which says once) decrypt to a checksum-valid zlib stream
			// holding one alphabet.
			want = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
		}
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s / %s: %d bytes (%v), want %d", v.h4, v.label, len(got), err, len(want))
		}
		count[v.h4]++
	}
	// 10 vectors per mode and key size: 0.x/1/2/2.x block, 0.x/1 chunk, 1
	// chunk + 0.x/1/1.x block, 2.x chunks.
	for _, h4 := range []string{"AES-CBC-STREAM 256-bit", "AES-CBC-CTS 128-bit", "AES-CBC-CTS 256-bit"} {
		if count[h4] != 10 {
			t.Errorf("%s: %d vectors checked, want 10", h4, count[h4])
		}
	}
}

func TestVectorStreamName(t *testing.T) {
	var id [16]byte
	copy(id[:], unhex(t, "F714C09327642647991FF50D4552FB00"))
	if got := streamName(id); got != "93C014F764274726991FF50D4552FB" {
		t.Fatalf("stream name %s", got)
	}
	id[15] = 7 // a non-NUL last byte is kept
	if got := streamName(id); got != "93C014F764274726991FF50D4552FB07" {
		t.Fatalf("stream name %s", got)
	}
}

func TestVectorKDF(t *testing.T) {
	cases := []struct {
		pw        string
		hash      uint32
		id        byte
		salt      string
		iter, n   int
		want      string
		withLabel string
	}{
		{"123456", 21, 3, "d0ee7a995bf3022e", 200000, 8, "98a431f7e9eda53f", "SHA-1 PBA"},
		{"123456", 21, 2, "a9e8a85292a5a67d", 100000, 16, "1e5101ebda3e528994456e29ec2d0682", "SHA-1 PBE IV"},
		{"123456", 21, 1, "a9e8a85292a5a67d", 100000, 32, "abf33b17d000bef9b0211159858bd8ad6665651c439a36cb23d12f697fb038e6", "SHA-1 PBE key"},
		{"123456", 22, 3, "4257726a5e963702", 200000, 8, "e7e369a7819ce1a7", "SHA-256 PBA"},
		{"1234567890azertyuiopqsdfghjklmwxcvbn", 22, 3, "950aeef1009a494f", 200000, 8, "a3a3a997b89b212a", "SHA-256 PBA, long password"},
		{"123456", 22, 2, "3d594d2e8c35d0a7", 100000, 16, "2d8958c9f356abb359515907105bedbe", "SHA-256 PBE IV"},
		{"123456", 22, 1, "3d594d2e8c35d0a7", 100000, 32, "64cc5dc03d9ea5c4df51bb256dbac7a6a94cd0631df421dc1c4dd1a396bc3317", "SHA-256 PBE key"},
	}
	for _, c := range cases {
		h, err := hashFor(c.hash)
		if err != nil {
			t.Fatal(err)
		}
		got := hex.EncodeToString(pkcs12KDF(h, bmpPassword(c.pw), unhex(t, c.salt), c.id, c.iter, c.n))
		if got != c.want {
			t.Errorf("%s: %s, want %s", c.withLabel, got, c.want)
		}
	}
	if _, err := hashFor(99); err == nil {
		t.Fatal("hash 99 accepted")
	}
	if bmpPassword("") != nil {
		t.Fatal("empty password must stay empty")
	}
	// Two output blocks of a short hash exercise the I += B+1 step.
	h, _ := hashFor(21)
	long := pkcs12KDF(h, bmpPassword("pw"), []byte("salt"), 1, 3, 50)
	if len(long) != 50 || !bytes.Equal(long[:20], pkcs12KDF(h, bmpPassword("pw"), []byte("salt"), 1, 3, 20)) {
		t.Fatal("multi-block derivation")
	}
}

func TestVectorTLV(t *testing.T) {
	single := parseOrFatal(t, unhex(t, "80330500000000081b00000000000000"))
	if len(single) != 1 || single[0].tag != tagFileSize || leUint64(single[0].val) != 27 {
		t.Fatalf("single TLV %v", single)
	}
	nested := parseOrFatal(t, unhex(t, strings.Join([]string{
		"80110600000000a08030050000000010c4fe92aaeeb16849a01fb1769b608b00",
		"0037050000000010000000000000000000000000000000008031040000000012",
		"460069006c00650031002e0074007800740080330500000000081b0000000000",
		"00008034050000000008840537fca815d30180350500000000088105e507a915",
		"d3018036050000000008840537fca815d301003805000000000e73868338f181",
		"709475a022575692"}, "")))
	if len(nested) != 1 || nested[0].tag != tagFileProps || len(nested[0].val) != 160 {
		t.Fatalf("nested TLV: %d items", len(nested))
	}
	e := parseOrFatal(t, nested[0].val)
	id, _ := e.first(tagFileID)
	parent, _ := e.first(tagParentID)
	half, _ := e.first(tagHalfAnon)
	name, _ := utf16le(half)
	ct, _ := e.first(tagNameCiphertext)
	size, _ := e.first(tagFileSize)
	if hex.EncodeToString(id) != "c4fe92aaeeb16849a01fb1769b608b00" || !bytes.Equal(parent, make([]byte, 16)) ||
		name != "File1.txt" || leUint64(size) != 27 || hex.EncodeToString(ct) != "73868338f181709475a022575692" {
		t.Fatal("nested TLV fields")
	}
	// The three FILETIMEs of the vector.
	for tag, want := range map[uint32]string{
		tagFileCreated:  "2017-08-15T09:29:25.40297",
		tagFileWritten:  "2017-08-15T09:29:44.998233",
		tagFileAccessed: "2017-08-15T09:29:25.40297",
	} {
		v, _ := e.first(tag)
		got, err := filetime(v)
		if err != nil || got.Format("2006-01-02T15:04:05.999999") != want {
			t.Errorf("tag %08x: %v (%v), want %s", tag, got, err, want)
		}
	}
}

func parseOrFatal(t testing.TB, b []byte) tlvs {
	t.Helper()
	x, err := parseTLV(b)
	if err != nil {
		t.Fatal(err)
	}
	return x
}
