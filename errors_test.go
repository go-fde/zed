package zed

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/go-filesystems/cfb/cfbtest"
)

type ed struct {
	level string
	tag   uint32
	val   []byte // nil drops the item
}

// with returns a copy of a whose TLV items are changed as listed.
func (a tArchive) with(es ...ed) tArchive {
	a.edit = func(level string, tag uint32, v []byte) ([]byte, bool) {
		for _, e := range es {
			if e.level == level && e.tag == tag {
				return e.val, e.val != nil
			}
		}
		return v, true
	}
	return a
}

func small() tArchive {
	a := defaultArchive()
	a.root = []*tNode{{name: "a", data: []byte("x")}, {name: "d", kids: []*tNode{{name: "b", data: []byte("y")}}}}
	return a
}

func expect(t *testing.T, name string, a tArchive, want error, opts ...Option) {
	t.Helper()
	_, err := open(t, a.bytes(t), "s3cret", opts...)
	if !errors.Is(err, want) {
		t.Errorf("%s: got %v, want %v", name, err, want)
	}
}

func TestControlRefusals(t *testing.T) {
	odd, empty, nine := []byte{1, 2, 3}, []byte{}, make([]byte, 9)
	five := []byte{1, 0, 0, 0, 0}
	cases := []struct {
		name string
		a    tArchive
		want error
	}{
		{"archive path odd length", small().with(ed{"glob", tagArchivePath, odd}), ErrFormat},
		{"mode missing", small().with(ed{"glob", tagEncMode, nil}), ErrFormat},
		{"mode empty", small().with(ed{"glob", tagEncMode, empty}), ErrFormat},
		{"mode of 9 bytes", small().with(ed{"glob", tagEncMode, nine}), ErrFormat},
		{"mode above 32 bits", small().with(ed{"glob", tagEncMode, five}), ErrFormat},
		{"strength missing", small().with(ed{"glob", tagEncStrength, nil}), ErrFormat},
		{"iv missing", small().with(ed{"glob", tagFilesIV, nil}), ErrFormat},
		{"archive properties broken", small().with(ed{"top", tagFileProps, odd}), ErrFormat},
		{"archive properties missing", small().with(ed{"top", tagFileProps, nil}), ErrFormat},
		{"extra properties broken", small().with(ed{"top", tagExtraProps, odd}), ErrFormat},
		{"creation time of 7 bytes", small().with(ed{"extra", tagCreationTime, make([]byte, 7)}), ErrFormat},
		{"created-with odd length", small().with(ed{"extra", tagCreatedWith, odd}), ErrFormat},
		{"access list broken", small().with(ed{"top", tagAccessList, odd}), ErrFormat},
		{"user broken", small().with(ed{"acl", tagPasswordUser, odd}), ErrFormat},
		{"login odd length", small().with(ed{"user", tagLogin, odd}), ErrFormat},
		{"hash empty", small().with(ed{"user", tagHashFunc, empty}), ErrFormat},
		{"pbe iterations empty", small().with(ed{"user", tagPBEIter, empty}), ErrFormat},
		{"pba iterations empty", small().with(ed{"user", tagPBAIter, empty}), ErrFormat},
		{"hash missing", small().with(ed{"user", tagHashFunc, nil}), ErrFormat},
		{"pbe iterations missing", small().with(ed{"user", tagPBEIter, nil}), ErrFormat},
		{"pba iterations missing", small().with(ed{"user", tagPBAIter, nil}), ErrFormat},
		{"key ciphertext missing", small().with(ed{"user", tagFilesKeyCT, nil}), ErrFormat},
		{"checksum missing", small().with(ed{"user", tagPBAChecksum, nil}), ErrFormat},
		{"pba iterations above the limit", small().with(ed{"user", tagPBAIter, be32(1 << 31)}), ErrLimit},
		{"pbe iterations above the limit", small().with(ed{"user", tagPBEIter, be32(10_000_001)}), ErrLimit},
		{"pba iterations zero", small().with(ed{"user", tagPBAIter, be32(0)}), ErrFormat},
		{"pbe iterations zero", small().with(ed{"user", tagPBEIter, be32(0)}), ErrFormat},
		{"unknown hash function", small().with(ed{"user", tagHashFunc, be32(99)}), ErrUnsupported},
		{"key size 20", small().with(ed{"glob", tagEncStrength, be32(20)}), ErrUnsupported},
		{"key ciphertext of 5 bytes", small().with(ed{"user", tagFilesKeyCT, odd}), ErrFormat},
		{"unknown encryption mode", small().with(ed{"glob", tagEncMode, be32(5)}), ErrUnsupported},
		{"files_iv of 3 bytes", small().with(ed{"glob", tagFilesIV, odd}), ErrFormat},
	}
	for _, c := range cases {
		expect(t, c.name, c.a, c.want)
	}
	// Ten million is allowed, one more is not; the refusal comes before the
	// derivation, so it is instant whatever the number.
	start := time.Now()
	expect(t, "iterations 4e9", small().with(ed{"user", tagPBAIter, be32(4_000_000_000)}), ErrLimit)
	if time.Since(start) > 5*time.Second {
		t.Fatal("the iteration limit was applied after the derivation")
	}
	expect(t, "custom iteration limit", small(), ErrLimit, WithLimits(Limits{MaxIterations: 4}))
	// More users than allowed.
	many := small()
	many.users = []tUser{{login: "a", password: "1", hash: 21, iter: 2}, {login: "b", password: "2", hash: 21, iter: 2}, {login: "c", password: "3", hash: 21, iter: 2}}
	expect(t, "users", many, ErrLimit, WithLimits(Limits{MaxUsers: 2}))
}

func TestFileKeyRefusals(t *testing.T) {
	kek, iv := bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16)
	blk, _ := aes.NewCipher(kek)
	wrap := func(pt []byte) []byte {
		ct := make([]byte, len(pt))
		cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ct, pt)
		return ct
	}
	good := append(bytes.Repeat([]byte{9}, 16), bytes.Repeat([]byte{16}, 16)...)
	if k, err := unwrapKey(kek, iv, wrap(good)); err != nil || len(k) != 16 {
		t.Fatalf("valid key: %v", err)
	}
	for name, pt := range map[string][]byte{
		"pad 0":              append(bytes.Repeat([]byte{9}, 15), 0),
		"pad 17":             append(bytes.Repeat([]byte{9}, 15), 17),
		"pad bytes disagree": append(bytes.Repeat([]byte{9}, 14), 1, 2),
	} {
		if _, err := unwrapKey(kek, iv, wrap(pt)); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := unwrapKey(kek, iv, nil); !errors.Is(err, ErrFormat) {
		t.Errorf("empty: %v", err)
	}
	if _, err := newDecryptor(bytes.Repeat([]byte{1}, 20), iv, modeCTS); !errors.Is(err, ErrFormat) {
		t.Errorf("20-byte file key: %v", err)
	}
}

func catEntry(d *decryptor, n int, parent int, name string, dir bool, size int) []byte {
	id, pid := testID(n), testID(parent)
	d = d.withFile(id) // per-file IV when the archive (version 0200) has one
	props := cat(put(tagFileID, id[:]), put(tagNameCiphertext, d.encrypt(d.iv[:], nameBytes(name))), put(tagFileSize, le64(uint64(size))))
	if parent != 0 {
		props = cat(props, put(tagParentID, pid[:]))
	} else {
		props = cat(props, put(tagParentID, make([]byte, 16)))
	}
	if dir {
		props = cat(props, put(tagIsDir, []byte{1}))
	}
	return put(tagFileProps, props)
}

func TestCatalogRefusals(t *testing.T) {
	odd, empty := []byte{1, 2, 3}, []byte{}
	d, _ := newDecryptor(defaultArchive().key, defaultArchive().iv, modeCTS)
	d.perFile = true
	cases := []struct {
		name string
		a    tArchive
		want error
	}{
		{"catalog broken", func() tArchive { a := small(); a.rawCatalog = odd; return a }(), ErrFormat},
		{"entry broken", small().with(ed{"catalog", tagFileProps, odd}), ErrFormat},
		{"file_id missing", small().with(ed{"entry", tagFileID, nil}), ErrFormat},
		{"file_id of 3 bytes", small().with(ed{"entry", tagFileID, odd}), ErrFormat},
		{"parent of 3 bytes", small().with(ed{"entry", tagParentID, odd}), ErrFormat},
		{"name ciphertext of odd length", small().with(ed{"entry", tagNameCiphertext, odd}), ErrFormat},
		{"half-anonymised name odd", small().with(ed{"entry", tagNameCiphertext, nil}, ed{"entry", tagHalfAnon, odd}), ErrFormat},
		{"no name at all", small().with(ed{"entry", tagNameCiphertext, nil}, ed{"entry", tagHalfAnon, nil}), ErrFormat},
		{"size of 3 bytes", small().with(ed{"entry", tagFileSize, odd}), ErrFormat},
		{"size above 2^62", small().with(ed{"entry", tagFileSize, le64(1 << 63)}), ErrFormat},
		{"creation time of 3 bytes", small().with(ed{"entry", tagFileCreated, odd}), ErrFormat},
		{"is_dir empty", small().with(ed{"entry", tagIsDir, empty}), ErrFormat},
		{"same file_id twice", small().with(ed{"entry", tagFileID, bytes.Repeat([]byte{7}, 16)}), ErrFormat},
		{"parent that does not exist", small().with(ed{"entry", tagParentID, bytes.Repeat([]byte{7}, 16)}), ErrFormat},
		{"parent is a file", func() tArchive {
			a := small()
			a.rawCatalog = cat(catEntry(d, 1, 0, "f", false, 1), catEntry(d, 2, 1, "g", false, 1))
			return a
		}(), ErrFormat},
		{"parents in a cycle", func() tArchive {
			a := small()
			a.rawCatalog = cat(catEntry(d, 1, 2, "p", true, 0), catEntry(d, 2, 1, "q", true, 0))
			return a
		}(), ErrFormat},
	}
	for _, c := range cases {
		expect(t, c.name, c.a, c.want)
	}
	// File names that would escape a directory when extracted.
	for _, name := range []string{"..", ".", "a/b", `a\b`, "a\x00b"} {
		a := defaultArchive()
		a.root = []*tNode{{name: name, data: []byte("x")}}
		expect(t, "name "+name, a, ErrFormat)
	}
	expect(t, "entry limit", small(), ErrLimit, WithLimits(Limits{MaxEntries: 2}))
	// Without the encrypted name, the half-anonymised one is used.
	a := small().with(ed{"entry", tagNameCiphertext, nil})
	arch, err := open(t, a.bytes(t), "s3cret")
	if err != nil || arch.Lookup("halfa") == nil || arch.Lookup("halfd/halfb") == nil {
		t.Fatalf("half-anonymised names: %v", err)
	}
}

func TestUnknownItemsAreSkipped(t *testing.T) {
	// ZED! Free 2024.4 writes items this package does not know: skip them.
	unknown := put(0x80100200, be32(4))
	d, _ := newDecryptor(defaultArchive().key, defaultArchive().iv, modeCTS)
	d.perFile = true
	a := small()
	a.extra = map[string][]byte{"acl": unknown, "top": unknown, "glob": unknown, "extra": unknown, "user": unknown}
	a.rawCatalog = cat(unknown, catEntry(d, 1, 0, "f", false, 0), unknown)
	arch, err := open(t, a.bytes(t), "s3cret")
	if err != nil || len(arch.Entries()) != 1 || arch.Lookup("f") == nil {
		t.Fatalf("%v", err)
	}
	// A zero FILETIME is "not recorded".
	a = small().with(ed{"entry", tagFileCreated, le64(0)})
	arch, _ = open(t, a.bytes(t), "s3cret")
	if !entry(t, arch, "a").Created.IsZero() {
		t.Fatal("zero FILETIME is not the zero time")
	}
	// A metadata stream that is no property set.
	junk, _ := cfbtest.Build(3, cfbtest.Storage("Root Entry", cfbtest.Stream(metadataStream, []byte("junk"))), false)
	if _, err := open(t, junk, "x"); !errors.Is(err, ErrFormat) {
		t.Fatalf("junk metadata: %v", err)
	}
}

func TestContainerRefusals(t *testing.T) {
	a := small()
	data, lay := a.build(t)
	// Metadata over its limit.
	if _, err := open(t, data, "s3cret", WithLimits(Limits{MaxMetadata: 100})); !errors.Is(err, ErrLimit) {
		t.Errorf("metadata limit: %v", err)
	}
	// Metadata stream whose chain is damaged: its directory entry points outside.
	b := append([]byte(nil), data...)
	at := lay.DirOff + int64(lay.EntryIdx[metadataStream])*128
	binary.LittleEndian.PutUint64(b[at+120:], 100_000) // more than its chain holds
	if _, err := open(t, b, "s3cret"); !errors.Is(err, ErrFormat) {
		t.Errorf("damaged metadata: %v", err)
	}
	// A file stream whose chain is damaged.
	b = append([]byte(nil), data...)
	at = lay.DirOff + int64(lay.EntryIdx[streamName(testID(1))])*128
	binary.LittleEndian.PutUint64(b[at+120:], 1<<30)
	arch, err := open(t, b, "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := arch.ReadFile(entry(t, arch, "a")); !errors.Is(err, ErrFormat) {
		t.Errorf("damaged file stream: %v", err)
	}
	// A file whose stream is a storage, and one with no stream.
	a.dropStreams = true
	a.cfbExtra = []*cfbtest.Node{cfbtest.Storage(streamName(testID(1)))}
	b2, _ := a.build(t)
	arch, _ = open(t, b2, "s3cret")
	if _, err := arch.Open(entry(t, arch, "a")); !errors.Is(err, ErrFormat) {
		t.Errorf("stream is a storage: %v", err)
	}
	a = small().with(ed{"entry", tagFileID, nil})
	_ = a
	arch, _ = open(t, small().bytes(t), "s3cret")
	e := *entry(t, arch, "a")
	e.ID[0] ^= 0xFF
	if _, err := arch.Open(&e); !errors.Is(err, ErrFormat) {
		t.Errorf("no stream: %v", err)
	}
	if _, err := arch.ReadFile(&e); !errors.Is(err, ErrFormat) {
		t.Errorf("ReadFile, no stream: %v", err)
	}
	if _, err := arch.ReadFile(entry(t, arch, "d")); err == nil {
		t.Error("ReadFile of a directory")
	}
	lim := small()
	lim.root = []*tNode{{name: "big", data: bytes.Repeat([]byte{1}, 3000)}}
	arch, _ = open(t, lim.bytes(t), "s3cret", WithLimits(Limits{MaxFileSize: 2000}))
	if _, err := arch.Open(entry(t, arch, "big")); !errors.Is(err, ErrLimit) {
		t.Errorf("file size limit: %v", err)
	}
}

func TestDamagedFiles(t *testing.T) {
	flip := func(i int) func(string, []byte) []byte {
		return func(_ string, z []byte) []byte { z = append([]byte(nil), z...); z[i%len(z)] ^= 0xFF; return z }
	}
	cases := map[string]struct {
		hook func(string, []byte) []byte
		size []byte // declared file_size, nil: honest
	}{
		"zlib header":    {hook: flip(0)},
		"adler-32":       {hook: flip(-1 + 1<<20)}, // set below to the last byte
		"deflate data":   {hook: func(_ string, z []byte) []byte { z = append([]byte(nil), z...); z[2] = 0xFF; z[3] = 0xFF; return z }},
		"truncated":      {hook: func(_ string, z []byte) []byte { return z[:len(z)-6] }},
		"longer":         {size: le64(3)},
		"shorter":        {size: le64(10_000)},
		"truncated tiny": {hook: func(_ string, z []byte) []byte { return z[:1] }},
	}
	for name, c := range cases {
		a := defaultArchive()
		a.root = []*tNode{{name: "f", data: bytes.Repeat([]byte("0123456789"), 100)}}
		a.zhook = c.hook
		if name == "adler-32" {
			a.zhook = func(_ string, z []byte) []byte { z = append([]byte(nil), z...); z[len(z)-1] ^= 0xFF; return z }
		}
		if c.size != nil {
			a = a.with(ed{"entry", tagFileSize, c.size})
		}
		arch, err := open(t, a.bytes(t), "s3cret")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := arch.ReadFile(entry(t, arch, "f")); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// flaky fails every read after armed is set.
type flaky struct {
	data  []byte
	armed bool
}

var errDisk = errors.New("disk on fire")

func (f *flaky) ReadAt(p []byte, off int64) (int, error) {
	if f.armed {
		return 0, errDisk
	}
	return copy(p, f.data[off:]), nil
}

func TestReadFailureIsNotAFormatError(t *testing.T) {
	a := defaultArchive()
	a.root = []*tNode{{name: "f", data: random(3000, 4)}}
	data := a.bytes(t)
	fl := &flaky{data: data}
	arch, err := Open(fl, int64(len(data)), "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	fl.armed = true
	if _, err := arch.ReadFile(entry(t, arch, "f")); !errors.Is(err, errDisk) || errors.Is(err, ErrFormat) {
		t.Fatalf("got %v", err)
	}
}

// TestZlibBomb: a few hundred kilobytes that inflate to far more than the
// declared size are refused after about the declared size, not decompressed.
func TestZlibBomb(t *testing.T) {
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zeros := make([]byte, 1<<20)
	for i := 0; i < 64; i++ { // 64 MiB of zeros
		zw.Write(zeros)
	}
	zw.Close()
	bomb := z.Bytes()
	if len(bomb) > 200<<10 {
		t.Fatalf("the bomb is %d bytes; not a bomb", len(bomb))
	}
	a := defaultArchive()
	a.root = []*tNode{{name: "bomb", data: []byte("0123456789")}}
	a.zhook = func(string, []byte) []byte { return bomb }
	data := a.bytes(t)

	old := debug.SetMemoryLimit(128 << 20)
	defer debug.SetMemoryLimit(old)
	arch, err := open(t, data, "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err = arch.ReadFile(entry(t, arch, "bomb"))
	runtime.ReadMemStats(&after)
	if !errors.Is(err, ErrFormat) || !strings.Contains(err.Error(), "longer than its declared size") {
		t.Fatalf("bomb: %v", err)
	}
	if grown := after.TotalAlloc - before.TotalAlloc; grown > 8<<20 {
		t.Fatalf("refusing the bomb allocated %d MiB", grown>>20)
	}
	// A declared size above the limit is refused before any inflation.
	a = a.with(ed{"entry", tagFileSize, le64(1 << 40)})
	arch, _ = open(t, a.bytes(t), "s3cret")
	runtime.ReadMemStats(&before)
	if _, err := arch.ReadFile(entry(t, arch, "bomb")); !errors.Is(err, ErrLimit) {
		t.Fatalf("declared 1 TiB: %v", err)
	}
	runtime.ReadMemStats(&after)
	if after.TotalAlloc-before.TotalAlloc > 1<<20 {
		t.Fatal("the size limit allocated")
	}
}

func TestCiphersRoundTrip(t *testing.T) {
	blk, _ := aes.NewCipher(bytes.Repeat([]byte{3}, 32))
	iv := bytes.Repeat([]byte{4}, 16)
	for n := 0; n <= 100; n++ {
		pt := random(n, uint64(n))
		for name, pair := range map[string]struct {
			enc, dec func(cipher.Block, []byte, []byte) []byte
		}{"stream": {encryptStream, decryptStream}, "cts": {encryptCTS, decryptCTS}} {
			ct := pair.enc(blk, iv, pt)
			if len(ct) != n || !bytes.Equal(pair.dec(blk, iv, ct), pt) {
				t.Fatalf("%s: length %d does not round trip", name, n)
			}
		}
	}
}

func TestParsersRefuse(t *testing.T) {
	// TLV.
	if _, err := parseTLV([]byte{1, 2, 3}); !errors.Is(err, ErrFormat) {
		t.Error("short TLV header accepted")
	}
	if _, err := parseTLV(append(be32(1), be32(5)...)); !errors.Is(err, ErrFormat) {
		t.Error("TLV longer than the data accepted")
	}
	if _, err := parseTLV(append(be32(1), be32(0xFFFFFFFF)...)); !errors.Is(err, ErrFormat) {
		t.Error("TLV of 4 GiB accepted")
	}
	// _ctlfile wrapper.
	good := obfuscate("0200", bytes.Repeat([]byte{1}, 16), put(tagFileProps, []byte{}))
	for name, mut := range map[string]func([]byte) []byte{
		"short":            func(b []byte) []byte { return b[:60] },
		"first delimiter":  func(b []byte) []byte { b[0] ^= 1; return b },
		"second delimiter": func(b []byte) []byte { b[len(b)-20] ^= 1; return b },
		"trailer text":     func(b []byte) []byte { b[len(b)-3] ^= 1; return b },
	} {
		if _, err := parseControl(mut(append([]byte(nil), good...)), DefaultLimits()); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := append([]byte(nil), good...)
	bad[17] = 3 // version 0300
	if _, err := parseControl(bad, DefaultLimits()); !errors.Is(err, ErrUnsupported) {
		t.Errorf("version: %v", err)
	}
	if _, err := parseControl(obfuscate("0100", make([]byte, 16), []byte{1, 2, 3}), DefaultLimits()); !errors.Is(err, ErrFormat) {
		t.Errorf("plaintext not TLV: %v", err)
	}
}

func TestOLEPSRefusals(t *testing.T) {
	le := binary.LittleEndian
	base := oleps([]byte("control"), []byte("catalog"), olepsOpts{})
	if c, k, err := blobs(base); err != nil || string(c) != "control" || string(k) != "catalog" {
		t.Fatalf("base: %v", err)
	}
	// Property order in oleps(): code page, dictionary, ctl, catalog.
	setAt := 48
	entry := func(i int) (id, off int) { return setAt + 8 + 8*i, setAt + 12 + 8*i }
	_, ctlOff := entry(2)
	_, dictOff := entry(1)
	cases := map[string]func([]byte) []byte{
		"too short":         func(b []byte) []byte { return b[:20] },
		"byte order":        func(b []byte) []byte { b[0] = 0; return b },
		"no property set":   func(b []byte) []byte { le.PutUint32(b[24:], 0); return b },
		"three sets":        func(b []byte) []byte { le.PutUint32(b[24:], 3); return b },
		"sets past the end": func(b []byte) []byte { le.PutUint32(b[24:], 2); return b[:60] },
		"set offset":        func(b []byte) []byte { le.PutUint32(b[44:], 1<<30); return b },
		"property count":    func(b []byte) []byte { le.PutUint32(b[setAt+4:], 1<<24); return b },
		"property offset":   func(b []byte) []byte { le.PutUint32(b[ctlOff:], 1<<30); return b },
		"blob size": func(b []byte) []byte {
			le.PutUint32(b[setAt+int(le.Uint32(b[ctlOff:]))+4:], 1<<30)
			return b
		},
		"dictionary count": func(b []byte) []byte { le.PutUint32(b[setAt+int(le.Uint32(b[dictOff:])):], 1<<24); return b },
		"dictionary name": func(b []byte) []byte {
			le.PutUint32(b[setAt+int(le.Uint32(b[dictOff:]))+8:], 1<<20)
			return b
		},
		"names lost": func(b []byte) []byte {
			le.PutUint32(b[setAt+int(le.Uint32(b[ctlOff:])):], 0) // ctl is no blob any more, and 3/4 are absent
			return b
		},
	}
	for name, mut := range cases {
		if _, _, err := blobs(mut(append([]byte(nil), base...))); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A dictionary that ends in the middle of the entries.
	p := &propSet{names: map[string]uint32{}}
	d := cat(le.AppendUint32(nil, 2), le.AppendUint32(nil, 4), le.AppendUint32(nil, 1), []byte{'a', 0, 0, 0}, make([]byte, 4))
	if err := p.dictionary(d, 1252); !errors.Is(err, ErrFormat) {
		t.Errorf("truncated dictionary: %v", err)
	}
	// Two property sets: the second one holds the blobs.
	empty := cat(le.AppendUint32(nil, 8), le.AppendUint32(nil, 0))
	set := base[48:]
	hdr := cat(base[:24], le.AppendUint32(nil, 2),
		make([]byte, 16), le.AppendUint32(nil, 68), make([]byte, 16), le.AppendUint32(nil, 76))
	two := cat(hdr, empty, set)
	if c, k, err := blobs(two); err != nil || string(c) != "control" || string(k) != "catalog" {
		t.Errorf("second property set: %v", err)
	}
	none := cat(hdr, empty, empty)
	if _, _, err := blobs(none); !errors.Is(err, ErrFormat) {
		t.Errorf("no blobs anywhere: %v", err)
	}
}

func TestReadersBehave(t *testing.T) {
	// exact: a reader that answers (0, nil) is asked again by the caller.
	var _ io.Reader = &exact{}
	if _, err := io.ReadAll(&exact{r: bytes.NewReader(nil), zr: io.NopCloser(nil)}); err != nil {
		t.Fatalf("empty file: %v", err)
	}
	if err := (&exact{zr: io.NopCloser(nil)}).Close(); err != nil {
		t.Fatal(err)
	}
	if err := corrupt(errDisk); err != errDisk {
		t.Fatal("a non-format error was changed")
	}
}
