package zed

import (
	"bytes"
	"errors"
	"hash"
	"io"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/go-filesystems/cfb"
)

var epoch = time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)

func fixedClock() func() time.Time { return func() time.Time { return epoch } }

// seeded is a deterministic random source for the writer's tests.
func seeded(seed uint64) io.Reader {
	r := rand.New(rand.NewPCG(seed, 11))
	return readerFunc(func(p []byte) (int, error) {
		for i := range p {
			p[i] = byte(r.Uint32())
		}
		return len(p), nil
	})
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// failingRand yields n bytes, then fails.
func failingRand(n int) io.Reader {
	left, counter := n, 0
	return readerFunc(func(p []byte) (int, error) {
		if left <= 0 {
			return 0, errors.New("entropy exhausted")
		}
		k := min(len(p), left)
		left -= k
		for i := 0; i < k; i++ {
			counter++
			p[i] = byte(counter * 7) // distinct identifiers
		}
		if k < len(p) {
			return k, errors.New("entropy exhausted")
		}
		return k, nil
	})
}

func build(t testing.TB, pw string, opts []CreateOption, fill func(w *Writer)) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := Create(&out, pw, append([]CreateOption{WithRandom(seeded(1)), WithClock(fixedClock())}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	if fill != nil {
		fill(w)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func mustMkdir(t testing.TB, w *Writer, p string) {
	t.Helper()
	if err := w.Mkdir(p); err != nil {
		t.Fatal(err)
	}
}

func mustAdd(t testing.TB, w *Writer, p string, data []byte) {
	t.Helper()
	if err := w.AddFile(p, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
}

// Whatever Create writes, Open reads back: every size around the chunk and the
// batch boundaries, nested folders, Unicode names, both key sizes.
func TestCreateRoundTrip(t *testing.T) {
	files := map[string][]byte{
		"empty.txt":              {},
		"one":                    []byte("x"),
		"text.txt":               bytes.Repeat([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ"), 400),
		"noise.bin":              random(100_000, 3),
		"é été ✓.txt":            random(512, 4),
		"docs/a.txt":             random(511, 5),
		"docs/b.txt":             random(513, 6),
		"docs/deep/c.bin":        random(5000, 7),
		"docs/deep/deeper/d.bin": random(70_000, 8),
	}
	order := []string{"docs", "docs/deep", "docs/deep/deeper", "emptydir"}
	for _, strength := range []int{16, 32} {
		data := build(t, "pässwörd ✓", []CreateOption{WithStrength(strength), WithLogin("alice")}, func(w *Writer) {
			for _, d := range order {
				mustMkdir(t, w, d)
			}
			for p, b := range files {
				mustAdd(t, w, p, b)
			}
		})
		a, err := open(t, data, "pässwörd ✓")
		if err != nil {
			t.Fatalf("strength %d: %v", strength, err)
		}
		in := a.Info()
		if in.Version != "0200" || in.EncryptionMode != modeCTS || in.KeyBytes != strength || in.PathName != "(none)" ||
			in.CreatedWith != createdWithDefault || !in.Created.Equal(epoch) ||
			len(in.Users) != 1 || in.Users[0] != (User{Login: "alice", Method: "password", Admin: true, HashFunc: hashPBKDF2SHA512, Iter: writePBAIter}) {
			t.Fatalf("strength %d: info %+v", strength, in)
		}
		for _, d := range order {
			if e := entry(t, a, d); !e.Dir {
				t.Fatalf("%s is not a directory", d)
			}
		}
		for p, want := range files {
			e := entry(t, a, p)
			got, err := a.ReadFile(e)
			if err != nil || !bytes.Equal(got, want) || e.Size != int64(len(want)) || e.Dir {
				t.Fatalf("strength %d: %s: %d bytes, %v", strength, p, len(got), err)
			}
		}
		if len(a.Entries()) != len(files)+len(order) {
			t.Fatalf("%d entries", len(a.Entries()))
		}
		if _, err := open(t, data, "other"); !errors.Is(err, ErrPassword) {
			t.Fatalf("wrong password: %v", err)
		}
	}
}

// The seal, the watermark and the options.
func TestCreateOptions(t *testing.T) {
	one := func(w *Writer) { mustAdd(t, w, "f.txt", []byte("hello")) }
	streams := func(data []byte) map[string]int64 {
		f := openCFB(t, data)
		got := map[string]int64{}
		for _, c := range f.Root().Children {
			got[c.Name] = c.Size
			for _, cc := range c.Children {
				got[c.Name+"/"+cc.Name] = cc.Size
			}
		}
		return got
	}
	full := streams(build(t, "pw", nil, one))
	if full[sealStreamName] != 8192 || full[metadataStream] == 0 || full[watermarkStorage+"/CONTENTS"] != 244 || full[watermarkStorage+"/prop0005"] == 0 {
		t.Fatalf("default streams %v", full)
	}
	none := build(t, "pw", []CreateOption{WithSeal(SealNone)}, one)
	if s := streams(none); s[sealStreamName] != 0 || s[metadataStream] >= full[metadataStream] {
		t.Fatalf("SealNone: %v", s)
	}
	propOnly := build(t, "pw", []CreateOption{WithSeal(SealPropertyOnly)}, one)
	if s := streams(propOnly); s[sealStreamName] != 0 || s[metadataStream] != full[metadataStream] {
		t.Fatalf("SealPropertyOnly: %v", s)
	}
	noWM := build(t, "pw", []CreateOption{WithoutWatermark()}, one)
	if s := streams(noWM); s[watermarkStorage+"/CONTENTS"] != 0 || s[sealStreamName] != 8192 {
		t.Fatalf("WithoutWatermark: %v", s)
	}
	for name, data := range map[string][]byte{"none": none, "propOnly": propOnly, "noWM": noWM} {
		a, err := open(t, data, "pw")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if b, err := a.ReadFile(entry(t, a, "f.txt")); err != nil || string(b) != "hello" {
			t.Fatalf("%s: %q %v", name, b, err)
		}
	}
	// The seal's three known hashes are the SHA-256 of _ctlfile, _catalog and the picture.
	a := build(t, "pw", []CreateOption{WithCreatedWith("{x}")}, one)
	if in := mustOpen(t, a, "pw").Info(); in.CreatedWith != "{x}" {
		t.Fatalf("createdwith %q", in.CreatedWith)
	}
	// Same random source and clock: the same archive, byte for byte.
	b1 := build(t, "pw", nil, one)
	b2 := build(t, "pw", nil, one)
	if !bytes.Equal(b1, b2) {
		t.Fatal("two archives from one random source and one clock differ")
	}
	if bytes.Equal(b1, build(t, "pw", []CreateOption{WithRandom(seeded(2))}, one)) {
		t.Fatal("another random source gave the same archive")
	}
}

func mustOpen(t testing.TB, data []byte, pw string) *Archive {
	t.Helper()
	a, err := open(t, data, pw)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func openCFB(t testing.TB, data []byte) *cfb.File {
	t.Helper()
	f, err := cfb.Open(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestCreateRefusals(t *testing.T) {
	var sink bytes.Buffer
	for name, opts := range map[string][]CreateOption{
		"strength 24":             {WithStrength(24)},
		"empty login":             {WithLogin("")},
		"login that is not UTF-8": {WithLogin("a\xffb")},
		"NUL login":               {WithLogin("a\x00b")},
	} {
		if _, err := Create(&sink, "pw", opts...); !errors.Is(err, ErrArgument) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Create(&sink, ""); !errors.Is(err, ErrArgument) {
		t.Errorf("empty password: %v", err)
	}
	w, err := Create(&sink, "pw", WithRandom(seeded(1)))
	if err != nil {
		t.Fatal(err)
	}
	mustMkdir(t, w, "dir")
	mustAdd(t, w, "dir/f", []byte("x"))
	for name, p := range map[string]string{
		"empty": "", "slash only": "/", "dot": ".", "dotdot": "a/..", "backslash": `a\b`, "colon": "a:b", "reserved": "CON", "reserved dir": "dir/nul.txt",
		"trailing dot": "a.", "not UTF-8": "a\xffb", "duplicate dir": "dir", "duplicate file": "dir/f", "no parent": "missing/x", "parent is a file": "dir/f/x",
	} {
		if err := w.Mkdir(p); !errors.Is(err, ErrArgument) {
			t.Errorf("Mkdir %s: %v", name, err)
		}
		if _, err := w.Create(p); !errors.Is(err, ErrArgument) {
			t.Errorf("Create %s: %v", name, err)
		}
	}
	// A file open while another path is added; an open file blocks Close.
	f, err := w.Create("dir/open")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); !errors.Is(err, ErrArgument) {
		t.Errorf("Close with an open file: %v", err)
	}
	if err := w.Mkdir("dir/open"); !errors.Is(err, ErrArgument) {
		t.Errorf("a pending file's path is taken: %v", err)
	}
	f.Write([]byte("data"))
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Errorf("second Close of a file: %v", err)
	}
	if _, err := f.Write([]byte("more")); !errors.Is(err, ErrArgument) {
		t.Errorf("Write after Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); !errors.Is(err, ErrArgument) {
		t.Errorf("Close twice: %v", err)
	}
	if err := w.Mkdir("late"); !errors.Is(err, ErrArgument) {
		t.Errorf("Mkdir after Close: %v", err)
	}
}

func TestCreateLimits(t *testing.T) {
	mk := func(opts ...CreateOption) *Writer {
		w, err := Create(io.Discard, "pw", append([]CreateOption{WithRandom(seeded(1))}, opts...)...)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	w := mk(WithWriteLimits(Limits{MaxEntries: 2}))
	mustMkdir(t, w, "a")
	mustMkdir(t, w, "b")
	if err := w.Mkdir("c"); !errors.Is(err, ErrLimit) {
		t.Errorf("entries: %v", err)
	}
	w = mk(WithWriteLimits(Limits{MaxDepth: 2}))
	mustMkdir(t, w, "a")
	mustMkdir(t, w, "a/b")
	if err := w.Mkdir("a/b/c"); !errors.Is(err, ErrLimit) {
		t.Errorf("depth: %v", err)
	}
	w = mk(WithWriteLimits(Limits{MaxPathBytes: 5}))
	mustMkdir(t, w, "abcde")
	if err := w.Mkdir("abcdef"); !errors.Is(err, ErrLimit) {
		t.Errorf("path bytes: %v", err)
	}
	w = mk(WithWriteLimits(Limits{MaxTotalPathBytes: 8}))
	mustMkdir(t, w, "abcde")
	if err := w.Mkdir("fghi"); !errors.Is(err, ErrLimit) {
		t.Errorf("total path bytes: %v", err)
	}
	// A file larger than MaxFileSize fails at the write that crosses it, and the
	// path is free again.
	w = mk(WithWriteLimits(Limits{MaxFileSize: 10}))
	if err := w.AddFile("big", bytes.NewReader(make([]byte, 11))); !errors.Is(err, ErrLimit) {
		t.Errorf("file size: %v", err)
	}
	mustAdd(t, w, "big", make([]byte, 10))
	f, _ := w.Create("second")
	f.Write(make([]byte, 6))
	if _, err := f.Write(make([]byte, 6)); !errors.Is(err, ErrLimit) {
		t.Errorf("file size across writes: %v", err)
	}
	if _, err := f.Write([]byte("x")); !errors.Is(err, ErrLimit) {
		t.Errorf("a failed file keeps failing: %v", err)
	}
	if err := f.Close(); !errors.Is(err, ErrLimit) {
		t.Errorf("Close of a failed file: %v", err)
	}
	// The archive's total.
	w = mk(WithMaxArchiveSize(3000))
	if err := w.AddFile("noise", bytes.NewReader(random(5000, 1))); !errors.Is(err, ErrLimit) {
		t.Errorf("archive size: %v", err)
	}
	// Metadata above the reader's limit is refused at Close, never written.
	w = mk(WithWriteLimits(Limits{MaxMetadata: 200}))
	mustMkdir(t, w, "a")
	if err := w.Close(); !errors.Is(err, ErrLimit) {
		t.Errorf("metadata: %v", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestCreateErrorsPropagate(t *testing.T) {
	w, _ := Create(io.Discard, "pw", WithRandom(seeded(1)))
	if err := w.AddFile("f", errReader{}); err == nil || err.Error() != "read failed" {
		t.Errorf("a failing reader: %v", err)
	}
	mustAdd(t, w, "f", []byte("the path is free again after a failed AddFile"))
	// A failing destination.
	w2, _ := Create(failWriter{}, "pw", WithRandom(seeded(1)))
	mustAdd(t, w2, "f", []byte("x"))
	if err := w2.Close(); err == nil || err.Error() != "disk full" {
		t.Errorf("a failing destination: %v", err)
	}
	// A failing random source, whichever draw it fails at.
	failures := 0
	// The derivations are not what this loop tests: make them cheap.
	oldKDF := pbkdf2Key
	pbkdf2Key = func(h func() hash.Hash, pw string, salt []byte, iter, n int) ([]byte, error) {
		return oldKDF(h, pw, salt, 1, n)
	}
	defer func() { pbkdf2Key = oldKDF }()
	for n := 0; n < 450; n++ {
		var out bytes.Buffer
		w, err := Create(&out, "pw", WithRandom(failingRand(n)), WithClock(fixedClock()))
		if err == nil {
			err = w.Mkdir("d")
		}
		if err == nil {
			err = w.AddFile("d/f", strings.NewReader("hello"))
		}
		if err == nil {
			err = w.Close()
		}
		if err != nil {
			failures++
		}
	}
	if failures < 250 || failures >= 450 {
		t.Errorf("%d of 450 runs failed: the random failures were not all noticed, or some run could never succeed", failures)
	}
	// A random source that repeats itself gives two files one identifier.
	zero := readerFunc(func(p []byte) (int, error) { return len(p), nil })
	w3, err := Create(io.Discard, "pw", WithRandom(zero))
	if err != nil {
		t.Fatal(err)
	}
	mustMkdir(t, w3, "a")
	if err := w3.Mkdir("b"); err == nil || !strings.Contains(err.Error(), "repeated") {
		t.Errorf("a repeated identifier: %v", err)
	}
	// The last, partial chunk crossing the archive size limit fails at Close.
	w4, _ := Create(io.Discard, "pw", WithRandom(seeded(3)), WithMaxArchiveSize(10))
	if err := w4.AddFile("small", strings.NewReader("hello hello hello")); !errors.Is(err, ErrLimit) {
		t.Errorf("the last chunk over the archive limit: %v", err)
	}
}

// The standard library refuses some inputs only in FIPS-only mode: that is
// reported, not turned into a different archive.
func TestCreateReportsAFailingKDF(t *testing.T) {
	old := pbkdf2Key
	defer func() { pbkdf2Key = old }()
	for failAt := 1; failAt <= 2; failAt++ {
		calls := 0
		pbkdf2Key = func(h func() hash.Hash, pw string, salt []byte, iter, n int) ([]byte, error) {
			calls++
			if calls == failAt {
				return nil, errors.New("fips only")
			}
			return old(h, pw, salt, iter, n)
		}
		if _, err := Create(io.Discard, "pw", WithRandom(seeded(1))); !errors.Is(err, ErrUnsupported) {
			t.Errorf("KDF call %d failing: %v", failAt, err)
		}
	}
}

// What the reader's limits say, the writer says first: an archive the writer
// accepts is one Open reads.
func TestWriterNeverWritesWhatOpenRefuses(t *testing.T) {
	w, _ := Create(io.Discard, "pw")
	long := strings.Repeat("a", 300)
	if err := w.Mkdir(long); err != nil {
		t.Fatal(err) // 300 bytes is under the path limit
	}
	if _, err := w.Create(strings.Repeat("a/", 300)); err == nil {
		t.Error("a path of 600 bytes and depth 300")
	}
}

// The tags of the _ctlfile and the _catalog, in order, as a ZED! Free 2026.3
// container has them (read from two real containers): a literal, so a change to
// the writer's layout cannot follow itself.
const (
	goldenControl = "80100200 80110600(00220300 00230400 80250300 80270200 80260200 80280500 80290200) " +
		"80140600(80610600(80710400 80720300 807e0100 00830200 80740500 80750200 80760500 80770200 80780200 80790500 807a0500 807b0200 807c0200 00840500)) " +
		"001b0600(00c00400 00c40500 00c80200 00c90200) 801c0600(00e00500 00e10200 00e20500 00e30300 00e40200) 001d0600(00f00200 00f10200 00f20200)"
	goldenCatalog = "80100200 00120100 00130100 00140200 00150100 " +
		"80110600(80300500 00370500 80310400 80330500 80340500 80350500 80360500 00380500 00390500 00400500 00410500) " +
		"80110600(80300500 00370500 80310400 80320100 80330500 80340500 80350500 80360500 00380500)"
)

// skeleton lists the tags of a TLV sequence, nesting in parentheses.
func skeleton(b []byte, nested map[uint32]bool) string {
	items, err := parseTLV(b)
	if err != nil {
		return "BAD"
	}
	var parts []string
	for _, it := range items {
		s := hex8(it.tag)
		if nested[it.tag] {
			s += "(" + skeleton(it.val, nested) + ")"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}

func hex8(v uint32) string {
	const h = "0123456789abcdef"
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = h[v&15]
		v >>= 4
	}
	return string(b)
}

var skeletonNest = map[uint32]bool{0x80110600: true, 0x80140600: true, 0x80610600: true, 0x001b0600: true, 0x801c0600: true, 0x001d0600: true}

func TestWrittenStructureIsThatOfAZED2026Container(t *testing.T) {
	data := build(t, "pw", nil, func(w *Writer) {
		mustAdd(t, w, "File.png", []byte("not really a png"))
		mustMkdir(t, w, "Folder")
	})
	f := openCFB(t, data)
	if f.Version() != 4 || f.Root().CLSID != rootCLSID {
		t.Fatalf("container: version %d clsid %x", f.Version(), f.Root().CLSID)
	}
	var names []string
	for _, c := range f.Root().Children {
		names = append(names, c.Name)
	}
	if len(names) != 4 { // the seal, the metadata, the watermark storage, the file
		t.Fatalf("root children %q", names)
	}
	if wm := f.Lookup(watermarkStorage); wm == nil || wm.CLSID != watermarkCLSID || len(wm.Children) != 2 {
		t.Fatalf("watermark storage %+v", wm)
	}
	meta, _ := f.ReadAll(f.Lookup(metadataStream), 1<<20)
	ctlBlob, catBlob, err := blobs(meta)
	if err != nil {
		t.Fatal(err)
	}
	plain := decryptStream(mustAES(staticKey), ctlBlob[18:34], ctlBlob[34:len(ctlBlob)-36])
	if got := skeleton(plain, skeletonNest); got != goldenControl {
		t.Errorf("_ctlfile tags\n got %s\nwant %s", got, goldenControl)
	}
	// The catalog lists the file, then the folder, as the real one does.
	if got := skeleton(catBlob, map[uint32]bool{0x80110600: true}); got != goldenCatalog {
		t.Errorf("_catalog tags\n got %s\nwant %s", got, goldenCatalog)
	}
	// The property table of the metadata: code page, locale, dictionary, 3 blobs.
	le := leOrder
	set := meta[le.Uint32(meta[44:]):]
	var ids []uint32
	for i := uint32(0); i < le.Uint32(set[4:]); i++ {
		ids = append(ids, le.Uint32(set[8+8*i:]))
	}
	if want := []uint32{1, 0x80000000, 0, 4, 5, 6}; !equalU32(ids, want) {
		t.Errorf("properties %v, want %v", ids, want)
	}
	if len(watermarkContents) != 244 {
		t.Errorf("CONTENTS is %d bytes, ZED writes 244", len(watermarkContents))
	}
	if len(watermarkPNG()) < 100 {
		t.Error("the watermark picture")
	}
}

func equalU32(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Against real containers, when there are any: the same skeleton, the same
// streams and the same sizes of the fixed fields.
func TestStructureMatchesRealContainers(t *testing.T) {
	files, _ := corpus(t)
	mine := build(t, "pw", nil, func(w *Writer) {
		mustAdd(t, w, "File1.png", []byte("x"))
		mustMkdir(t, w, "Folder1")
	})
	mf := openCFB(t, mine)
	for _, p := range files {
		real := mustReadFile(t, p)
		rf := openCFB(t, real)
		if rf.Version() != mf.Version() || rf.Root().CLSID != mf.Root().CLSID || len(rf.Root().Children) != len(mf.Root().Children) {
			t.Errorf("%s: container differs", p)
		}
		rm, _ := rf.ReadAll(rf.Lookup(metadataStream), 1<<20)
		mm, _ := mf.ReadAll(mf.Lookup(metadataStream), 1<<20)
		rc, rk, _ := blobs(rm)
		mc, mk, _ := blobs(mm)
		rp := decryptStream(mustAES(staticKey), rc[18:34], rc[34:len(rc)-36])
		mp := decryptStream(mustAES(staticKey), mc[18:34], mc[34:len(mc)-36])
		if skeleton(rp, skeletonNest) != skeleton(mp, skeletonNest) {
			t.Errorf("%s: _ctlfile skeleton differs", p)
		}
		if skeleton(rk, map[uint32]bool{0x80110600: true}) != skeleton(mk, map[uint32]bool{0x80110600: true}) {
			t.Errorf("%s: _catalog skeleton differs", p)
		}
		rs, _ := rf.ReadAll(rf.Lookup(sealStreamName), 1<<20)
		ms, _ := mf.ReadAll(mf.Lookup(sealStreamName), 1<<20)
		if len(rs) != len(ms) || skeleton(rs[8:8+leOrder.Uint32(rs[4:])], map[uint32]bool{0x80120600: true, 0x80130600: true}) !=
			skeleton(ms[8:8+leOrder.Uint32(ms[4:])], map[uint32]bool{0x80120600: true, 0x80130600: true}) {
			t.Errorf("%s: seal stream differs", p)
		}
		rcn, _ := rf.ReadAll(rf.Lookup(watermarkStorage+"/CONTENTS"), 1<<20)
		if !bytes.Equal(rcn, watermarkContents) {
			t.Errorf("%s: CONTENTS differs from the template", p)
		}
		if len(rm) != len(mm) && len(rc) == len(mc) {
			t.Errorf("%s: metadata sizes differ", p)
		}
	}
}

// FuzzCreate feeds the writer names, sizes and tree shapes taken from the
// input: whatever it accepts, Open must read back, and whatever it refuses is
// ErrArgument or ErrLimit.
func FuzzCreate(f *testing.F) {
	f.Add([]byte("\x00dir\x00\x01dir/a.txt\x05hello\x01b\x00\x00\x01c\xff"), uint8(0))
	f.Add([]byte("\x01\xc3\xa9t\xc3\xa9.txt\x10x\x00CON\x00a:b\x00..\x00"), uint8(1))
	old := pbkdf2Key
	pbkdf2Key = func(h func() hash.Hash, pw string, salt []byte, iter, n int) ([]byte, error) { // cheap: not under test
		return old(h, pw, salt, 1, n)
	}
	f.Cleanup(func() { pbkdf2Key = old })
	f.Fuzz(func(t *testing.T, in []byte, strength uint8) {
		var out bytes.Buffer
		w, err := Create(&out, "pw", WithRandom(seeded(uint64(strength))), WithClock(fixedClock()), WithStrength(16+16*int(strength%2)),
			WithWriteLimits(Limits{MaxEntries: 40, MaxDepth: 4, MaxPathBytes: 60, MaxTotalPathBytes: 400, MaxFileSize: 5000}), WithMaxArchiveSize(1<<16))
		if err != nil {
			t.Fatal(err)
		}
		type want struct {
			dir  bool
			data []byte
		}
		accepted := map[string]want{}
		for len(in) >= 2 {
			kind, nl := in[0]%2, int(in[1])%24
			in = in[2:]
			nl = min(nl, len(in))
			name := string(in[:nl])
			in = in[nl:]
			p := name
			for q, v := range accepted { // under some known directory
				if v.dir && kind == 1 {
					p = q + "/" + name
					break
				}
			}
			var err error
			if kind == 0 {
				if err = w.Mkdir(p); err == nil {
					accepted[strings.Trim(p, "/")] = want{dir: true}
				}
			} else {
				n := 0
				if len(in) > 0 {
					n = int(in[0]) * 25
					in = in[1:]
				}
				data := bytes.Repeat([]byte("zed"), n/3+1)[:n]
				if err = w.AddFile(p, bytes.NewReader(data)); err == nil {
					accepted[strings.Trim(p, "/")] = want{data: data}
				}
			}
			if err != nil && !errors.Is(err, ErrArgument) && !errors.Is(err, ErrLimit) {
				t.Fatalf("unexpected error %v", err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		a, err := Open(bytes.NewReader(out.Bytes()), int64(out.Len()), "pw")
		if err != nil {
			t.Fatalf("the archive does not open: %v", err)
		}
		if len(a.Entries()) != len(accepted) {
			t.Fatalf("%d entries, %d accepted", len(a.Entries()), len(accepted))
		}
		for p, v := range accepted {
			e := a.Lookup(p)
			if e == nil || e.Dir != v.dir {
				t.Fatalf("%q lost or changed kind", p)
			}
			if !v.dir {
				got, err := a.ReadFile(e)
				if err != nil || !bytes.Equal(got, v.data) {
					t.Fatalf("%q: %v", p, err)
				}
			}
		}
	})
}
