package zed

// Regression tests for the review of the first version: costs that came from
// the file (catalog depth, derivation lengths and counts), names, and
// tag values written out as literal bytes.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func deepID(n int) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint32(b, uint32(n)+1)
	return b
}

// halfEntry is a catalog entry named by its half-anonymised name (no cipher).
func halfEntry(id, parent int, name string, dir bool) []byte {
	items := [][]byte{put(tagFileID, deepID(id)), put(tagHalfAnon, u16(name))}
	if dir {
		items = append(items, put(tagIsDir, []byte{1}))
	}
	if parent >= 0 {
		items = append(items, put(tagParentID, deepID(parent)))
	}
	return put(tagFileProps, cat(items...))
}

func testDecryptor(t testing.TB) *decryptor {
	d, err := newDecryptor(make([]byte, 16), make([]byte, 16), modeStream)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// chain is n directories, each the child of the one before, with names of
// nameLen characters.
func chain(n, nameLen int) []byte {
	var parts [][]byte
	for k := 0; k < n; k++ {
		parts = append(parts, halfEntry(k, k-1, strings.Repeat("a", nameLen), true))
	}
	return cat(parts...)
}

// The path of every entry used to be rebuilt by walking its whole parent chain
// and joining strings again: a legal 4000-deep chain of 100-character names
// took 30 s. It is refused now, by a counter, before any path is built.
func TestDeepCatalogIsRefusedQuickly(t *testing.T) {
	d := testDecryptor(t)
	for _, n := range []int{1000, 4000, 20000} {
		start := time.Now()
		_, err := parseCatalog(chain(n, 100), d, DefaultLimits())
		if !errors.Is(err, ErrLimit) {
			t.Errorf("chain of %d: %v", n, err)
		}
		if took := time.Since(start); took > time.Second {
			t.Errorf("chain of %d took %v", n, took)
		}
	}
	// Two directories that are each other's parent, among filler entries.
	var parts [][]byte
	for k := 0; k < 4000; k++ {
		parent := -1
		if k < 2 {
			parent = 1 - k
		}
		parts = append(parts, halfEntry(k, parent, strings.Repeat("a", 100), true))
	}
	start := time.Now()
	if _, err := parseCatalog(cat(parts...), d, DefaultLimits()); !errors.Is(err, ErrFormat) {
		t.Errorf("cycle: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Errorf("cycle took %v", time.Since(start))
	}
}

// A catalog exactly at the depth and path caps opens, in bounded time and with
// a bounded number of allocations; one level or one byte more is refused.
func TestCatalogAtTheCaps(t *testing.T) {
	d := testDecryptor(t)
	lim := DefaultLimits() // depth 256, path 4096 bytes
	build := func(depth, nameLen, leaves int) []byte {
		var parts [][]byte
		for k := 0; k < depth; k++ {
			parts = append(parts, halfEntry(k, k-1, strings.Repeat("d", nameLen), true))
		}
		for l := 0; l < leaves; l++ { // files in the deepest directory
			parts = append(parts, halfEntry(depth+l, depth-1, fmt.Sprintf("f%0*d", nameLen-1, l), false))
		}
		return cat(parts...)
	}
	// 256 levels of 15 characters: a path of 256*15+255 = 4095 bytes; the
	// leaves make it 4095 + 1 + 15 = 4111 > 4096 unless they sit one level up.
	atCap := build(255, 15, 3000) // deepest file: 255 dirs + file = 256 levels, 255*16+15 = 4095 bytes
	start := time.Now()
	var entries []Entry
	allocs := testing.AllocsPerRun(1, func() {
		var err error
		if entries, err = parseCatalog(atCap, d, lim); err != nil {
			t.Fatal(err)
		}
	})
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("a catalog at the caps took %v", took)
	}
	if limit := float64(200 * len(entries)); allocs > limit {
		t.Errorf("%.0f allocations for %d entries (more than %.0f)", allocs, len(entries), limit)
	}
	if len(entries) != 3255 || len(entries[len(entries)-1].Path) != 4095 {
		t.Errorf("%d entries, last path %d bytes", len(entries), len(entries[len(entries)-1].Path))
	}
	if _, err := parseCatalog(build(256, 15, 1), d, lim); !errors.Is(err, ErrLimit) {
		t.Errorf("257 levels: %v", err)
	}
	if _, err := parseCatalog(build(255, 16, 1), d, lim); !errors.Is(err, ErrLimit) {
		t.Errorf("a path of 4351 bytes: %v", err)
	}
	if _, err := parseCatalog(build(3, 8, 1), d, lim); err != nil {
		t.Errorf("a small tree: %v", err)
	}
	custom := lim
	custom.MaxDepth = 2
	if _, err := parseCatalog(build(3, 8, 0), d, custom); !errors.Is(err, ErrLimit) {
		t.Errorf("custom depth: %v", err)
	}
	custom = lim
	custom.MaxPathBytes = 20
	if _, err := parseCatalog(build(3, 8, 0), d, custom); !errors.Is(err, ErrLimit) {
		t.Errorf("custom path length: %v", err)
	}
}

func TestDuplicatePathsAreRefused(t *testing.T) {
	d := testDecryptor(t)
	two := cat(halfEntry(1, -1, "same", false), halfEntry(2, -1, "same", false))
	if _, err := parseCatalog(two, d, DefaultLimits()); !errors.Is(err, ErrFormat) {
		t.Fatalf("two files with one path: %v", err)
	}
	nested := cat(halfEntry(0, -1, "dir", true), halfEntry(1, 0, "x", false), halfEntry(2, -1, "dir", true), halfEntry(3, 2, "x", false))
	if _, err := parseCatalog(nested, d, DefaultLimits()); !errors.Is(err, ErrFormat) {
		t.Fatalf("two directories with one path: %v", err)
	}
	ok := cat(halfEntry(0, -1, "a", true), halfEntry(1, 0, "x", false), halfEntry(2, -1, "b", true), halfEntry(3, 2, "x", false))
	if es, err := parseCatalog(ok, d, DefaultLimits()); err != nil || es[1].Path != "a/x" || es[3].Path != "b/x" {
		t.Fatalf("same name in two directories: %v", err)
	}
}

func TestUnusableNames(t *testing.T) {
	bad := []string{"", ".", "..", "a/b", `a\b`, "a:b", "C:", "file:stream", "a\x00b",
		"CON", "con", "PRN", "AUX", "NUL", "COM1", "com9", "LPT1", "lpt9",
		"CON.txt", "nul.tar.gz", "Aux.x", "COM5.dat", "con ", "LPT3 .txt",
		// go-fde/zed#5: what Go's Windows filepath.IsLocal refuses, on every OS.
		"a.", "a ", "file.txt.", "name  ", "x...", "CONIN$", "conin$", "CONOUT$", "ConOut$", "CONIN$.txt", "CONOUT$ .log",
		"COM¹", "com²", "COM³.x", "LPT¹", "lpt² .txt", "LPT³"}
	for _, n := range bad {
		if usableName(n) {
			t.Errorf("%q accepted", n)
		}
	}
	good := []string{"a", "file.txt", "CONSOLE", "COM0", "COM10", "LPT0", "COMX", "xcon", "con-1.txt", "résumé ✓.txt", ".hidden", "a b", "NULL", "AUXILIARY.txt",
		"CONIN", "CONOUT", "CONIN$$", "COM¹¹", "COM⁴", "COM½", "LPT´", "a.b", "a .b", "à la carte"}
	for _, n := range good {
		if !usableName(n) {
			t.Errorf("%q refused", n)
		}
	}
	// And through a whole archive.
	for _, name := range []string{"a:b", "CON", "nul.txt", "LPT1", "CONIN$", "COM²", "trailing.", "trailing "} {
		a := defaultArchive()
		a.root = []*tNode{{name: name, data: []byte("x")}}
		expect(t, "name "+name, a, ErrFormat)
	}
}

// pba_checksum, the salts and the wrapped key have lengths that come from the
// file and are used before any password is known.
func TestDerivationInputsAreBounded(t *testing.T) {
	big := make([]byte, 8<<10)
	cases := []struct {
		name string
		a    tArchive
	}{
		{"pba_checksum of 8 KiB", small().with(ed{"user", tagPBAChecksum, big})},
		{"pba_checksum longer than the hash (SHA-256, 33)", small().with(ed{"user", tagPBAChecksum, make([]byte, 33)})},
		{"pba_checksum empty", small().with(ed{"user", tagPBAChecksum, []byte{}})},
		{"pba salt of 8 KiB", small().with(ed{"user", tagPBASalt, big})},
		{"pbe salt of 8 KiB", small().with(ed{"user", tagPBESalt, big})},
		{"wrapped key of 8 KiB", small().with(ed{"user", tagFilesKeyCT, big})},
	}
	for _, c := range cases {
		start := time.Now()
		expect(t, c.name, c.a, ErrFormat)
		if time.Since(start) > time.Second {
			t.Errorf("%s: took %v", c.name, time.Since(start))
		}
	}
	// SHA-1 allows 20, SHA-256 32: a checksum of that length is read, and a
	// wrong one is a wrong password, not a format error.
	for hash, n := range map[uint32]int{hashSHA1: 20, hashSHA256: 32} {
		a := small()
		a.users[0].hash = hash
		_, err := open(t, a.with(ed{"user", tagPBAChecksum, make([]byte, n)}).bytes(t), "s3cret")
		if !errors.Is(err, ErrPassword) {
			t.Errorf("hash %d, checksum of %d bytes: %v", hash, n, err)
		}
	}
}

// An empty pba_checksum compared equal to an empty derivation: any password
// opened the user. It must never reach the comparison.
func TestEmptyChecksumAcceptsNoPassword(t *testing.T) {
	g := &control{info: Info{KeyBytes: 16}, users: []user{{hash: hashSHA256, pbaIter: 1, pbeIter: 1, pbaSum: []byte{}, files: make([]byte, 16)}}}
	if _, err := g.unlock("any password", DefaultLimits()); !errors.Is(err, ErrFormat) {
		t.Fatalf("got %v", err)
	}
}

// The limit on iterations is per user; the work is bounded for all of them.
func TestTotalDerivationWorkIsBounded(t *testing.T) {
	var users []user
	for i := 0; i < 64; i++ {
		users = append(users, user{hash: hashSHA256, pbaIter: 1_000_000, pbeIter: 1000, pbaSalt: make([]byte, 8), pbeSalt: make([]byte, 8),
			pbaSum: make([]byte, 8), files: make([]byte, 16)})
	}
	g := &control{info: Info{KeyBytes: 16}, users: users}
	start := time.Now()
	if _, err := g.unlock("x", DefaultLimits()); !errors.Is(err, ErrLimit) {
		t.Fatalf("64 users of one million iterations: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("the total was checked after deriving")
	}
	// Users at the per-user cap are each allowed; together they are not.
	at := user{hash: hashSHA1, pbaIter: 10_000_000, pbeIter: 1, pbaSalt: make([]byte, 8), pbeSalt: make([]byte, 8), pbaSum: make([]byte, 8), files: make([]byte, 16)}
	g.users = []user{at, at, at, at}
	if _, err := g.unlock("x", DefaultLimits()); !errors.Is(err, ErrLimit) {
		t.Fatalf("four users at 10M: %v", err)
	}
	lim := DefaultLimits()
	lim.MaxTotalIterations = 7
	g.users = []user{{hash: hashSHA1, pbaIter: 2, pbeIter: 1, pbaSalt: []byte{1}, pbeSalt: []byte{1}, pbaSum: make([]byte, 8), files: make([]byte, 16)}}
	if _, err := g.unlock("x", lim); !errors.Is(err, ErrPassword) { // 2 + 3*1 = 5 <= 7
		t.Fatalf("inside the total: %v", err)
	}
	lim.MaxTotalIterations = 4
	if _, err := g.unlock("x", lim); !errors.Is(err, ErrLimit) { // 5 > 4
		t.Fatalf("outside the total: %v", err)
	}
}

// lit is a TLV item whose tag is written out as hex, independent of the tag
// constants the reader and the test builder share: renumbering a constant
// breaks these tests.
func lit(tagHex string, vals ...[]byte) []byte {
	tag, err := hex.DecodeString(tagHex)
	if err != nil || len(tag) != 4 {
		panic("bad tag " + tagHex)
	}
	return put(binary.BigEndian.Uint32(tag), vals...)
}

func TestTagsAsLiteralBytes(t *testing.T) {
	// A whole _ctlfile and _catalog written with literal tags (the names are
	// in Beucler's tables), a password user derived at low cost.
	key, iv := bytes.Repeat([]byte{0x21}, 16), bytes.Repeat([]byte{0x22}, 16)
	pbeSalt, pbaSalt := bytes.Repeat([]byte{1}, 8), bytes.Repeat([]byte{2}, 8)
	h, _ := hashFor(hashSHA256)
	pw := bmpPassword("literal")
	kek := pkcs12KDF(h, pw, pbeSalt, 1, 4, 32)[:16]
	kiv := pkcs12KDF(h, pw, pbeSalt, 2, 4, 16)
	wrapped := make([]byte, 32)
	copy(wrapped, key)
	for i := 16; i < 32; i++ {
		wrapped[i] = 16
	}
	blk := mustAES(kek)
	cbcEncrypt(blk, kiv, wrapped)
	user := lit("80610600",
		lit("80710400", u16("lit")), lit("807e0100", []byte{1}), lit("80740500", wrapped),
		lit("80760500", pbeSalt), lit("80770200", be32(4)), lit("80780200", be32(22)),
		lit("80790500", pkcs12KDF(h, pw, pbaSalt, 3, 3, 8)), lit("807a0500", pbaSalt), lit("807b0200", be32(3)))
	plain := cat(
		lit("80110600", lit("00230400", u16("(none)")), lit("80270200", be32(104)), lit("80260200", be32(16)), lit("80280500", iv)),
		lit("001b0600", lit("00c40500", ftBytes(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))), lit("00c00400", u16("{literal}"))),
		lit("80140600", user),
	)
	ctl := obfuscate("0200", bytes.Repeat([]byte{9}, 16), plain)

	d, _ := newDecryptor(key, iv, modeCTS)
	id, parent := bytes.Repeat([]byte{0x31}, 16), make([]byte, 16)
	dirID := bytes.Repeat([]byte{0x32}, 16)
	catalog := cat(
		lit("80110600", lit("80300500", dirID), lit("00370500", parent), lit("00380500", d.encrypt(iv, nameBytes("folder"))),
			lit("80330500", le64(0)), lit("80320100", []byte{1})),
		lit("80110600", lit("80300500", id), lit("00370500", dirID), lit("00380500", d.encrypt(iv, nameBytes("note.txt"))),
			lit("80330500", le64(5)), lit("80340500", ftBytes(time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC))),
			lit("80350500", ftBytes(time.Date(2026, 3, 4, 5, 6, 8, 0, time.UTC))), lit("80360500", ftBytes(time.Date(2026, 3, 4, 5, 6, 9, 0, time.UTC)))),
	)
	g, err := parseControl(ctl, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	in := g.info
	if in.Version != "0200" || in.PathName != "(none)" || in.EncryptionMode != 104 || in.KeyBytes != 16 || in.CreatedWith != "{literal}" ||
		!in.Created.Equal(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)) ||
		len(in.Users) != 1 || in.Users[0] != (User{Login: "lit", Method: "password", Admin: true, HashFunc: 22, Iter: 3}) {
		t.Fatalf("info %+v", in)
	}
	got, err := g.unlock("literal", DefaultLimits())
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("unlock: %v", err)
	}
	if _, err := g.unlock("other", DefaultLimits()); !errors.Is(err, ErrPassword) {
		t.Fatalf("wrong password: %v", err)
	}
	es, err := parseCatalog(catalog, d, DefaultLimits())
	if err != nil || len(es) != 2 || es[0].Path != "folder" || !es[0].Dir || es[1].Path != "folder/note.txt" || es[1].Size != 5 ||
		!es[1].Created.Equal(time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)) || !es[1].Modified.Equal(time.Date(2026, 3, 4, 5, 6, 8, 0, time.UTC)) ||
		!es[1].Accessed.Equal(time.Date(2026, 3, 4, 5, 6, 9, 0, time.UTC)) {
		t.Fatalf("catalog: %v %+v", err, es)
	}
}
