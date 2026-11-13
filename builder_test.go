package zed

// A test-only writer of .zed archives, the inverse of the reader. Each piece
// is checked against the 2017 test vectors on the way in (TestVector*), so a
// round trip through it tests the container, not only the writer against the
// reader.

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"
	"time"

	"github.com/go-filesystems/cfb/cfbtest"
)

func cmpOr(a, b int) int {
	if a != 0 {
		return a
	}
	return b
}

// olepsOpts shape the metadata stream.
type olepsOpts struct {
	noDict    bool // IDs 3 and 4, as the 2017 document says
	codepage  uint16
	dictLast  bool
	extraBlob bool // a third blob, like ZED's _seal
	cpLast    bool // the code page property comes after the dictionary
}

// bareCFB is a valid compound file that is not a .zed archive.
func bareCFB(t testing.TB) []byte {
	out, _ := cfbtest.Build(3, cfbtest.Storage("Root Entry", cfbtest.Stream("other", []byte("x"))), false)
	return out
}

func oleps(ctl, catalog []byte, o olepsOpts) []byte {
	le := binary.LittleEndian
	if o.codepage == 0 {
		o.codepage = 1200
	}
	blob := func(b []byte) []byte {
		v := cat(le.AppendUint16(nil, vtBlob), []byte{0, 0}, le.AppendUint32(nil, uint32(len(b))), b)
		for len(v)%4 != 0 {
			v = append(v, 0)
		}
		return v
	}
	type prop struct {
		id  uint32
		val []byte
	}
	ctlID, catID := uint32(4), uint32(5)
	if o.noDict {
		ctlID, catID = 3, 4
	}
	cp := prop{propCodePage, cat(le.AppendUint16(nil, vtI2), []byte{0, 0}, le.AppendUint16(nil, o.codepage), []byte{0, 0})}
	var props []prop
	if !o.cpLast {
		props = append(props, cp)
	}
	var dict []byte
	if !o.noDict {
		names := []struct {
			id   uint32
			name string
		}{{ctlID, nameCtlfile}, {catID, nameCatalog}, {6, "_seal"}}
		dict = le.AppendUint32(nil, uint32(len(names)))
		for _, n := range names {
			var raw []byte
			length := len(n.name) + 1
			if o.codepage == cpUTF16 {
				raw = u16(n.name)
			} else {
				raw = append([]byte(n.name), 0)
			}
			dict = cat(dict, le.AppendUint32(nil, n.id), le.AppendUint32(nil, uint32(length)), raw)
			for o.codepage == cpUTF16 && len(dict)%4 != 0 {
				dict = append(dict, 0)
			}
		}
	}
	if !o.dictLast && dict != nil {
		props = append(props, prop{propDictionary, dict})
	}
	props = append(props, prop{ctlID, blob(ctl)}, prop{catID, blob(catalog)})
	if o.extraBlob {
		props = append(props, prop{6, blob([]byte("seal"))})
	}
	if o.dictLast && dict != nil {
		props = append(props, prop{propDictionary, dict})
	}
	if o.cpLast {
		props = append(props, cp)
	}
	head := 8 + 8*len(props)
	table, body := []byte(nil), []byte(nil)
	for _, p := range props {
		table = cat(table, le.AppendUint32(nil, p.id), le.AppendUint32(nil, uint32(head+len(body))))
		body = append(body, p.val...)
	}
	set := cat(le.AppendUint32(nil, uint32(head+len(body))), le.AppendUint32(nil, uint32(len(props))), table, body)
	hdr := cat(le.AppendUint16(nil, 0xFFFE), make([]byte, 2+4+16), le.AppendUint32(nil, 1), make([]byte, 16), le.AppendUint32(nil, 48))
	return cat(hdr, set)
}

type tUser struct {
	login, password string
	hash            uint32 // 21 or 22
	iter            uint32
	rsa             bool
}

type tNode struct {
	name string
	data []byte
	kids []*tNode // a node with kids (or dir) is a directory
	dir  bool
}

type tArchive struct {
	version string
	mode    uint32
	key     []byte
	iv      []byte
	users   []tUser
	root    []*tNode
	opts    olepsOpts
	created time.Time
	// edit sees every TLV item before it is written and may change its value
	// or drop it; extra adds raw bytes at the end of a level. Levels: top,
	// glob, extra, acl, user, catalog, entry.
	edit  func(level string, tag uint32, val []byte) ([]byte, bool)
	extra map[string][]byte
	// rawCtl and rawCatalog replace the generated _ctlfile plaintext and catalog.
	rawCtl, rawCatalog []byte
	// zhook may damage a file's zlib stream before it is encrypted.
	zhook func(name string, z []byte) []byte
	// kekLen overrides the length of the key encryption key (default: the
	// file key's length); cfbExtra adds nodes to the container's root.
	kekLen      int
	cfbExtra    []*cfbtest.Node
	dropStreams bool
	// globalIV writes a 0200 archive with the global IV alone, the way the 2017
	// document describes: a reader that knows the real rule must not read it.
	globalIV bool
}

// p writes one item of a level, through the edit hook.
func (a tArchive) p(level string, tag uint32, vals ...[]byte) []byte {
	v := bytes.Join(vals, nil)
	if a.edit != nil {
		var keep bool
		if v, keep = a.edit(level, tag, v); !keep {
			return nil
		}
	}
	return put(tag, v)
}

// box writes a container item holding children and the level's extra bytes.
func (a tArchive) box(level string, tag uint32, inner string, children ...[]byte) []byte {
	return a.p(level, tag, cat(children...), a.extra[inner])
}

func defaultArchive() tArchive {
	return tArchive{
		version: "0200", mode: modeCTS, key: bytes.Repeat([]byte{0x42}, 16),
		iv:      bytes.Repeat([]byte{0x17}, 16),
		users:   []tUser{{login: "alice", password: "s3cret", hash: 22, iter: 5}},
		created: time.Date(2026, 11, 11, 15, 9, 17, 0, time.UTC),
	}
}

func (a tArchive) userTLV(t testing.TB, u tUser, idx int) []byte {
	t.Helper()
	if u.rsa {
		return a.box("acl", tagRSAUser, "user", a.p("user", tagLogin, u16(u.login)), a.p("user", tagFilesKeyCT, []byte("rsa ciphertext")), a.p("user", 0x807d0500, []byte("cert")))
	}
	h, err := hashFor(u.hash)
	if err != nil {
		t.Fatal(err)
	}
	pbeSalt := bytes.Repeat([]byte{byte(0xA0 + idx)}, 8)
	pbaSalt := bytes.Repeat([]byte{byte(0xB0 + idx)}, 8)
	kek, iv, err := h.keyIV(u.password, pbeSalt, int(u.iter), cmpOr(a.kekLen, len(a.key)))
	if err != nil {
		t.Fatal(err)
	}
	sum, err := h.check(u.password, pbaSalt, int(u.iter), 8)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := aes.NewCipher(kek)
	pad := aesBlock - len(a.key)%aesBlock
	padded := append(append([]byte(nil), a.key...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	files := make([]byte, len(padded))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(files, padded)
	return a.box("acl", tagPasswordUser, "user",
		a.p("user", tagLogin, u16(u.login)), a.p("user", 0x807e0100, []byte{1}),
		a.p("user", tagFilesKeyCT, files), a.p("user", tagPBESalt, pbeSalt), a.p("user", tagPBEIter, be32(u.iter)),
		a.p("user", tagHashFunc, be32(u.hash)), a.p("user", tagPBAChecksum, sum),
		a.p("user", tagPBASalt, pbaSalt), a.p("user", tagPBAIter, be32(u.iter)))
}

func (a tArchive) control(t testing.TB) []byte {
	var users [][]byte
	for i, u := range a.users {
		users = append(users, a.userTLV(t, u, i))
	}
	plain := a.rawCtl
	if plain == nil {
		plain = cat(
			a.box("top", tagFileProps, "glob", a.p("glob", tagArchivePath, u16("(none)")), a.p("glob", tagEncMode, be32(a.mode)),
				a.p("glob", tagEncStrength, be32(uint32(len(a.key)))), a.p("glob", tagFilesIV, a.iv)),
			a.box("top", tagExtraProps, "extra", a.p("extra", tagCreationTime, ftBytes(a.created)), a.p("extra", tagCreatedWith, u16("{00000018-A040-3CA8-8868-36F59DEFD14D}"))),
			a.box("top", tagAccessList, "acl", users...),
			a.extra["top"],
		)
	}
	return obfuscate(a.version, bytes.Repeat([]byte{0x5A}, 16), plain)
}

// build returns the archive bytes and where the CFB builder put things.
func (a tArchive) build(t testing.TB) ([]byte, cfbtest.Layout) {
	t.Helper()
	d, err := newDecryptor(a.key, a.iv, a.mode)
	if err != nil {
		t.Fatal(err)
	}
	d.perFile = a.version == "0200" && !a.globalIV
	var catalog []byte
	var streams []*cfbtest.Node
	counter := 0
	var walk func(nodes []*tNode, parent [16]byte)
	walk = func(nodes []*tNode, parent [16]byte) {
		for _, n := range nodes {
			counter++
			id := testID(counter)
			d := d.withFile(id) // the per-file IV of version 0200 archives
			isDir := n.dir || len(n.kids) > 0
			props := cat(
				a.p("entry", tagFileID, id[:]), a.p("entry", tagParentID, parent[:]),
				a.p("entry", tagHalfAnon, u16("half"+n.name)), a.p("entry", tagNameCiphertext, d.encrypt(d.iv[:], nameBytes(n.name))),
				a.p("entry", tagFileSize, le64(uint64(len(n.data)))), a.p("entry", tagFileCreated, ftBytes(a.created)),
				a.p("entry", tagFileWritten, ftBytes(a.created.Add(time.Hour))), a.p("entry", tagFileAccessed, ftBytes(a.created)),
				a.extra["entry"],
			)
			if isDir {
				props = cat(props, a.p("entry", tagIsDir, []byte{1}))
			} else {
				var z bytes.Buffer
				w := zlib.NewWriter(&z)
				w.Write(n.data)
				w.Close()
				var enc []byte
				zdata := z.Bytes()
				if a.zhook != nil {
					zdata = a.zhook(n.name, zdata)
				}
				for i, zb := uint64(0), zdata; len(zb) > 0; i++ {
					k := min(len(zb), chunkSize)
					enc = append(enc, d.encrypt(d.chunkIV(i), zb[:k])...)
					zb = zb[k:]
				}
				if !a.dropStreams {
					streams = append(streams, cfbtest.Stream(streamName(id), enc))
				}
			}
			catalog = cat(catalog, a.p("catalog", tagFileProps, props))
			walk(n.kids, id)
		}
	}
	walk(a.root, [16]byte{})
	if a.rawCatalog != nil {
		catalog = a.rawCatalog
	}
	meta := cfbtest.Stream(metadataStream, oleps(a.control(t), catalog, a.opts))
	streams = append(append(streams, a.cfbExtra...), meta)
	out, lay := cfbtest.Build(3, cfbtest.Storage("Root Entry", streams...), false)
	return out, lay
}

// testID is the file_id the builder gives the n-th entry (from 1).
func testID(n int) (id [16]byte) {
	binary.LittleEndian.PutUint32(id[:], uint32(0x01020300+n))
	id[5] = 0x77
	return id
}

// bytes returns the archive.
func (a tArchive) bytes(t testing.TB) []byte {
	b, _ := a.build(t)
	return b
}
