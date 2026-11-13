package zed

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-filesystems/cfb"
)

// ErrArgument reports something Create, Mkdir or a file writer refuses: a name
// or path an archive cannot hold (the rules the reader applies), a name used
// twice, a missing parent, an empty password.
var ErrArgument = errors.New("zed: invalid argument")

// SealMode says what Close writes of the seal: the _seals property of the
// metadata and the ~zedCFSTG_PGI_SEAL_STREAM stream. ZED! Free 2026.3 writes
// both. The seal holds six SHA-256 sized values; three of them are the SHA-256
// of _ctlfile, of _catalog and of the watermark picture, the other three (and
// the hash in the seal stream) are not known and are written random. It is not
// known whether ZED! checks them: these modes exist to find out.
type SealMode int

const (
	// SealPlaceholders writes the seal as ZED! Free 2026.3 lays it out, with
	// the three known hashes and random values for the unknown ones.
	SealPlaceholders SealMode = iota
	// SealNone writes no seal at all.
	SealNone
	// SealPropertyOnly writes the _seals property but no seal stream.
	SealPropertyOnly
)

const (
	// The iteration counts ZED! Free 2026.3 writes.
	writePBAIter = 200_000
	writePBEIter = 100_000
	// The values the archive properties carry in a 2026.3 container.
	createdWithDefault = "{00000006-B030-3CA8-8868-36F59DEFD14D}"
	sealStreamName     = "~zedCFSTG_PGI_SEAL_STREAM"
	watermarkStorage   = "\x05RydaaaqaIekzeecnWj31zxh0Nc"
)

var (
	rootCLSID      = [16]byte{0xE0, 0x0F, 0, 0, 0x04, 0x88, 0xA8, 0x4C, 0x88, 0x68, 0x36, 0xF5, 0x9D, 0xEF, 0xD1, 0x4D}
	watermarkCLSID = [16]byte{0x12, 0x0F, 0, 0, 0x04, 0x88, 0xA8, 0x4C, 0x88, 0x68, 0x36, 0xF5, 0x9D, 0xEF, 0xD1, 0x4D}
	metaCLSID      = [16]byte{0xFA, 0, 0, 0, 0x04, 0x88, 0xA8, 0x4C, 0x88, 0x68, 0x36, 0xF5, 0x9D, 0xEF, 0xD1, 0x4D}
	metaFMTID      = [16]byte{0xFF, 0, 0, 0, 0x04, 0x88, 0xA8, 0x4C, 0x88, 0x68, 0x36, 0xF5, 0x9D, 0xEF, 0xD1, 0x4D}
)

// watermarkContents is the property set that describes the watermark picture
// ("_watermark", stored as the stream prop0005, a PNG), identical in the
// ZED! Free 2024.4 and 2026.3 containers.
var watermarkContents = hexBytes("feff000005000200120f00000488a84c886836f59defd14d01000000110f00000488a84c886836f59defd14d30000000c4000000" +
	"05000000010000003800000000000080400000000000000048000000030000009400000004000000b00000000000000000000000020000" +
	"00b0040000130000000904000002000000030000000b0000005f00770061007400650072006d00610072006b0000000000040000000f00" +
	"00005f00770061007400650072006d00610072006b002e00650078007400000000004200000012000000700072006f007000300030003000" +
	"350000000000080000000a00000070006e006700000000000000")

// hexBytes decodes a constant; TestWrittenStructure... checks its length.
func hexBytes(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

// watermarkPNG is the picture ZED! shows behind the file list: a plain white
// 128x128 image. (The one in a real container is Prim'X's, and is not ours to
// copy.)
func watermarkPNG() []byte {
	img := image.NewRGBA(image.Rect(0, 0, 128, 128))
	for i := range img.Pix {
		img.Pix[i] = 0xFF
	}
	var b bytes.Buffer
	_ = png.Encode(&b, img) // into memory: it cannot fail
	return b.Bytes()
}

// CreateOption configures Create.
type CreateOption func(*creator)

type creator struct {
	login       string
	lim         Limits
	rand        io.Reader
	now         func() time.Time
	createdWith string
	seal        SealMode
	watermark   bool
	maxArchive  int64
	strength    int
}

// WithStrength selects the AES key size in bytes: 16 (AES-128, what ZED! Free
// 2026.3 writes, the default) or 32 (AES-256, which ZED! Enterprise offers).
// For 32 the archive key is 32 bytes and the key that wraps it is the first 32
// bytes of the PBKDF2 derivation, the IV the 16 after them (the layout the
// reader infers; not yet seen in a real container).
func WithStrength(n int) CreateOption { return func(c *creator) { c.strength = n } }

// WithLogin names the password user (default "user").
func WithLogin(login string) CreateOption { return func(c *creator) { c.login = login } }

// WithWriteLimits replaces the limits the writer enforces, which are the
// reader's by default: it never writes an archive its own Open would refuse.
// Zero fields keep their default.
func WithWriteLimits(l Limits) CreateOption { return func(c *creator) { c.lim = l.withDefaults() } }

// WithRandom replaces crypto/rand as the source of salts, IVs, keys and file
// identifiers. For tests: a predictable source makes the archive predictable.
func WithRandom(r io.Reader) CreateOption { return func(c *creator) { c.rand = r } }

// WithClock replaces time.Now as the source of the archive's times.
func WithClock(now func() time.Time) CreateOption { return func(c *creator) { c.now = now } }

// WithCreatedWith sets archive_createdwith, the GUID-like text naming the
// application that made the archive. The default is the one ZED! Free 2026.3
// writes.
func WithCreatedWith(s string) CreateOption { return func(c *creator) { c.createdWith = s } }

// WithSeal selects how the seal is written (see SealMode).
func WithSeal(m SealMode) CreateOption { return func(c *creator) { c.seal = m } }

// WithoutWatermark leaves out the watermark storage (the picture and its
// description).
func WithoutWatermark() CreateOption { return func(c *creator) { c.watermark = false } }

// WithMaxArchiveSize bounds the bytes of file data the writer holds (the
// archive is built in memory). The default is 1 GiB.
func WithMaxArchiveSize(n int64) CreateOption { return func(c *creator) { c.maxArchive = n } }

type wentry struct {
	id, parent [16]byte
	name, path string
	dir        bool
	size       int64
	created    time.Time
	modified   time.Time
	accessed   time.Time
	stream     []byte
	ordinal    int
	done       bool
}

// Writer builds a new .zed archive with one password user: ZED! Free 2026.3's
// layout (version 0200, PBKDF2-HMAC-SHA-512, CTS, 512-byte chunks, zlib). The
// archive is held in memory and written by Close. A Writer is not safe for
// concurrent use.
//
// What it writes is read by this package's Open, and was designed to open in
// ZED! Free 2026.3 (see the README for what has been tried). It is not an
// ANSSI-qualified product.
type Writer struct {
	dst        io.Writer
	c          creator
	dec        *decryptor
	fileKey    []byte
	filesIV    []byte
	entries    []*wentry
	byPath     map[string]*wentry
	open       int
	closed     bool
	totalPath  int
	stored     int64
	nFiles     int
	nDirs      int
	pbeSalt    []byte
	pbaSalt    []byte
	pbaSum     []byte
	filesKeyCT []byte
	sealKeyCT  []byte
	rnd        func(n int) []byte
	err        error // the first failure of the random source
}

// Create starts a new archive for the password. It derives the user's keys
// (about a tenth of a second of PBKDF2) and draws the archive key from
// crypto/rand.
func Create(dst io.Writer, password string, opts ...CreateOption) (*Writer, error) {
	c := creator{login: "user", lim: DefaultLimits(), rand: rand.Reader, now: time.Now, createdWith: createdWithDefault,
		watermark: true, maxArchive: 1 << 30, strength: 16}
	for _, o := range opts {
		o(&c)
	}
	if password == "" {
		return nil, fmt.Errorf("%w: empty password", ErrArgument)
	}
	if c.strength != 16 && c.strength != 32 {
		return nil, fmt.Errorf("%w: key strength %d (16 or 32)", ErrArgument, c.strength)
	}
	if c.login == "" || strings.ContainsRune(c.login, 0) || !utf8.ValidString(c.login) {
		return nil, fmt.Errorf("%w: login %q", ErrArgument, c.login)
	}
	w := &Writer{dst: dst, c: c, byPath: map[string]*wentry{}}
	w.rnd = func(n int) []byte {
		b := make([]byte, n)
		if _, err := io.ReadFull(c.rand, b); err != nil && w.err == nil {
			w.err = fmt.Errorf("zed: random source: %w", err)
		}
		return b
	}
	w.fileKey, w.filesIV = w.rnd(c.strength), w.rnd(16)
	w.pbeSalt, w.pbaSalt = w.rnd(8), w.rnd(8)
	h, _ := hashFor(hashPBKDF2SHA512)
	var err error
	if w.pbaSum, err = h.check(password, w.pbaSalt, writePBAIter, 8); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	kek, iv, err := h.keyIV(password, w.pbeSalt, writePBEIter, c.strength)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	blk, _ := aes.NewCipher(kek)
	w.filesKeyCT = pkcs7CBC(blk, iv, w.fileKey)
	w.dec, _ = newDecryptor(w.fileKey, w.filesIV, modeCTS) // a 16- or 32-byte key and a 16-byte IV: it cannot fail
	w.dec.perFile = true
	if w.err != nil {
		return nil, w.err
	}
	return w, nil
}

// pkcs7CBC encrypts data under AES-CBC with PKCS#7 padding.
func pkcs7CBC(b cipher.Block, iv, data []byte) []byte {
	pad := aesBlock - len(data)%aesBlock
	p := append(append([]byte(nil), data...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	cipher.NewCBCEncrypter(b, iv).CryptBlocks(p, p)
	return p
}

func (w *Writer) newEntry(p string, dir bool) (*wentry, error) {
	if w.closed {
		return nil, fmt.Errorf("%w: the archive is closed", ErrArgument)
	}
	p = strings.Trim(p, "/")
	if p == "" {
		return nil, fmt.Errorf("%w: empty path", ErrArgument)
	}
	parts := strings.Split(p, "/")
	for _, part := range parts {
		if !usableName(part) || !utf8.ValidString(part) { // names are UTF-16 in the archive
			return nil, fmt.Errorf("%w: %q is not a name an archive can hold", ErrArgument, part)
		}
	}
	if _, dup := w.byPath[p]; dup {
		return nil, fmt.Errorf("%w: %q exists already", ErrArgument, p)
	}
	var parent [16]byte
	if len(parts) > 1 {
		par, ok := w.byPath[path.Dir(p)]
		if !ok || !par.dir {
			return nil, fmt.Errorf("%w: %q has no parent directory", ErrArgument, p)
		}
		parent = par.id
	}
	lim := w.c.lim
	if len(w.entries)+w.open+1 > lim.MaxEntries || len(parts) > lim.MaxDepth || len(p) > lim.MaxPathBytes || w.totalPath+len(p) > lim.MaxTotalPathBytes {
		return nil, fmt.Errorf("%w: %q would exceed the limits (%d entries, depth %d, paths of %d bytes, %d in all)",
			ErrLimit, p, lim.MaxEntries, lim.MaxDepth, lim.MaxPathBytes, lim.MaxTotalPathBytes)
	}
	e := &wentry{parent: parent, name: parts[len(parts)-1], path: p, dir: dir}
	copy(e.id[:15], w.rnd(15)) // the 16th byte is 0, as in ZED's file identifiers
	if w.err != nil {
		return nil, w.err
	}
	for _, o := range w.byPath {
		if o.id == e.id {
			return nil, fmt.Errorf("zed: the random source repeated a file identifier")
		}
	}
	now := w.c.now()
	e.modified = now
	if !dir {
		e.created, e.accessed = now, now
	}
	if dir {
		w.nDirs++
		e.ordinal = w.nDirs
	} else {
		w.nFiles++
		e.ordinal = w.nFiles
	}
	w.byPath[p] = e
	w.totalPath += len(p)
	return e, nil
}

// Mkdir adds a directory; its parent must exist.
func (w *Writer) Mkdir(p string) error {
	e, err := w.newEntry(p, true)
	if err != nil {
		return err
	}
	e.done = true
	w.entries = append(w.entries, e)
	return nil
}

// AddFile adds a file with the content r yields.
func (w *Writer) AddFile(p string, r io.Reader) error {
	f, err := w.Create(p)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.(*fileWriter).abort()
		return err
	}
	return f.Close()
}

// Create starts a file; the content is what is written to the result, and the
// file exists in the archive once it is closed. Its directory must exist.
func (w *Writer) Create(p string) (io.WriteCloser, error) {
	e, err := w.newEntry(p, false)
	if err != nil {
		return nil, err
	}
	w.open++
	f := &fileWriter{w: w, e: e, dec: w.dec.withFile(e.id)}
	f.zw = zlib.NewWriter(sinkFunc(f.put)) // the compressed bytes go to put, chunk by chunk
	return f, nil
}

// fileWriter compresses with zlib and encrypts chunk by chunk as the data
// arrives, so only the encrypted file is held in memory.
type fileWriter struct {
	w      *Writer
	e      *wentry
	dec    *decryptor
	zw     *zlib.Writer
	chunk  []byte
	index  uint64
	plain  int64
	closed bool
	failed error
}

// Write implements io.Writer for the uncompressed data.
func (f *fileWriter) Write(p []byte) (int, error) {
	if f.closed {
		return 0, fmt.Errorf("%w: the file is closed", ErrArgument)
	}
	if f.failed != nil {
		return 0, f.failed
	}
	if f.plain+int64(len(p)) > f.w.c.lim.MaxFileSize {
		f.failed = fmt.Errorf("%w: %q is larger than %d bytes", ErrLimit, f.e.path, f.w.c.lim.MaxFileSize)
		return 0, f.failed
	}
	f.plain += int64(len(p))
	return f.zw.Write(p) // the compressed bytes come back through put
}

// put receives the compressed bytes from zlib: the writer's output side.
func (f *fileWriter) put(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		k := min(chunkSize-len(f.chunk), len(p))
		f.chunk = append(f.chunk, p[:k]...)
		p = p[k:]
		if len(f.chunk) == chunkSize {
			if err := f.flushChunk(); err != nil {
				return 0, err
			}
		}
	}
	return n, nil
}

func (f *fileWriter) flushChunk() error {
	if f.w.stored+int64(len(f.chunk)) > f.w.c.maxArchive {
		f.failed = fmt.Errorf("%w: the archive would hold more than %d bytes", ErrLimit, f.w.c.maxArchive)
		return f.failed
	}
	f.e.stream = append(f.e.stream, f.dec.decryptChunkEncrypt(f.index, f.chunk)...)
	f.w.stored += int64(len(f.chunk))
	f.index++
	f.chunk = f.chunk[:0]
	return nil
}

func (f *fileWriter) abort() {
	f.closed = true
	f.w.open--
	f.w.stored -= int64(len(f.e.stream))
	delete(f.w.byPath, f.e.path)
	f.w.totalPath -= len(f.e.path)
	f.w.nFiles--
}

// Close finishes the file: it joins the archive's catalog.
func (f *fileWriter) Close() error {
	if f.closed {
		return nil
	}
	if f.failed != nil {
		f.abort()
		return f.failed
	}
	if err := f.zw.Close(); err != nil {
		f.abort()
		return err
	}
	if len(f.chunk) > 0 {
		if err := f.flushChunk(); err != nil {
			f.abort()
			return err
		}
	}
	f.closed = true
	f.w.open--
	f.e.size = f.plain
	f.e.done = true
	f.w.entries = append(f.w.entries, f.e)
	return nil
}

// chunkEncrypt encrypts the index-th 512-byte chunk of a file stream.
func (d *decryptor) decryptChunkEncrypt(index uint64, pt []byte) []byte {
	return d.encrypt(d.chunkIV(index), pt)
}

// sinkFunc adapts put to the io.Writer zlib wants.
type sinkFunc func([]byte) (int, error)

func (s sinkFunc) Write(p []byte) (int, error) { return s(p) }

// Close writes the archive. It fails if a file is still open.
func (w *Writer) Close() error {
	if w.closed {
		return fmt.Errorf("%w: the archive is closed already", ErrArgument)
	}
	if w.open > 0 {
		return fmt.Errorf("%w: %d files are still open", ErrArgument, w.open)
	}
	w.closed = true
	catalog, err := w.catalog()
	if err != nil {
		return err
	}
	ctl := w.control()
	now := w.c.now()
	meta := w.metadata(ctl, catalog)
	seal := w.sealStream(now)
	if w.err != nil { // the random source failed while the metadata was drawn
		return w.err
	}
	if int64(len(meta)) > int64(w.c.lim.MaxMetadata) {
		return fmt.Errorf("%w: the metadata is %d bytes, limit %d", ErrLimit, len(meta), w.c.lim.MaxMetadata)
	}
	// The container writer cannot refuse what follows: the names are constants or
	// 30 hex digits of identifiers newEntry has checked are distinct, the parents
	// exist, and the limits leave room for everything the writer accepted.
	cw := cfb.NewWriter(cfb.WithVersion(4), cfb.WithLimits(len(w.entries)+16, w.c.maxArchive+int64(len(meta))+(1<<20)))
	at := cfb.Attrs{Created: now, Modified: now}
	cw.SetRoot(cfb.Attrs{CLSID: rootCLSID})
	add := func(name string, data []byte) { _ = cw.AddStream(name, data, at) }
	if w.c.seal != SealNone && w.c.seal != SealPropertyOnly {
		add(sealStreamName, seal)
	}
	add(metadataStream, meta)
	if w.c.watermark {
		_ = cw.AddStorage(watermarkStorage, cfb.Attrs{CLSID: watermarkCLSID, Created: now, Modified: now})
		add(watermarkStorage+"/CONTENTS", watermarkContents)
		add(watermarkStorage+"/prop0005", w.png())
	}
	for _, e := range w.entries {
		if !e.dir {
			add(streamName(e.id), e.stream)
		}
	}
	_, err = cw.WriteTo(w.dst)
	return err
}

func (w *Writer) png() []byte { return watermarkPNG() }

// catalog encodes _catalog: the header items, then one fileprops per entry.
func (w *Writer) catalog() ([]byte, error) {
	out := cat(put(0x80100200, be32(2)), put(0x00120100, []byte{1}), put(0x00130100, []byte{0}), put(0x00140200, be32(3)), put(0x00150100, []byte{1}))
	for _, e := range w.entries {
		half := fmt.Sprintf("File%d%s", e.ordinal, path.Ext(e.name))
		if e.dir {
			half = fmt.Sprintf("Folder%d", e.ordinal)
		}
		fd := w.dec.withFile(e.id)
		props := [][]byte{put(tagFileID, e.id[:]), put(tagParentID, e.parent[:]), put(tagHalfAnon, nameBytes(half))}
		if e.dir {
			props = append(props, put(tagIsDir, []byte{1}))
		}
		props = append(props, put(tagFileSize, le64(uint64(e.size))), put(tagFileCreated, ftBytes(e.created)),
			put(tagFileWritten, ftBytes(e.modified)), put(tagFileAccessed, ftBytes(e.accessed)),
			put(tagNameCiphertext, fd.encrypt(fd.iv[:], nameBytes(e.name))))
		if !e.dir {
			// Three items every file has in a ZED! Free 2026.3 catalog: a byte and
			// two 32-byte values whose meaning is not known; they are written as the
			// SHA-256 of the file's encrypted stream and random.
			sum := sha256.Sum256(e.stream)
			props = append(props, put(0x00390500, []byte{0}), put(0x00400500, sum[:]), put(0x00410500, w.rnd(32)))
		}
		out = append(out, put(tagFileProps, props...)...)
	}
	return out, w.err
}

// control encodes the _ctlfile plaintext and wraps it.
func (w *Writer) control() []byte {
	c := w.c
	now := c.now()
	sealKey := w.rnd(16)
	blk, _ := aes.NewCipher(w.fileKey)
	sealIV := w.rnd(16)
	md := md5.Sum(nameBytes(c.login))
	user := put(tagPasswordUser,
		put(tagLogin, nameBytes(c.login)), put(0x80720300, md[:]), put(0x807e0100, []byte{1}), put(0x00830200, be32(2)),
		put(tagFilesKeyCT, w.filesKeyCT), put(0x80750200, be32(hashPBKDF2SHA512)), put(tagPBESalt, w.pbeSalt), put(tagPBEIter, be32(writePBEIter)),
		put(tagHashFunc, be32(hashPBKDF2SHA512)), put(tagPBAChecksum, w.pbaSum), put(tagPBASalt, w.pbaSalt), put(tagPBAIter, be32(writePBAIter)),
		put(0x807c0200, be32(0x66)), put(0x00840500, ftBytes(now)))
	plain := cat(
		put(0x80100200, be32(2)),
		put(tagFileProps, put(0x00220300, w.rnd(16)), put(tagArchivePath, nameBytes("(none)")), put(0x80250300, w.rnd(16)),
			put(tagEncMode, be32(modeCTS)), put(tagEncStrength, be32(uint32(c.strength))), put(tagFilesIV, w.filesIV), put(0x80290200, be32(6))),
		put(tagAccessList, user),
		put(tagExtraProps, put(tagCreatedWith, nameBytes(c.createdWith)), put(tagCreationTime, ftBytes(now)),
			put(0x00c80200, []byte{0xED, 0xD1, 0x5F, 0x5F}), put(0x00c90200, []byte{0x00, 0x00, 0xB5, 0xCB})),
		put(0x801c0600, put(0x00e00500, pkcs7CBC(blk, sealIV, sealKey)), put(0x00e10200, be32(0x66)), put(0x00e20500, sealIV),
			put(0x00e30300, w.rnd(16)), put(0x00e40200, be32(16))),
		put(0x001d0600, put(0x00f00200, be32(3)), put(0x00f10200, be32(3)), put(0x00f20200, be32(0x34))),
	)
	return obfuscate("0200", w.rnd(16), plain)
}

// sealStream is ~zedCFSTG_PGI_SEAL_STREAM: a short TLV record, zero padded to
// 8192 bytes.
func (w *Writer) sealStream(now time.Time) []byte {
	payload := cat(put(0x80100200, be32(1)), put(0x80110500, ftBytes(now)),
		put(0x80120600, put(0x80210200, be32(1)), put(0x80220200, be32(0x1000)), put(0x80230200, be32(2))),
		put(0x80130600, put(0x80100200, be32(1)), put(0x80120600, put(0x80300500, w.rnd(32)))))
	out := binary.LittleEndian.AppendUint32(nil, 1)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(payload)))
	out = append(out, payload...)
	return append(out, make([]byte, 8192-len(out))...)
}

// metadata encodes the OLEPS stream: code page, locale, the dictionary naming
// the three blobs, and the blobs _ctlfile (4), _catalog (5) and _seals (6).
func (w *Writer) metadata(ctl, catalog []byte) []byte {
	le := binary.LittleEndian
	var seal []byte
	withSeal := w.c.seal != SealNone
	if withSeal {
		h := func(b []byte) []byte { s := sha256.Sum256(b); return s[:] }
		seal = cat(put(0x80100200, be32(1)), put(0x80110200, be32(3)),
			put(0x80120500, h(ctl)), put(0x80130500, w.rnd(32)), put(0x80140500, h(catalog)), put(0x80150500, w.rnd(32)),
			put(0x00160500, h(w.png())), put(0x00170500, w.rnd(32)))
	}
	pad4 := func(b []byte) []byte {
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}
	blob := func(b []byte) []byte {
		return pad4(cat(le.AppendUint16(nil, vtBlob), []byte{0, 0}, le.AppendUint32(nil, uint32(len(b))), b))
	}
	names := []struct {
		id   uint32
		name string
	}{{4, nameCtlfile}, {5, nameCatalog}}
	if withSeal {
		names = append(names, struct {
			id   uint32
			name string
		}{6, "_seals"})
	}
	dict := le.AppendUint32(nil, uint32(len(names)))
	for _, n := range names {
		dict = append(dict, cat(le.AppendUint32(nil, n.id), le.AppendUint32(nil, uint32(len(n.name)+1)), pad4(u16(n.name)))...)
	}
	type prop struct {
		id  uint32
		val []byte
	}
	props := []prop{
		{propCodePage, cat(le.AppendUint16(nil, vtI2), []byte{0, 0}, le.AppendUint16(nil, cpUTF16), []byte{0, 0})},
		{0x80000000, cat(le.AppendUint16(nil, 0x13), []byte{0, 0}, le.AppendUint32(nil, 0x409))},
		{propDictionary, dict},
		{4, blob(ctl)}, {5, blob(catalog)},
	}
	if withSeal {
		props = append(props, prop{6, blob(seal)})
	}
	head := 8 + 8*len(props)
	var table, body []byte
	for _, p := range props {
		table = cat(table, le.AppendUint32(nil, p.id), le.AppendUint32(nil, uint32(head+len(body))))
		body = append(body, p.val...)
	}
	set := cat(le.AppendUint32(nil, uint32(head+len(body))), le.AppendUint32(nil, uint32(len(props))), table, body)
	hdr := cat(le.AppendUint16(nil, 0xFFFE), []byte{0, 0, 5, 0, 2, 0}, metaCLSID[:], le.AppendUint32(nil, 1), metaFMTID[:], le.AppendUint32(nil, 48))
	return cat(hdr, set)
}
