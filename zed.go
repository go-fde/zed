// Package zed reads Prim'X ZED! encrypted archives (.zed) opened with a
// password.
//
// The format follows Sylvain Beucler's ".zed archive file format" (2017): an
// MS-CFB container whose metadata stream holds an obfuscated access list
// (_ctlfile) and the file list (_catalog), and one AES-CBC encrypted, zlib
// compressed stream per file. Users who hold only an RSA key are not
// supported: Open returns ErrUnsupported for them. Writing is out of scope.
//
// The archive is untrusted input. Iteration counts, entry counts, metadata
// size and decompressed file size are bounded by Limits and refused before the
// work is done.
package zed

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/go-fde/zed/internal/cfb"
)

const (
	metadataStream = "\x05" + "5haaaaqaIekzeecnWj31zxh0Nc"
	trailerText    = "ZoneCentral (R)\x00"
)

var (
	delimiter = []byte{0x07, 0x65, 0x92, 0x1A, 0x2A, 0x07, 0x74, 0x53, 0x47, 0x52, 0x07, 0x33, 0x61, 0x71, 0x93, 0x00}
	staticKey = []byte{0x37, 0xF1, 0x3C, 0xF8, 0x1C, 0x78, 0x0A, 0xF2, 0x6B, 0x6A, 0x52, 0x65, 0x4F, 0x79, 0x4A, 0xEF}
)

// Limits bounds the work an archive can ask for. A zero field takes the value
// of DefaultLimits.
type Limits struct {
	MaxIterations int   // PBA/PBE iteration count a user may declare
	MaxUsers      int   // password users examined
	MaxEntries    int   // files and directories in the catalog
	MaxMetadata   int64 // bytes of the metadata stream
	MaxFileSize   int64 // decompressed bytes of one file
}

// DefaultLimits returns the limits Open uses: 10 million iterations (ZEDFREE
// writes 100000 and 200000), 64 users, 100000 entries, 64 MiB of metadata and
// 4 GiB per file.
func DefaultLimits() Limits {
	return Limits{MaxIterations: 10_000_000, MaxUsers: 64, MaxEntries: 100_000, MaxMetadata: 64 << 20, MaxFileSize: 4 << 30}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxIterations <= 0 {
		l.MaxIterations = d.MaxIterations
	}
	if l.MaxUsers <= 0 {
		l.MaxUsers = d.MaxUsers
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = d.MaxEntries
	}
	if l.MaxMetadata <= 0 {
		l.MaxMetadata = d.MaxMetadata
	}
	if l.MaxFileSize <= 0 {
		l.MaxFileSize = d.MaxFileSize
	}
	return l
}

// Option configures Open.
type Option func(*Limits)

// WithLimits replaces the default limits; zero fields keep their default.
func WithLimits(l Limits) Option { return func(dst *Limits) { *dst = l } }

// Entry is a file or a directory of the archive.
type Entry struct {
	ID       [16]byte
	Name     string // the file name, decrypted
	Path     string // slash-separated, from the top of the archive
	Dir      bool
	Size     int64 // decompressed size
	Created  time.Time
	Modified time.Time
	Accessed time.Time

	parent [16]byte
}

// User describes one entry of the access list.
type User struct {
	Login    string
	Method   string // "password" or "rsa"
	Admin    bool
	HashFunc int // pkcs12_hashfunc: 21 SHA-1, 22 SHA-256; password users only
	Iter     int // pba_iter; password users only
}

// Info is what the obfuscated _ctlfile says about the archive. It needs no
// password.
type Info struct {
	Version        string // "0100" (ZED! Free) or "0200"
	PathName       string // archive_pathname
	CreatedWith    string // archive_createdwith, empty when absent
	Created        time.Time
	EncryptionMode int // 103 STREAM, 104 CTS
	KeyBytes       int // encryption_strength
	Users          []User
}

// Archive is an open, unlocked .zed archive.
type Archive struct {
	cf      *cfb.File
	dec     *decryptor
	lim     Limits
	info    Info
	entries []Entry
	closer  io.Closer
}

// Info returns the archive properties.
func (a *Archive) Info() Info { return a.info }

// Entries returns the files and directories in catalog order.
func (a *Archive) Entries() []Entry { return append([]Entry(nil), a.entries...) }

// Lookup returns the entry at a slash-separated path, or nil.
func (a *Archive) Lookup(path string) *Entry {
	path = strings.Trim(path, "/")
	for i := range a.entries {
		if a.entries[i].Path == path {
			return &a.entries[i]
		}
	}
	return nil
}

// Close releases the file opened by OpenFile; it is a no-op after Open.
func (a *Archive) Close() error {
	if a.closer == nil {
		return nil
	}
	return a.closer.Close()
}

// fileSize is replaceable so that tests can make Stat fail.
var fileSize = func(f *os.File) (int64, error) { return f.Seek(0, io.SeekEnd) }

// OpenFile opens the .zed archive at path.
func OpenFile(path, password string, opts ...Option) (*Archive, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	size, err := fileSize(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	a, err := Open(f, size, password, opts...)
	if err != nil {
		f.Close()
		return nil, err
	}
	a.closer = f
	return a, nil
}

// Open unlocks the archive held by r, which is size bytes long.
func Open(r io.ReaderAt, size int64, password string, opts ...Option) (*Archive, error) {
	var lim Limits
	for _, o := range opts {
		o(&lim)
	}
	lim = lim.withDefaults()
	cf, err := cfb.Open(r, size)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFormat, err)
	}
	e := cf.Lookup(metadataStream)
	if e == nil {
		return nil, fmt.Errorf("%w: no metadata stream: not a .zed archive", ErrFormat)
	}
	meta, err := cf.ReadAll(e, lim.MaxMetadata)
	if err != nil {
		if errors.Is(err, cfb.ErrLimit) {
			return nil, fmt.Errorf("%w: %w", ErrLimit, err)
		}
		return nil, fmt.Errorf("%w: %w", ErrFormat, err)
	}
	ctlBlob, catBlob, err := blobs(meta)
	if err != nil {
		return nil, err
	}
	g, err := parseControl(ctlBlob, lim)
	if err != nil {
		return nil, err
	}
	key, err := g.unlock(password, lim)
	if err != nil {
		return nil, err
	}
	dec, err := newDecryptor(key, g.iv, uint32(g.info.EncryptionMode))
	if err != nil {
		return nil, err
	}
	entries, err := parseCatalog(catBlob, dec, lim)
	if err != nil {
		return nil, err
	}
	return &Archive{cf: cf, dec: dec, lim: lim, info: g.info, entries: entries}, nil
}

// control is the decoded _ctlfile.
type control struct {
	info  Info
	iv    []byte
	users []user
}

type user struct {
	files, pbeSalt, pbaSalt, pbaSum []byte
	pbeIter, pbaIter, hash          uint32
	login                           string
}

// parseControl removes the static-key obfuscation of _ctlfile and decodes it.
func parseControl(blob []byte, lim Limits) (*control, error) {
	const head, tail = 16 + 2 + 16, 4 + 16 + 16
	if len(blob) < head+tail ||
		!bytes.Equal(blob[:16], delimiter) ||
		!bytes.Equal(blob[len(blob)-32:len(blob)-16], delimiter) ||
		string(blob[len(blob)-16:]) != trailerText {
		return nil, fmt.Errorf("%w: _ctlfile delimiters", ErrFormat)
	}
	ver := hex.EncodeToString(blob[16:18])
	if ver != "0100" && ver != "0200" {
		return nil, fmt.Errorf("%w: _ctlfile version %s", ErrUnsupported, ver)
	}
	b, _ := aes.NewCipher(staticKey)
	plain := decryptStream(b, blob[18:34], blob[34:len(blob)-36])
	top, err := parseTLV(plain)
	if err != nil {
		return nil, err
	}
	g := &control{info: Info{Version: ver}}
	props, ok := top.first(tagFileProps)
	if !ok {
		return nil, fmt.Errorf("%w: _ctlfile has no archive properties", ErrFormat)
	}
	if err := g.globals(props); err != nil {
		return nil, err
	}
	if extra, ok := top.first(tagExtraProps); ok {
		if err := g.extra(extra); err != nil {
			return nil, err
		}
	}
	if acl, ok := top.first(tagAccessList); ok {
		if err := g.access(acl, lim); err != nil {
			return nil, err
		}
	}
	return g, nil
}

func (g *control) globals(b []byte) error {
	t, err := parseTLV(b)
	if err != nil {
		return err
	}
	if v, ok := t.first(tagArchivePath); ok {
		if g.info.PathName, err = utf16le(v); err != nil {
			return err
		}
	}
	mode, ok, err := t.u32(tagEncMode)
	if err != nil || !ok {
		return fmt.Errorf("%w: encryption_mode missing or invalid", ErrFormat)
	}
	strength, ok, err := t.u32(tagEncStrength)
	if err != nil || !ok {
		return fmt.Errorf("%w: encryption_strength missing or invalid", ErrFormat)
	}
	g.info.EncryptionMode, g.info.KeyBytes = int(mode), int(strength)
	if g.iv, ok = t.first(tagFilesIV); !ok {
		return fmt.Errorf("%w: files_iv missing", ErrFormat)
	}
	return nil
}

func (g *control) extra(b []byte) error {
	t, err := parseTLV(b)
	if err != nil {
		return err
	}
	if v, ok := t.first(tagCreationTime); ok {
		if g.info.Created, err = filetime(v); err != nil {
			return err
		}
	}
	if v, ok := t.first(tagCreatedWith); ok {
		if g.info.CreatedWith, err = utf16le(v); err != nil {
			return err
		}
	}
	return nil
}

func (g *control) access(b []byte, lim Limits) error {
	t, err := parseTLV(b)
	if err != nil {
		return err
	}
	for _, it := range t {
		if it.tag != tagPasswordUser && it.tag != tagRSAUser {
			continue
		}
		if len(g.info.Users) >= lim.MaxUsers {
			return fmt.Errorf("%w: more than %d users", ErrLimit, lim.MaxUsers)
		}
		ut, err := parseTLV(it.val)
		if err != nil {
			return err
		}
		u := User{Method: "rsa"}
		if it.tag == tagPasswordUser {
			u.Method = "password"
		}
		var raw user
		if v, ok := ut.first(tagLogin); ok {
			if raw.login, err = utf16le(v); err != nil {
				return err
			}
			u.Login = raw.login
		}
		_, u.Admin = ut.first(0x807e0100)
		raw.files, _ = ut.first(tagFilesKeyCT)
		if it.tag == tagPasswordUser {
			var ok1, ok2, ok3 bool
			raw.hash, ok1, err = ut.u32(tagHashFunc)
			if err != nil {
				return err
			}
			raw.pbeIter, ok2, err = ut.u32(tagPBEIter)
			if err != nil {
				return err
			}
			raw.pbaIter, ok3, err = ut.u32(tagPBAIter)
			if err != nil {
				return err
			}
			raw.pbeSalt, _ = ut.first(tagPBESalt)
			raw.pbaSalt, _ = ut.first(tagPBASalt)
			raw.pbaSum, _ = ut.first(tagPBAChecksum)
			if !ok1 || !ok2 || !ok3 || raw.files == nil || raw.pbaSum == nil {
				return fmt.Errorf("%w: password user %q lacks a field", ErrFormat, raw.login)
			}
			u.HashFunc, u.Iter = int(raw.hash), int(raw.pbaIter)
			g.users = append(g.users, raw)
		}
		g.info.Users = append(g.info.Users, u)
	}
	return nil
}

// unlock finds the password user the password opens and returns the file key.
func (g *control) unlock(password string, lim Limits) ([]byte, error) {
	if len(g.users) == 0 {
		return nil, fmt.Errorf("%w: no password user (RSA key users only)", ErrUnsupported)
	}
	// Refuse before deriving anything.
	for _, u := range g.users {
		if uint64(u.pbaIter) > uint64(lim.MaxIterations) || uint64(u.pbeIter) > uint64(lim.MaxIterations) {
			return nil, fmt.Errorf("%w: user %q declares %d/%d iterations, limit %d", ErrLimit, u.login, u.pbaIter, u.pbeIter, lim.MaxIterations)
		}
		if u.pbaIter == 0 || u.pbeIter == 0 {
			return nil, fmt.Errorf("%w: user %q declares zero iterations", ErrFormat, u.login)
		}
		if _, err := hashFor(u.hash); err != nil {
			return nil, err
		}
	}
	if g.info.KeyBytes != 16 && g.info.KeyBytes != 24 && g.info.KeyBytes != 32 {
		return nil, fmt.Errorf("%w: encryption_strength %d", ErrUnsupported, g.info.KeyBytes)
	}
	pw := bmpPassword(password)
	for _, u := range g.users {
		h, _ := hashFor(u.hash)
		sum := pkcs12KDF(h, pw, u.pbaSalt, idMAC, int(u.pbaIter), len(u.pbaSum))
		if subtle.ConstantTimeCompare(sum, u.pbaSum) != 1 {
			continue
		}
		kek := pkcs12KDF(h, pw, u.pbeSalt, idKey, int(u.pbeIter), 32)[:g.info.KeyBytes]
		iv := pkcs12KDF(h, pw, u.pbeSalt, idIV, int(u.pbeIter), aes.BlockSize)
		return unwrapKey(kek, iv, u.files)
	}
	return nil, ErrPassword
}

// unwrapKey decrypts files_key_ciphertext: AES-CBC with PKCS#7 padding.
func unwrapKey(kek, iv, ct []byte) ([]byte, error) {
	b, _ := aes.NewCipher(kek) // kek is 16, 24 or 32 bytes: checked by unlock
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("%w: files_key_ciphertext of %d bytes", ErrFormat, len(ct))
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(b, iv).CryptBlocks(pt, ct)
	pad := int(pt[len(pt)-1])
	if pad < 1 || pad > aes.BlockSize || pad > len(pt) {
		return nil, fmt.Errorf("%w: files_key_ciphertext padding", ErrFormat)
	}
	for _, c := range pt[len(pt)-pad:] {
		if int(c) != pad {
			return nil, fmt.Errorf("%w: files_key_ciphertext padding", ErrFormat)
		}
	}
	return pt[:len(pt)-pad], nil
}

// parseCatalog decodes _catalog and rebuilds the hierarchy.
func parseCatalog(blob []byte, d *decryptor, lim Limits) ([]Entry, error) {
	top, err := parseTLV(blob)
	if err != nil {
		return nil, err
	}
	var entries []Entry
	byID := map[[16]byte]int{}
	for _, it := range top {
		if it.tag != tagFileProps {
			continue
		}
		if len(entries) >= lim.MaxEntries {
			return nil, fmt.Errorf("%w: more than %d catalog entries", ErrLimit, lim.MaxEntries)
		}
		e, err := parseEntry(it.val, d)
		if err != nil {
			return nil, err
		}
		if _, dup := byID[e.ID]; dup {
			return nil, fmt.Errorf("%w: duplicate file_id %x", ErrFormat, e.ID)
		}
		byID[e.ID] = len(entries)
		entries = append(entries, e)
	}
	paths := make([]string, len(entries))
	var zero [16]byte
	for i := range entries {
		// Walk to the top; a chain longer than the catalog is a cycle.
		path, cur := entries[i].Name, entries[i].parent
		for steps := 0; cur != zero; steps++ {
			j, ok := byID[cur]
			if !ok || steps > len(entries) || !entries[j].Dir {
				return nil, fmt.Errorf("%w: entry %q has a missing, non-directory or cyclic parent", ErrFormat, entries[i].Name)
			}
			path, cur = entries[j].Name+"/"+path, entries[j].parent
		}
		paths[i] = path
	}
	for i := range entries {
		entries[i].Path = paths[i]
	}
	return entries, nil
}

func parseEntry(b []byte, d *decryptor) (Entry, error) {
	var e Entry
	t, err := parseTLV(b)
	if err != nil {
		return e, err
	}
	id, ok := t.first(tagFileID)
	if !ok || len(id) != 16 {
		return e, fmt.Errorf("%w: file_id missing or not 16 bytes", ErrFormat)
	}
	copy(e.ID[:], id)
	if p, ok := t.first(tagParentID); ok {
		if len(p) != 16 {
			return e, fmt.Errorf("%w: parent_directory_id of %d bytes", ErrFormat, len(p))
		}
		copy(e.parent[:], p)
	}
	if ct, ok := t.first(tagNameCiphertext); ok {
		e.Name, err = utf16le(d.decrypt(d.iv[:], ct))
	} else if v, ok := t.first(tagHalfAnon); ok {
		e.Name, err = utf16le(v)
	}
	if err != nil {
		return e, err
	}
	if e.Name == "" || e.Name == "." || e.Name == ".." || strings.ContainsAny(e.Name, "/\\\x00") {
		return e, fmt.Errorf("%w: unusable file name %q", ErrFormat, e.Name)
	}
	if v, ok := t.first(tagFileSize); ok {
		if len(v) != 8 {
			return e, fmt.Errorf("%w: file_size of %d bytes", ErrFormat, len(v))
		}
		n := leUint64(v)
		if n > 1<<62 {
			return e, fmt.Errorf("%w: file_size %d", ErrFormat, n)
		}
		e.Size = int64(n)
	}
	for _, f := range []struct {
		tag uint32
		dst *time.Time
	}{{tagFileCreated, &e.Created}, {tagFileWritten, &e.Modified}, {tagFileAccessed, &e.Accessed}} {
		if v, ok := t.first(f.tag); ok {
			if *f.dst, err = filetime(v); err != nil {
				return e, err
			}
		}
	}
	if v, ok := t.first(tagIsDir); ok {
		n, err := beUint(v)
		if err != nil {
			return e, err
		}
		e.Dir = n == 1
	}
	return e, nil
}

func leUint64(b []byte) uint64 {
	var v uint64
	for i := 7; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

// streamName is the CFB stream holding a file: the bytes of file_id shuffled
// 3 2 1 0 5 4 7 6 8..15 and hex encoded, without the usual trailing NUL byte.
func streamName(id [16]byte) string {
	order := [16]int{3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15}
	var s [16]byte
	for i, j := range order {
		s[i] = id[j]
	}
	n := 16
	if s[15] == 0 {
		n = 15
	}
	return strings.ToUpper(hex.EncodeToString(s[:n]))
}
