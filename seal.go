package zed

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// The integrity values ZED! Free 2026.3 stores. They were recovered for
// interoperability (Directive 2009/24/EC, art. 6) by analysing how the
// application computes and checks them, then confirmed on a real container:
// the descriptions below are the format, written from our own notes; nothing of
// the application's code or tables is reproduced.

const (
	// fileBlock is the unit of the per-file values: 512 bytes.
	fileBlock = 512
	// sealMask is what the global value sees in place of the seal stream's own
	// record.
	sealMask = 0xA5
)

// sealBlockSize is the block size of the global value, as the seal stream states
// it (tag 0x80220200). A variable only so that a test can make the block
// boundaries close enough to reach.
var sealBlockSize = 1 << 20

// blockXOR computes the digest a ZED! Free file entry keeps of a byte string.
// The string is cut into 512-byte blocks, the last one possibly short and not
// padded. Block i contributes SHA-256(LE64(i) || id || block); the
// contributions are XORed together, so the value does not depend on how the
// bytes arrive. An empty string gives 32 zero bytes.
type blockXOR struct {
	id   [16]byte
	acc  [sha256.Size]byte
	buf  [fileBlock]byte
	n    int    // bytes pending in buf
	next uint64 // the index of the next block
}

func newBlockXOR(id [16]byte) *blockXOR { return &blockXOR{id: id} }

func (b *blockXOR) block(p []byte) {
	h := sha256.New()
	var idx [8]byte
	binary.LittleEndian.PutUint64(idx[:], b.next)
	h.Write(idx[:])
	h.Write(b.id[:])
	h.Write(p)
	var s [sha256.Size]byte
	h.Sum(s[:0])
	for i := range b.acc {
		b.acc[i] ^= s[i]
	}
	b.next++
}

// Write adds bytes; it never fails.
func (b *blockXOR) Write(p []byte) (int, error) {
	n := len(p)
	if b.n > 0 {
		k := copy(b.buf[b.n:], p)
		b.n += k
		p = p[k:]
		if b.n < fileBlock {
			return n, nil
		}
		b.block(b.buf[:])
		b.n = 0
	}
	for len(p) >= fileBlock {
		b.block(p[:fileBlock])
		p = p[fileBlock:]
	}
	b.n = copy(b.buf[:], p)
	return n, nil
}

// sum returns the digest of everything written, closing the last short block.
// The blockXOR must not be written to afterwards.
func (b *blockXOR) sum() []byte {
	if b.n > 0 {
		b.block(b.buf[:b.n])
		b.n = 0
	}
	return append([]byte(nil), b.acc[:]...)
}

// fileSeal is the value of a file entry's tags 0x00400500 (digest of the file's
// content) and 0x00410500 (digest of the encrypted stream): the HMAC-SHA-256,
// under the seal key, of the file identifier followed by the digest.
func fileSeal(sealKey []byte, id [16]byte, digest []byte) []byte {
	m := hmac.New(sha256.New, sealKey)
	m.Write(id[:])
	m.Write(digest)
	return m.Sum(nil)
}

// globalSeal computes the hash of the seal stream (tag 0x80300500 inside the
// stream) for a finished container image. off and n locate the seal stream's
// record (its header and TLV payload, the n bytes that precede the zero
// padding) in the image; ts is the stream's 8-byte timestamp (tag 0x80110500).
//
// The image is cut into blocks of sealBlockSize bytes (the last one short);
// each block is hashed with SHA-256, with the record's n bytes taken as 0xA5.
// The digests, in order, followed by ts, are the input of an HMAC-SHA-256 under
// the seal key. The record has to lie within one block and not begin on a block
// boundary; the application's own check cannot be satisfied otherwise.
func globalSeal(img []byte, off, n int, sealKey, ts []byte) ([]byte, error) {
	if !placeable(off, n) || off+n > len(img) {
		return nil, fmt.Errorf("zed: the seal stream lies at offset %d of %d, where its hash cannot be computed", off, len(img))
	}
	saved := append([]byte(nil), img[off:off+n]...)
	for i := 0; i < n; i++ {
		img[off+i] = sealMask
	}
	table := make([]byte, 0, (len(img)/sealBlockSize+1)*sha256.Size+len(ts))
	for p := 0; p < len(img); p += sealBlock(len(img), p) {
		s := sha256.Sum256(img[p : p+sealBlock(len(img), p)])
		table = append(table, s[:]...)
	}
	copy(img[off:], saved)
	table = append(table, ts...)
	m := hmac.New(sha256.New, sealKey)
	m.Write(table)
	return m.Sum(nil), nil
}

// placeable says whether a record of n bytes at off can be sealed: it must lie
// within one block and not begin on a block boundary.
func placeable(off, n int) bool {
	return off > 0 && off%sealBlockSize != 0 && off%sealBlockSize+n <= sealBlockSize
}

// sealBlock is the length of the block that starts at p.
func sealBlock(total, p int) int { return min(sealBlockSize, total-p) }

// locate finds the seal stream in the image by its content.
func locate(img, record []byte) (int, error) {
	off := bytes.Index(img, record)
	if off < 0 || bytes.Contains(img[off+1:], record) {
		return 0, fmt.Errorf("zed: the seal stream is not stored as one run of bytes")
	}
	return off, nil
}
