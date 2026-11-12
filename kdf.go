package zed

import (
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"unicode/utf16"
)

// Hash function identifiers of the pkcs12_hashfunc field.
const (
	hashSHA1   = 21
	hashSHA256 = 22
	// hashPBKDF2SHA512 is not a PKCS#12 hash: ZED! Free 2026.3 writes 43 for
	// PBKDF2-HMAC-SHA-512 with the password in UTF-8.
	hashPBKDF2SHA512 = 43
)

// pbkdf2SHA512Weight is the cost of one PBKDF2-HMAC-SHA-512 iteration in
// PKCS#12 SHA-256 rounds, the unit of the iteration budget. Measured with
// BenchmarkKDFRound on an Apple M4 Max, one core, 1-minute load 7.8, six rounds:
// 46.4 ns per PKCS#12 SHA-256 round (40.2 for SHA-1) and 225.3 ns per
// PBKDF2-HMAC-SHA-512 iteration, a ratio of 4.86, rounded up to 5.
const pbkdf2SHA512Weight = 5

// PKCS#12 diversifier IDs (RFC 7292, appendix B.3).
const (
	idKey = 1 // encryption key
	idIV  = 2 // initialisation vector
	idMAC = 3 // integrity key: ZED uses it as the password check
)

// hashSpec is what pkcs12_hashfunc selects. For the PKCS#12 KDF (21, 22) it is a
// hash: output size u, block size v and a one-shot sum into dst. For 43 (ZED!
// Free 2026.3) it is PBKDF2-HMAC-SHA-512 and hmacHash is set.
type hashSpec struct {
	size     int
	block    int
	sum      func(dst, data []byte) []byte
	hmacHash func() hash.Hash // non-nil: PBKDF2-HMAC with this hash, UTF-8 password
}

// pbkdf2Key is replaceable so that a test can make it fail, which the standard
// library does only in FIPS-only mode.
var pbkdf2Key = func(h func() hash.Hash, password string, salt []byte, iter, n int) ([]byte, error) {
	return pbkdf2.Key(h, password, salt, iter, n)
}

// weight is the cost of one iteration in PKCS#12 SHA-256 rounds.
func (h hashSpec) weight() uint64 {
	if h.hmacHash != nil {
		return pbkdf2SHA512Weight
	}
	return 1
}

// cost is the work, in PKCS#12 SHA-256 rounds, of the two derivations a user's
// header asks for: pba for the password check, pbe for the key and the IV,
// each as the scheme really derives. PKCS#12 derives the key from 32 bytes and
// the IV from 16, each a pass of the hash (the key two passes with SHA-1); PBKDF2
// derives key and IV together, one pass of 64 bytes for keys up to 48.
func (h hashSpec) cost(pbaIter, pbeIter uint64, keyLen int) (pba, pbe uint64) {
	if h.hmacHash != nil {
		passes := uint64(keyLen+16+h.size-1) / uint64(h.size)
		return pbaIter * h.weight(), pbeIter * h.weight() * passes
	}
	passes := uint64((32+h.size-1)/h.size + 1)
	return pbaIter, pbeIter * passes
}

// check derives the n bytes of the password check (PBA).
func (h hashSpec) check(password string, salt []byte, iter, n int) ([]byte, error) {
	if h.hmacHash != nil {
		return pbkdf2Key(h.hmacHash, password, salt, iter, n)
	}
	return pkcs12KDF(h, bmpPassword(password), salt, idMAC, iter, n), nil
}

// keyIV derives the key that unwraps the archive key, keyLen bytes, and its
// 16-byte IV (PBE). With PBKDF2 they are consecutive bytes of one derivation;
// the PKCS#12 KDF derives them separately (IDs 1 and 2), the key from 32 bytes
// cut to keyLen.
func (h hashSpec) keyIV(password string, salt []byte, iter, keyLen int) (key, iv []byte, err error) {
	if h.hmacHash != nil {
		d, err := pbkdf2Key(h.hmacHash, password, salt, iter, keyLen+16)
		if err != nil {
			return nil, nil, err
		}
		return d[:keyLen], d[keyLen:], nil
	}
	pw := bmpPassword(password)
	return pkcs12KDF(h, pw, salt, idKey, iter, 32)[:keyLen], pkcs12KDF(h, pw, salt, idIV, iter, 16), nil
}

func hashFor(id uint32) (hashSpec, error) {
	switch id {
	case hashSHA1:
		return hashSpec{size: sha1.Size, block: 64, sum: func(dst, data []byte) []byte {
			s := sha1.Sum(data)
			return append(dst[:0], s[:]...)
		}}, nil
	case hashSHA256:
		return hashSpec{size: sha256.Size, block: 64, sum: func(dst, data []byte) []byte {
			s := sha256.Sum256(data)
			return append(dst[:0], s[:]...)
		}}, nil
	case hashPBKDF2SHA512:
		return hashSpec{size: sha512.Size, hmacHash: sha512.New}, nil
	}
	return hashSpec{}, fmt.Errorf("%w: pkcs12_hashfunc %d", ErrUnsupported, id)
}

// bmpPassword encodes a password as RFC 7292 appendix B.1 asks: UTF-16 big
// endian with a terminating NUL; the empty password stays empty.
func bmpPassword(pw string) []byte {
	if pw == "" {
		return nil
	}
	u := utf16.Encode([]rune(pw))
	b := make([]byte, 0, 2*len(u)+2)
	for _, c := range u {
		b = append(b, byte(c>>8), byte(c))
	}
	return append(b, 0, 0)
}

// pkcs12KDF is the key derivation of RFC 7292 appendix B.2 for a hash of
// output size h.size and block size h.block. pw is the already encoded
// password.
func pkcs12KDF(h hashSpec, pw, salt []byte, id byte, iter, n int) []byte {
	v := h.block
	stretch := func(in []byte) []byte {
		if len(in) == 0 {
			return nil
		}
		out := make([]byte, v*((len(in)+v-1)/v))
		for i := range out {
			out[i] = in[i%len(in)]
		}
		return out
	}
	I := append(stretch(salt), stretch(pw)...)
	D := make([]byte, v)
	for i := range D {
		D[i] = id
	}
	out := make([]byte, 0, n+h.size)
	buf := make([]byte, 0, v+len(I))
	B := make([]byte, v)
	var A []byte
	for len(out) < n {
		buf = append(append(buf[:0], D...), I...)
		A = h.sum(A, buf)
		for r := 1; r < iter; r++ {
			A = h.sum(A, A)
		}
		out = append(out, A...)
		if len(out) >= n {
			break
		}
		// B is A repeated to v bytes; add B+1 into every v-byte block of I.
		for i := range B {
			B[i] = A[i%len(A)]
		}
		for j := 0; j < len(I); j += v {
			carry := 1
			for k := v - 1; k >= 0; k-- {
				s := int(I[j+k]) + int(B[k]) + carry
				I[j+k], carry = byte(s), s>>8
			}
		}
	}
	return out[:n]
}
