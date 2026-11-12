package zed

import (
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"unicode/utf16"
)

// Hash function identifiers of the pkcs12_hashfunc field.
const (
	hashSHA1   = 21
	hashSHA256 = 22
)

// PKCS#12 diversifier IDs (RFC 7292, appendix B.3).
const (
	idKey  = 1 // encryption key
	idIV   = 2 // initialisation vector
	idMAC  = 3 // integrity key: ZED uses it as the password check
	blockV = 64
)

type hashSpec struct {
	new  func() hash.Hash
	size int
	sum  func(dst, data []byte) []byte
}

func hashFor(id uint32) (hashSpec, error) {
	switch id {
	case hashSHA1:
		return hashSpec{sha1.New, sha1.Size, func(dst, data []byte) []byte {
			s := sha1.Sum(data)
			return append(dst[:0], s[:]...)
		}}, nil
	case hashSHA256:
		return hashSpec{sha256.New, sha256.Size, func(dst, data []byte) []byte {
			s := sha256.Sum256(data)
			return append(dst[:0], s[:]...)
		}}, nil
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

// pkcs12KDF is the key derivation of RFC 7292 appendix B.2, for a hash whose
// block size is 64 bytes (SHA-1 and SHA-256). pw is the already encoded
// password.
func pkcs12KDF(h hashSpec, pw, salt []byte, id byte, iter, n int) []byte {
	stretch := func(in []byte) []byte {
		if len(in) == 0 {
			return nil
		}
		out := make([]byte, blockV*((len(in)+blockV-1)/blockV))
		for i := range out {
			out[i] = in[i%len(in)]
		}
		return out
	}
	I := append(stretch(salt), stretch(pw)...)
	D := make([]byte, blockV)
	for i := range D {
		D[i] = id
	}
	out := make([]byte, 0, n+h.size)
	buf := make([]byte, 0, blockV+len(I))
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
		var B [blockV]byte
		for i := range B {
			B[i] = A[i%len(A)]
		}
		for j := 0; j < len(I); j += blockV {
			carry := 1
			for k := blockV - 1; k >= 0; k-- {
				s := int(I[j+k]) + int(B[k]) + carry
				I[j+k], carry = byte(s), s>>8
			}
		}
	}
	return out[:n]
}
