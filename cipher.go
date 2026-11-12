package zed

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

// Encryption modes of the encryption_mode field.
const (
	modeStream = 103 // AES-CBC-STREAM
	modeCTS    = 104 // AES-CBC-CTS (CBC-CS3)
)

const (
	chunkSize = 512
	aesBlock  = aes.BlockSize
)

// ecb encrypts one block without chaining.
func ecb(b cipher.Block, in []byte) []byte {
	out := make([]byte, aesBlock)
	b.Encrypt(out, in)
	return out
}

func xorInto(dst, a, b []byte) {
	for i := range dst {
		dst[i] = a[i] ^ b[i]
	}
}

// cbcDecrypt decrypts whole blocks of src into dst (the same length, a
// multiple of 16) chained from iv.
func cbcDecrypt(b cipher.Block, iv, dst, src []byte) {
	cipher.NewCBCDecrypter(b, iv).CryptBlocks(dst, src)
}

// decryptStream is the "STREAM" end-of-stream handler: whole blocks are CBC,
// a final partial block is XORed with the encryption of the previous
// ciphertext block, or of the IV when there is none.
func decryptStream(b cipher.Block, iv, ct []byte) []byte {
	pt := make([]byte, len(ct))
	full := len(ct) &^ (aesBlock - 1)
	if full > 0 {
		cbcDecrypt(b, iv, pt[:full], ct[:full])
	}
	if full < len(ct) {
		prev := iv
		if full > 0 {
			prev = ct[full-aesBlock : full]
		}
		xorInto(pt[full:], ct[full:], ecb(b, prev))
	}
	return pt
}

// decryptCTS is CBC-CS3 (NIST SP 800-38A addendum): the last two ciphertext
// blocks are swapped, the second-to-last being the full block. Ciphertext
// shorter than a block falls back to STREAM, as the format requires.
func decryptCTS(b cipher.Block, iv, ct []byte) []byte {
	if len(ct) <= aesBlock { // one block or less: no swap to make
		return decryptStream(b, iv, ct)
	}
	d := len(ct) - (len(ct)-1)&^(aesBlock-1) // bytes in the last block, 1..16
	head := len(ct) - d - aesBlock           // bytes before the full block Cn
	pt := make([]byte, len(ct))
	if head > 0 {
		cbcDecrypt(b, iv, pt[:head], ct[:head])
	}
	prev := iv
	if head > 0 {
		prev = ct[head-aesBlock : head]
	}
	cn, short := ct[head:head+aesBlock], ct[head+aesBlock:]
	x := make([]byte, aesBlock)
	b.Decrypt(x, cn)
	xorInto(pt[head+aesBlock:], x[:d], short) // last plaintext block
	y := make([]byte, 0, aesBlock)
	y = append(append(y, short...), x[d:]...)
	b.Decrypt(x, y)
	xorInto(pt[head:head+aesBlock], x, prev) // second-to-last plaintext block
	return pt
}

// decryptor holds a file key and the global IV.
type decryptor struct {
	block cipher.Block
	iv    [aesBlock]byte
	mode  uint32
}

func newDecryptor(key []byte, iv []byte, mode uint32) (*decryptor, error) {
	if mode != modeStream && mode != modeCTS {
		return nil, fmt.Errorf("%w: encryption_mode %d", ErrUnsupported, mode)
	}
	if len(iv) != aesBlock {
		return nil, fmt.Errorf("%w: files_iv is %d bytes", ErrFormat, len(iv))
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: file key: %v", ErrFormat, err)
	}
	d := &decryptor{block: b, mode: mode}
	copy(d.iv[:], iv)
	return d, nil
}

// decrypt applies the archive's end-of-stream handler with the given IV.
func (d *decryptor) decrypt(iv, ct []byte) []byte {
	if d.mode == modeCTS {
		return decryptCTS(d.block, iv, ct)
	}
	return decryptStream(d.block, iv, ct)
}

// chunkIV is AES-ECB(key, LE16(index) XOR global IV).
func (d *decryptor) chunkIV(index uint64) []byte {
	var x [aesBlock]byte
	binary.LittleEndian.PutUint64(x[:], index)
	xorInto(x[:], x[:], d.iv[:])
	return ecb(d.block, x[:])
}

// decryptChunk decrypts the index-th 512-byte chunk of a file stream.
func (d *decryptor) decryptChunk(index uint64, ct []byte) []byte {
	return d.decrypt(d.chunkIV(index), ct)
}
