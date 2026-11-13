package zed

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"time"
	"unicode/utf16"
)

// The encoders of the archive's byte layouts: the inverse of what tlv.go,
// cipher.go and zed.go decode.

func be32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

func le64(v uint64) []byte { return binary.LittleEndian.AppendUint64(nil, v) }

// put encodes one TLV item: type, length (big endian) and value.
func put(tag uint32, vals ...[]byte) []byte {
	v := bytes.Join(vals, nil)
	return append(append(be32(tag), be32(uint32(len(v)))...), v...)
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// u16 is a UTF-16LE string with a terminating NUL.
func u16(s string) []byte {
	var b []byte
	for _, c := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return append(b, 0, 0)
}

// nameBytes is a UTF-16LE string without the NUL, as filename_ciphertext holds
// a name and as login and archive_createdwith are stored.
func nameBytes(s string) []byte {
	b := u16(s)
	return b[:len(b)-2]
}

// ftBytes is a FILETIME, little endian; the zero time is "not recorded".
func ftBytes(t time.Time) []byte {
	if t.IsZero() {
		return le64(0)
	}
	return le64(uint64(t.Unix()+11644473600)*10_000_000 + uint64(t.Nanosecond()/100))
}

// encryptStream is decryptStream's inverse.
func encryptStream(b cipher.Block, iv, pt []byte) []byte {
	ct := make([]byte, len(pt))
	full := len(pt) &^ (aesBlock - 1)
	if full > 0 {
		cipher.NewCBCEncrypter(b, iv).CryptBlocks(ct[:full], pt[:full])
	}
	if full < len(pt) {
		prev := iv
		if full > 0 {
			prev = ct[full-aesBlock : full]
		}
		xorInto(ct[full:], pt[full:], ecb(b, prev))
	}
	return ct
}

// encryptCTS is decryptCTS's inverse: CBC-CS3, CBC over the zero-padded data
// with the last two blocks swapped and the last one cut to the data's length.
func encryptCTS(b cipher.Block, iv, pt []byte) []byte {
	if len(pt) <= aesBlock {
		return encryptStream(b, iv, pt)
	}
	d := len(pt) - (len(pt)-1)&^(aesBlock-1)
	padded := append(append([]byte(nil), pt...), make([]byte, aesBlock-d)...)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(b, iv).CryptBlocks(ct, padded)
	n := len(ct)
	out := append([]byte(nil), ct[:n-2*aesBlock]...)
	out = append(out, ct[n-aesBlock:]...)
	return append(out, ct[n-2*aesBlock:n-2*aesBlock+d]...)
}

// encrypt applies the archive's end-of-stream handler with the given IV.
func (d *decryptor) encrypt(iv, pt []byte) []byte {
	if d.mode == modeCTS {
		return encryptCTS(d.block, iv, pt)
	}
	return encryptStream(d.block, iv, pt)
}

// obfuscate wraps a _ctlfile plaintext the way ZED does: delimiter, version,
// IV, the plaintext under the static key, the length of all that, and the
// closing delimiter.
func obfuscate(version string, iv, plain []byte) []byte {
	b, _ := aes.NewCipher(staticKey)
	ver := []byte{0x01, 0x00}
	if version == "0200" {
		ver = []byte{0x02, 0x00}
	}
	out := cat(delimiter, ver, iv, encryptStream(b, iv, plain))
	out = append(out, be32(uint32(len(out)))...)
	return cat(out, delimiter, []byte(trailerText))
}
