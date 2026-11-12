package zed

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"testing"
)

// benchText is 10 MiB of text-like data that deflate shrinks to about a third.
func benchText() []byte {
	words := []string{"archive", "encrypted", "password", "chunk", "stream", "compound", "file", "binary", "zlib", "cipher"}
	r := random(1<<16, 11)
	var b bytes.Buffer
	for b.Len() < 10<<20 {
		b.WriteString(words[int(r[b.Len()&0xFFFF])%len(words)])
		b.WriteByte(' ')
	}
	return b.Bytes()[:10<<20]
}

// BenchmarkReadFile10MiB extracts one 10 MiB file (AES-256-CBC-CTS, 512-byte
// chunks, zlib). "ideal" is the floor: one CBC decryption of the same
// ciphertext in one call and one inflate, with no chunking and no CFB.
func BenchmarkReadFile10MiB(b *testing.B) {
	text := benchText()
	a := defaultArchive()
	a.key = random(32, 5)
	a.root = []*tNode{{name: "big", data: text}}
	data := a.bytes(b)
	arch, err := open(b, data, "s3cret")
	if err != nil {
		b.Fatal(err)
	}
	e := entry(b, arch, "big")
	b.Run("zed", func(b *testing.B) {
		b.SetBytes(int64(len(text)))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			got, err := arch.ReadFile(e)
			if err != nil || len(got) != len(text) {
				b.Fatal(err)
			}
		}
	})

	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write(text)
	zw.Close()
	blk, _ := aes.NewCipher(a.key)
	zlen := z.Len() &^ (aesBlock - 1) // whole blocks, for the floor only
	ct := make([]byte, zlen)
	pt := make([]byte, zlen)
	b.Run("ideal", func(b *testing.B) {
		b.SetBytes(int64(len(text)))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			cipher.NewCBCDecrypter(blk, make([]byte, 16)).CryptBlocks(pt, ct)
			zr, _ := zlib.NewReader(bytes.NewReader(z.Bytes()))
			if _, err := io.Copy(io.Discard, zr); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkOpen is the cost of unlocking: two PKCS#12 derivations of 200000
// iterations each (SHA-256), as ZED! Free 2024.4 writes them.
func BenchmarkOpen(b *testing.B) {
	a := defaultArchive()
	a.users = []tUser{{login: "u", password: "pw", hash: hashSHA256, iter: 200000}}
	data := a.bytes(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := open(b, data, "pw"); err != nil {
			b.Fatal(err)
		}
	}
}
