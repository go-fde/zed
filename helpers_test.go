package zed

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

func mustAES(key []byte) cipher.Block {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return b
}

// cbcEncrypt encrypts whole blocks in place.
func cbcEncrypt(b cipher.Block, iv, data []byte) {
	cipher.NewCBCEncrypter(b, iv).CryptBlocks(data, data)
}

// entry returns the entry at path, or stops the test: a nil entry passed on
// to ReadFile would panic and take every other test of the package with it.
func entry(t testing.TB, a *Archive, path string) *Entry {
	t.Helper()
	e := a.Lookup(path)
	if e == nil {
		t.Fatalf("the archive has no entry %q", path)
	}
	return e
}
