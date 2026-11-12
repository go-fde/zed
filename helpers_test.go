package zed

import (
	"crypto/aes"
	"crypto/cipher"
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
