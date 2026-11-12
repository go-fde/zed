package zed

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"testing"
)

// ZED! Free 2026.3 writes pkcs12_hashfunc 43 for PBKDF2-HMAC-SHA-512 with the
// password in UTF-8 (found on a real container: it opens only that way, and the
// unwrapped key reads the catalog and the file byte for byte).
func TestPBKDF2AgainstTheStandardLibrary(t *testing.T) {
	for _, nh := range []func() hash.Hash{sha512.New, sha256.New} {
		for _, c := range []struct {
			pw, salt string
			iter, n  int
		}{
			{"password", "salt", 1, 64}, {"password", "salt", 2, 8}, {"pässwörd ✓", "\x00\x01\x02\x03", 50, 150},
			{"", "salt", 3, 20}, {"x", "", 7, 1}, {"a long password that is longer than one hash block, certainly longer than 128 bytes............................................................",
				"salt", 4, 200},
		} {
			want, err := pbkdf2.Key(nh, c.pw, []byte(c.salt), c.iter, c.n)
			if err != nil {
				t.Skipf("the standard library refuses %+v: %v", c, err) // FIPS mode
			}
			if got := pbkdf2Of(nh, c.pw, c.salt, c.iter, c.n); !bytes.Equal(got, want) {
				t.Errorf("%+v: got %x want %x", c, got, want)
			}
		}
	}
}

func pbkdf2Of(nh func() hash.Hash, pw, salt string, iter, n int) []byte {
	return pbkdf2HMAC(nh, []byte(pw), []byte(salt), iter, n)
}

func TestHashFunc43IsPBKDF2SHA512(t *testing.T) {
	h, err := hashFor(hashPBKDF2SHA512)
	if err != nil || h.size != 64 || h.hmacHash == nil {
		t.Fatalf("hashFor(43): %+v %v", h, err)
	}
	want, _ := pbkdf2.Key(sha512.New, "s3cret", []byte("saltsalt"), 9, 8)
	if got := h.check("s3cret", []byte("saltsalt"), 9, 8); !bytes.Equal(got, want) {
		t.Fatalf("check %x want %x", got, want)
	}
	// Key and IV are consecutive bytes of one derivation; the key is keyLen long.
	for _, keyLen := range []int{16, 24, 32} {
		all, _ := pbkdf2.Key(sha512.New, "s3cret", []byte("saltsalt"), 9, keyLen+16)
		key, iv := h.keyIV("s3cret", []byte("saltsalt"), 9, keyLen)
		if !bytes.Equal(key, all[:keyLen]) || !bytes.Equal(iv, all[keyLen:]) {
			t.Errorf("key length %d: key/IV do not follow the derivation", keyLen)
		}
	}
}

// An archive of hash 43 opens with its password and refuses another, for every
// key size, and its checksum is bound by the hash output (64 bytes).
func TestRoundTripHash43(t *testing.T) {
	for _, keyLen := range []int{16, 24, 32} {
		a := defaultArchive()
		a.key = random(keyLen, 3)
		a.users = []tUser{{login: "u", password: "pässwörd ✓", hash: hashPBKDF2SHA512, iter: 6}}
		a.root = []*tNode{{name: "f", data: random(1500, 5)}}
		data := a.bytes(t)
		arch, err := open(t, data, "pässwörd ✓")
		if err != nil {
			t.Fatalf("key %d: %v", keyLen, err)
		}
		if got, err := arch.ReadFile(entry(t, arch, "f")); err != nil || !bytes.Equal(got, a.root[0].data) {
			t.Fatalf("key %d: %v", keyLen, err)
		}
		if _, err := open(t, data, "other"); !errors.Is(err, ErrPassword) {
			t.Fatalf("key %d: wrong password: %v", keyLen, err)
		}
	}
	a := small()
	a.users[0].hash = hashPBKDF2SHA512
	expect(t, "checksum of 65 bytes for a 64-byte hash", a.with(ed{"user", tagPBAChecksum, make([]byte, 65)}), ErrFormat)
}
