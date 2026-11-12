package zed

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"testing"
	"time"
)

// ZED! Free 2026.3 writes pkcs12_hashfunc 43 for PBKDF2-HMAC-SHA-512 with the
// password in UTF-8 (found on a real container: it opens only that way, and the
// unwrapped key reads the catalog and the file byte for byte).
//
// What the 2026.3 container proves is its own 16-byte key and the IV right
// after it. The IV placement for 24- and 32-byte keys (strength bytes, then 16)
// is an inference: this test and TestRoundTripHash43 check it against this
// package's own derivation and builder only, not against a real container.
func TestHashFunc43IsPBKDF2SHA512(t *testing.T) {
	h, err := hashFor(hashPBKDF2SHA512)
	if err != nil || h.size != 64 || h.hmacHash == nil || h.weight() != pbkdf2SHA512Weight {
		t.Fatalf("hashFor(43): %+v %v", h, err)
	}
	// Known answer for PBKDF2-HMAC-SHA-512 (password "password", salt "salt",
	// c = 1, dkLen = 64), against the standard library the package uses.
	k, err := pbkdf2.Key(sha512.New, "password", []byte("salt"), 1, 64)
	if err != nil || hex.EncodeToString(k) != "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce" {
		t.Fatalf("the standard library's PBKDF2 does not give the published vector: %x %v", k, err)
	}
	want, _ := pbkdf2.Key(sha512.New, "s3cret", []byte("saltsalt"), 9, 8)
	if got, err := h.check("s3cret", []byte("saltsalt"), 9, 8); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("check %x want %x (%v)", got, want, err)
	}
	// Key and IV are consecutive bytes of one derivation; the key is keyLen long.
	for _, keyLen := range []int{16, 24, 32} {
		all, _ := pbkdf2.Key(sha512.New, "s3cret", []byte("saltsalt"), 9, keyLen+16)
		key, iv, err := h.keyIV("s3cret", []byte("saltsalt"), 9, keyLen)
		if err != nil || !bytes.Equal(key, all[:keyLen]) || !bytes.Equal(iv, all[keyLen:]) {
			t.Errorf("key length %d: key/IV do not follow the derivation (%v)", keyLen, err)
		}
	}
}

// An archive of hash 43 opens with its password and refuses another, for every
// key size, and its checksum is bound by the hash output (64 bytes).
//
// Only the 16-byte key is checked against a real container (ZED! Free 2026.3).
// The 24- and 32-byte cases round-trip through this package's own builder, so
// they show the code is self-consistent, not that ZED! places the IV there.
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

// The standard library refuses some inputs in FIPS-only mode; that is not a
// wrong password.
func TestPBKDF2FailureIsUnsupportedNotWrongPassword(t *testing.T) {
	a := small()
	a.users[0].hash = hashPBKDF2SHA512
	data := a.bytes(t)
	old := pbkdf2Key
	defer func() { pbkdf2Key = old }()
	boom := errors.New("fips only")
	pbkdf2Key = func(h func() hash.Hash, pw string, salt []byte, iter, n int) ([]byte, error) { return nil, boom }
	if _, err := open(t, data, "s3cret"); !errors.Is(err, ErrUnsupported) || errors.Is(err, ErrPassword) {
		t.Fatalf("a failing PBA: %v", err)
	}
	// A failure in PBE only: the first call (the check) succeeds, the second fails.
	calls := 0
	pbkdf2Key = func(h func() hash.Hash, pw string, salt []byte, iter, n int) ([]byte, error) {
		calls++
		if calls == 2 {
			return nil, boom
		}
		return old(h, pw, salt, iter, n)
	}
	if _, err := open(t, data, "s3cret"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("a failing PBE: %v", err)
	}
}

// The budget charges each scheme what it derives, in PKCS#12 SHA-256 rounds.
func TestBudgetChargesEachSchemeAsItDerives(t *testing.T) {
	h43, _ := hashFor(hashPBKDF2SHA512)
	h256, _ := hashFor(hashSHA256)
	h1, _ := hashFor(hashSHA1)
	// PKCS#12: the check one pass; the key from 32 bytes and the IV from 16, a
	// pass each (the key two passes with SHA-1).
	if pba, pbe := h256.cost(100, 100, 16); pba != 100 || pbe != 200 {
		t.Errorf("SHA-256 cost %d/%d", pba, pbe)
	}
	if pba, pbe := h1.cost(100, 100, 16); pba != 100 || pbe != 300 {
		t.Errorf("SHA-1 cost %d/%d", pba, pbe)
	}
	// PBKDF2-HMAC-SHA-512: the check one pass; key and IV together, one pass for
	// up to 48 bytes (not the 2 or 3 passes PKCS#12 takes).
	for _, keyLen := range []int{16, 24, 32} {
		if pba, pbe := h43.cost(100, 100, keyLen); pba != 100*pbkdf2SHA512Weight || pbe != 100*pbkdf2SHA512Weight {
			t.Errorf("hash 43, key %d: cost %d/%d", keyLen, pba, pbe)
		}
	}
	if pba, pbe := h43.cost(1, 1, 64); pbe != 2*pbkdf2SHA512Weight || pba != pbkdf2SHA512Weight {
		t.Errorf("a 64-byte key would take two passes: %d/%d", pba, pbe)
	}
}

// A hostile hashfunc-43 header at the caps that were right for PKCS#12 (10M
// iterations for one user, 40M together) asks for about five times the work
// (pbkdf2SHA512Weight) and is refused with ErrLimit before anything is derived.
func TestHostileHashFunc43IsRefusedBeforeDeriving(t *testing.T) {
	lim := DefaultLimits()
	mk := func(pba, pbe uint32) user {
		return user{hash: hashPBKDF2SHA512, pbaIter: pba, pbeIter: pbe, pbaSalt: make([]byte, 8), pbeSalt: make([]byte, 8),
			pbaSum: make([]byte, 8), files: make([]byte, 32)}
	}
	for name, us := range map[string][]user{
		"one user at the PKCS#12 cap (10M)":     {mk(10_000_000, 10_000_000)},
		"one user just over the cap, the check": {mk(2_000_001, 1)},
		"one user just over the cap, key + IV":  {mk(1, 2_000_001)},
		"five users just inside the cap each":   {mk(1_900_000, 1), mk(1_900_000, 1), mk(1_900_000, 1), mk(1_900_000, 1), mk(1_900_000, 1)},
	} {
		g := &control{info: Info{KeyBytes: 16}, users: us}
		start := time.Now()
		_, err := g.unlock("x", lim)
		if !errors.Is(err, ErrLimit) {
			t.Errorf("%s: %v", name, err)
		}
		if time.Since(start) > 200*time.Millisecond {
			t.Errorf("%s: refusing took %v: it derived first", name, time.Since(start))
		}
	}
	// What ZED! Free 2026.3 writes (200000 and 100000) is far inside.
	g := &control{info: Info{KeyBytes: 16}, users: []user{mk(200_000, 100_000)}}
	g.users[0].pbaSum = []byte{1, 2, 3, 4, 5, 6, 7, 8}
	if _, err := g.unlock("x", lim); !errors.Is(err, ErrPassword) {
		t.Errorf("the 2026.3 values: %v", err)
	}
}
