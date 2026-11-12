package zed

import (
	"errors"
	"math"
	"testing"
)

// One user at MaxIterations costs its PBA count plus three times its PBE count
// (the key takes up to two passes, the IV one): the total must allow it.
// go-fde/zed#4: the defaults were 10M and 30M, so no user could reach 10M.
func TestOneUserAtTheIterationLimitFits(t *testing.T) {
	d := DefaultLimits()
	if d.MaxTotalIterations < 4*d.MaxIterations {
		t.Fatalf("default total %d is below four times the per-user limit %d", d.MaxTotalIterations, d.MaxIterations)
	}
	for _, in := range []Limits{{MaxIterations: 7}, {MaxIterations: 1000}, {MaxIterations: 50_000_000}} {
		got := in.withDefaults()
		if got.MaxTotalIterations != 4*in.MaxIterations {
			t.Errorf("MaxIterations %d: total %d, want %d", in.MaxIterations, got.MaxTotalIterations, 4*in.MaxIterations)
		}
	}
	if got := (Limits{MaxIterations: math.MaxInt}).withDefaults(); got.MaxTotalIterations <= 0 {
		t.Errorf("MaxIterations at MaxInt overflowed: total %d", got.MaxTotalIterations)
	}
	if got := (Limits{MaxIterations: 10, MaxTotalIterations: 12}).withDefaults(); got.MaxTotalIterations != 12 {
		t.Errorf("an explicit total was replaced: %d", got.MaxTotalIterations)
	}
}

// With test-sized limits, an archive whose users sit exactly at MaxIterations
// opens, and one iteration more is refused.
func TestIterationLimitIsReachable(t *testing.T) {
	// The budget counts PKCS#12 SHA-256 rounds. A user of 100 iterations costs
	// its check plus its key and IV as the scheme derives them: SHA-1 100 + 3*100,
	// SHA-256 100 + 2*100, and PBKDF2-HMAC-SHA-512 (weight 16) 1600 + 1600.
	for _, c := range []struct {
		hash          uint32
		maxIter, need int
	}{{hashSHA1, 100, 400}, {hashSHA256, 100, 300}, {hashPBKDF2SHA512, 100 * pbkdf2SHA512Weight, 2 * 100 * pbkdf2SHA512Weight}} {
		a := small()
		a.users = []tUser{{login: "u", password: "s3cret", hash: c.hash, iter: 100}}
		data := a.bytes(t)
		if _, err := open(t, data, "s3cret", WithLimits(Limits{MaxIterations: c.maxIter})); err != nil {
			t.Errorf("hash %d: a user at the limit: %v", c.hash, err)
		}
		if _, err := open(t, data, "s3cret", WithLimits(Limits{MaxIterations: c.maxIter - 1})); !errors.Is(err, ErrLimit) {
			t.Errorf("hash %d: one unit over the limit: %v", c.hash, err)
		}
		// The total, when set, is still what bounds the work.
		if _, err := open(t, data, "s3cret", WithLimits(Limits{MaxIterations: c.maxIter, MaxTotalIterations: c.need - 1})); !errors.Is(err, ErrLimit) {
			t.Errorf("hash %d: total of %d: %v", c.hash, c.need-1, err)
		}
		if _, err := open(t, data, "s3cret", WithLimits(Limits{MaxIterations: c.maxIter, MaxTotalIterations: c.need})); err != nil {
			t.Errorf("hash %d: total of %d: %v", c.hash, c.need, err)
		}
	}
}
