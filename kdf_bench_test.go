package zed

import (
	"testing"
)

// BenchmarkKDFRound measures one iteration of each derivation on one core:
// the PKCS#12 round with SHA-256 (the unit of the iteration budget), with
// SHA-1, and one PBKDF2-HMAC-SHA-512 iteration. The ratio of the last to the
// first is pbkdf2SHA512Weight. Run it on an idle machine (1-minute load at most
// 8), interleaved:
//
//	go test -bench KDFRound -count 6 -benchtime 20x
func BenchmarkKDFRound(b *testing.B) {
	const iter = 100_000
	salt := []byte("saltsalt")
	for _, c := range []struct {
		name string
		id   uint32
	}{{"pkcs12-sha256", hashSHA256}, {"pkcs12-sha1", hashSHA1}, {"pbkdf2-hmac-sha512", hashPBKDF2SHA512}} {
		h, _ := hashFor(c.id)
		b.Run(c.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				h.check("password", salt, iter, 8)
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/iter, "ns/iteration")
		})
	}
}
