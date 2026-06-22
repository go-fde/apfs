package apfs

import (
	"crypto/sha256"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// Benchmarks for the hot crypto paths of the APFS (FileVault-style) backend.
//
// These exercise the exact code that go-fde/apfs uses in production: the
// xtscipher (AES-XTS over golang.org/x/crypto/xts + crypto/aes, hardware AES
// on arm64/amd64) and the PBKDF2 / Argon2id key-derivation used to unwrap the
// volume KEK.
//
// They are excluded from the coverage gate: `go test` without -bench skips
// Benchmark* functions and benchmark bodies do not count toward coverage.

func benchData(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func benchAPFSXTS(b *testing.B, vekLen, bufBytes int, encrypt bool) {
	c, err := newXTSCipher(benchData(vekLen))
	if err != nil {
		b.Fatal(err)
	}
	buf := benchData(bufBytes)
	b.SetBytes(int64(bufBytes))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.processSectors(buf, 0, encrypt)
	}
}

// AES-256-XTS: 64-byte VEK.
func BenchmarkXTSEncryptAES256(b *testing.B) { benchAPFSXTS(b, 64, 1<<20, true) }
func BenchmarkXTSDecryptAES256(b *testing.B) { benchAPFSXTS(b, 64, 1<<20, false) }

// AES-128-XTS: 32-byte VEK (APFS default).
func BenchmarkXTSEncryptAES128(b *testing.B) { benchAPFSXTS(b, 32, 1<<20, true) }

func BenchmarkPBKDF2_SHA256_100k(b *testing.B) {
	pass := []byte("correct horse battery staple")
	salt := benchData(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pbkdf2.Key(pass, salt, 100000, formatKEKSize, sha256.New)
	}
}

func BenchmarkArgon2id_t4_m256MiB_p1(b *testing.B) {
	pass := []byte("correct horse battery staple")
	salt := benchData(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = argon2.IDKey(pass, salt, 4, 256*1024, 1, 32)
	}
}
