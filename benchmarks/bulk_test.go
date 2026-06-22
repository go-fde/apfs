// Package benchmarks reproduces the hot crypto paths of go-fde/luks in a
// standalone module so the parity numbers in BENCHMARKS.md can be regenerated
// independently of the main package's test/coverage gate.
//
//	go test -bench . -benchtime=3s ./...
//
// The constructions here are byte-for-byte the same calls go-fde/luks makes:
//   - AES-XTS via golang.org/x/crypto/xts over crypto/aes (HW AES on
//     arm64/amd64),
//   - PBKDF2-SHA256 and Argon2id via golang.org/x/crypto.
package benchmarks

import (
	"crypto/aes"
	"crypto/sha256"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/xts"
)

const sectorSize = 512

func data(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func benchXTS(b *testing.B, keyLen, bufBytes int, encrypt bool) {
	c, err := xts.NewCipher(aes.NewCipher, data(keyLen))
	if err != nil {
		b.Fatal(err)
	}
	buf := data(bufBytes)
	n := bufBytes / sectorSize
	b.SetBytes(int64(bufBytes))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for s := 0; s < n; s++ {
			off := s * sectorSize
			if encrypt {
				c.Encrypt(buf[off:off+sectorSize], buf[off:off+sectorSize], uint64(s))
			} else {
				c.Decrypt(buf[off:off+sectorSize], buf[off:off+sectorSize], uint64(s))
			}
		}
	}
}

func BenchmarkXTSEncryptAES256(b *testing.B) { benchXTS(b, 64, 1<<20, true) }
func BenchmarkXTSDecryptAES256(b *testing.B) { benchXTS(b, 64, 1<<20, false) }
func BenchmarkXTSEncryptAES128(b *testing.B) { benchXTS(b, 32, 1<<20, true) }

func BenchmarkPBKDF2_SHA256_100k(b *testing.B) {
	pass := []byte("correct horse battery staple")
	salt := data(32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pbkdf2.Key(pass, salt, 100000, 32, sha256.New)
	}
}

func BenchmarkArgon2id_t4_m256MiB_p1(b *testing.B) {
	pass := []byte("correct horse battery staple")
	salt := data(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = argon2.IDKey(pass, salt, 4, 256*1024, 1, 32)
	}
}
