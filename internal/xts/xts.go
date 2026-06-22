// Package xts implements the XTS-AES tweakable block-cipher mode (IEEE
// P1619/D16, NIST SP 800-38E) used for full-disk encryption.
//
// It is a drop-in replacement for golang.org/x/crypto/xts: the Cipher type
// exposes the same NewCipher / Encrypt / Decrypt API and produces
// byte-identical ciphertext. The difference is performance. x/crypto/xts drives
// the underlying block cipher one 16-byte block at a time through the
// cipher.Block interface and advances the XTS tweak with a scalar GF(2^128)
// multiply per block; on a CPU with hardware AES this collapses a ~10 GB/s AES
// engine to ~600 MB/s because the per-block interface dispatch defeats the
// pipelined multi-block AES path.
//
// This package instead ships a fused AES-XTS kernel that pipelines four AES
// blocks at a time and folds the tweak XOR into the round pipeline. On arm64
// (ARMv8 AES + NEON) and amd64 (AES-NI) the kernel runs the AESE/AESMC (resp.
// AESENC) pipeline directly, reaching multi-GB/s per core. On the remaining
// architectures (riscv64, loong64, ppc64le, s390x) it transparently falls back
// to the same per-block algorithm as x/crypto/xts, so behaviour is identical
// everywhere; only the speed differs.
//
// XTS provides confidentiality but no authentication, and does not implement
// ciphertext stealing, so each sector must be a multiple of 16 bytes. It is
// intended for disk-sector encryption only.
package xts

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

// blockSize is the AES (and XTS) block size in bytes.
const blockSize = 16

// Cipher is an expanded XTS key. It is safe for concurrent use.
type Cipher struct {
	// k1 encrypts the data blocks, k2 encrypts the tweak. Both are always
	// populated and used by the portable fallback path.
	k1, k2 cipher.Block

	// accelerated reports whether the fused assembly kernel is available and
	// usable for this cipher (AES, on a supported architecture). When false,
	// Encrypt/Decrypt use the portable per-block path via k1.
	accelerated bool

	// enc and dec are the flat AES round-key schedules used by the assembly
	// kernel. dec already has InvMixColumns folded in for the inner rounds.
	enc    []byte
	dec    []byte
	rounds int
}

// NewCipher creates a Cipher from a function that builds the underlying block
// cipher (which must have a 16-byte block size) and a key that is twice the
// underlying cipher's key length. For AES this is a 32-byte key (AES-128-XTS)
// or a 64-byte key (AES-256-XTS).
func NewCipher(cipherFunc func([]byte) (cipher.Block, error), key []byte) (*Cipher, error) {
	c := new(Cipher)
	var err error
	if c.k1, err = cipherFunc(key[:len(key)/2]); err != nil {
		return nil, err
	}
	if c.k2, err = cipherFunc(key[len(key)/2:]); err != nil {
		return nil, err
	}
	if c.k1.BlockSize() != blockSize {
		return nil, errors.New("xts: cipher does not have a block size of 16")
	}

	// Enable the fused kernel only for AES on a supported architecture. We
	// detect AES by re-deriving a schedule from the data key half; if the
	// caller passed a non-AES cipherFunc the data-key length will not be a
	// valid AES key size and we stay on the portable path.
	dataKey := key[:len(key)/2]
	if accelAvailable && isAESKeyLen(len(dataKey)) && isAESCipher(cipherFunc) {
		c.enc = expandEnc(dataKey)
		c.dec = expandDec(dataKey)
		c.rounds = len(dataKey)/4 + 6
		c.accelerated = true
	}
	return c, nil
}

func isAESKeyLen(n int) bool { return n == 16 || n == 24 || n == 32 }

// isAESCipher reports whether cipherFunc is crypto/aes.NewCipher by comparing
// the block produced against a freshly created AES block of the same concrete
// type. This guards the accelerated path so that a custom 16-byte block cipher
// never gets silently replaced by AES.
func isAESCipher(cipherFunc func([]byte) (cipher.Block, error)) bool {
	probe := make([]byte, 16)
	b, err := cipherFunc(probe)
	if err != nil {
		return false
	}
	ref, _ := aes.NewCipher(probe)
	// crypto/aes returns *aes.Block; comparing the encryption of a known
	// vector is the most robust cross-version check.
	var in, gotB, gotRef [16]byte
	for i := range in {
		in[i] = byte(i)
	}
	b.Encrypt(gotB[:], in[:])
	ref.Encrypt(gotRef[:], in[:])
	return gotB == gotRef
}

// Encrypt encrypts a sector of plaintext into ciphertext using the given sector
// number as the XTS tweak. ciphertext and plaintext must overlap entirely or
// not at all, and len(plaintext) must be a non-zero multiple of 16 bytes.
func (c *Cipher) Encrypt(ciphertext, plaintext []byte, sectorNum uint64) {
	if len(ciphertext) < len(plaintext) {
		panic("xts: ciphertext is smaller than plaintext")
	}
	if len(plaintext)%blockSize != 0 {
		panic("xts: plaintext is not a multiple of the block size")
	}

	tweak := c.tweak(sectorNum)
	if c.accelerated {
		copy(ciphertext, plaintext)
		xtsEncSectorAsm(ciphertext[:len(plaintext)], &c.enc[0], c.rounds, &tweak[0])
		return
	}
	c.cryptBlocks(ciphertext, plaintext, &tweak, true)
}

// Decrypt decrypts a sector of ciphertext into plaintext using the given sector
// number as the XTS tweak. The same overlap and length rules as Encrypt apply.
func (c *Cipher) Decrypt(plaintext, ciphertext []byte, sectorNum uint64) {
	if len(plaintext) < len(ciphertext) {
		panic("xts: plaintext is smaller than ciphertext")
	}
	if len(ciphertext)%blockSize != 0 {
		panic("xts: ciphertext is not a multiple of the block size")
	}

	tweak := c.tweak(sectorNum)
	if c.accelerated {
		copy(plaintext, ciphertext)
		xtsDecSectorAsm(plaintext[:len(ciphertext)], &c.dec[0], c.rounds, &tweak[0])
		return
	}
	c.cryptBlocks(plaintext, ciphertext, &tweak, false)
}

// tweak computes the initial XTS tweak T0 = E_k2(sectorNum) for a sector.
func (c *Cipher) tweak(sectorNum uint64) [blockSize]byte {
	var t [blockSize]byte
	binary.LittleEndian.PutUint64(t[:8], sectorNum)
	c.k2.Encrypt(t[:], t[:])
	return t
}

// cryptBlocks is the portable per-block XTS path, identical in behaviour to
// golang.org/x/crypto/xts. It is used for non-AES ciphers and on architectures
// without an assembly kernel.
func (c *Cipher) cryptBlocks(dst, src []byte, tweak *[blockSize]byte, encrypt bool) {
	n := len(src)
	for i := 0; i < n; i += blockSize {
		for j := 0; j < blockSize; j++ {
			dst[i+j] = src[i+j] ^ tweak[j]
		}
		if encrypt {
			c.k1.Encrypt(dst[i:i+blockSize], dst[i:i+blockSize])
		} else {
			c.k1.Decrypt(dst[i:i+blockSize], dst[i:i+blockSize])
		}
		for j := 0; j < blockSize; j++ {
			dst[i+j] ^= tweak[j]
		}
		mul2(tweak)
	}
}

// mul2 doubles tweak in GF(2^128) with the XTS reduction polynomial
// x^128 + x^7 + x^2 + x + 1.
func mul2(tweak *[blockSize]byte) {
	var carryIn byte
	for j := range tweak {
		carryOut := tweak[j] >> 7
		tweak[j] = (tweak[j] << 1) + carryIn
		carryIn = carryOut
	}
	if carryIn != 0 {
		tweak[0] ^= 1<<7 | 1<<2 | 1<<1 | 1
	}
}
