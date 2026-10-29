package apfs

import (
	"errors"
	"fmt"
)

// Limits bound the work a keybag may make Open do. A keybag is read from the
// image, so it is untrusted: without bounds a locker can ask for 2^32 PBKDF2
// iterations (hours), 4 TiB of Argon2 memory, or a parallelism of 256 that
// becomes 0 once converted to the uint8 argon2 takes -- a panic in
// golang.org/x/crypto/argon2.
//
// Structural bounds always apply: Argon2 1 to 255 threads (what argon2
// takes), at least 8 KiB of memory per thread (RFC 9106 §3.1), at most
// 4 GiB; at least one iteration; a wrapped key of at most 64 bytes plus
// AES-KW's 8 (RFC 3394). The cost bounds are the caller's.
type Limits struct {
	MaxPBKDF2Iterations uint32
	MaxArgon2Time       uint32
	MaxArgon2MemoryKiB  uint32
}

// DefaultLimits are what Open and OpenFrom use: generous for keybags written
// by macOS (FileVault calibrates its PBKDF2 count to the machine) and by this
// package.
var DefaultLimits = Limits{
	MaxPBKDF2Iterations: 1 << 26,
	MaxArgon2Time:       1000,
	MaxArgon2MemoryKiB:  argon2MaxMemoryKiB,
}

const (
	argon2MaxMemoryKiB = 4 << 20 // 4 GiB
	argon2MaxThreads   = 255
	maxWrappedKey      = 64 + 8
)

// ErrLimit is a locker whose parameters a Limits refuses.
var ErrLimit = errors.New("apfs: the keybag asks for more than the limits allow")

func (l Limits) pbkdf2(iter uint64) error {
	if iter < 1 || iter > uint64(l.MaxPBKDF2Iterations) {
		return fmt.Errorf("%w: %d PBKDF2 iterations (1 to %d)", ErrLimit, iter, l.MaxPBKDF2Iterations)
	}
	return nil
}

func (l Limits) argon2(time, memKiB, threads uint64) error {
	maxMem := uint64(min(l.MaxArgon2MemoryKiB, argon2MaxMemoryKiB))
	switch {
	case time < 1 || time > uint64(l.MaxArgon2Time):
		return fmt.Errorf("%w: %d Argon2 passes (1 to %d)", ErrLimit, time, l.MaxArgon2Time)
	case threads < 1 || threads > argon2MaxThreads:
		return fmt.Errorf("%w: %d Argon2 threads (1 to %d)", ErrLimit, threads, argon2MaxThreads)
	case memKiB < 8*threads || memKiB > maxMem:
		return fmt.Errorf("%w: %d KiB of Argon2 memory for %d threads (8 per thread to %d)", ErrLimit, memKiB, threads, maxMem)
	}
	return nil
}

// kekBlob checks a KEKBLOB of an Apple-shape volume keybag.
func (l Limits) kekBlob(kb kekBlobParse) error {
	if err := l.pbkdf2(uint64(kb.Iterations)); err != nil {
		return err
	}
	return wrappedKey(len(kb.WrappedKey))
}

func wrappedKey(n int) error {
	if n > maxWrappedKey {
		return fmt.Errorf("%w: a wrapped key of %d bytes, at most %d", ErrLimit, n, maxWrappedKey)
	}
	return nil
}

// OpenLimited is Open with lim instead of DefaultLimits.
func OpenLimited(path string, passphrase []byte, lim Limits) (*Device, error) {
	return open(path, passphrase, lim)
}

// OpenFromLimited is OpenFrom with lim instead of DefaultLimits.
func OpenFromLimited(rw blockRW, passphrase []byte, lim Limits) (*Device, error) {
	return openDevice(rw, passphrase, lim)
}
