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
//
// The first three bound ONE locker. The last three bound the keybag as a
// whole, checked before the first derivation, so that many lockers each at the
// per-locker limit cannot multiply it; zero means the default described on
// each field, so a Limits written before these existed keeps working.
type Limits struct {
	MaxPBKDF2Iterations uint32
	MaxArgon2Time       uint32
	MaxArgon2MemoryKiB  uint32

	// MaxLockers is the most passphrase lockers a keybag may hold. Zero
	// means 16.
	MaxLockers uint32
	// MaxTotalPBKDF2Iterations is the most PBKDF2 iterations summed over
	// the keybag's lockers. Zero means 4 x MaxPBKDF2Iterations.
	MaxTotalPBKDF2Iterations uint64
	// MaxTotalArgon2Work is the most Argon2 work, passes x KiB of memory,
	// summed over the keybag's lockers. Zero means 4 x MaxArgon2Time x
	// MaxArgon2MemoryKiB.
	MaxTotalArgon2Work uint64
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

// The totals. The bounds above are for ONE locker; a keybag holds many (about
// a thousand at 4 KiB blocks, sixteen thousand at 64 KiB) and an image needs
// no key material to ask for all of them, so the keybag as a whole is bounded
// too, before the first derivation, and one over a bound is ErrLimit, not
// "wrong passphrase".

// defaultMaxLockers is what Limits.MaxLockers == 0 means. macOS writes one
// passphrase locker per user plus recovery keys; sixteen is generous.
const defaultMaxLockers = 16

// defaultTotalLockers is the multiple of one locker's cost a keybag may ask
// for in total when no total is set: four lockers at the per-locker limit.
const defaultTotalLockers = 4

func (l Limits) maxLockers() uint64 {
	if l.MaxLockers == 0 {
		return defaultMaxLockers
	}
	return uint64(l.MaxLockers)
}

func (l Limits) maxTotalPBKDF2() uint64 {
	if l.MaxTotalPBKDF2Iterations == 0 {
		return defaultTotalLockers * uint64(l.MaxPBKDF2Iterations)
	}
	return l.MaxTotalPBKDF2Iterations
}

func (l Limits) maxTotalArgon2() uint64 {
	if l.MaxTotalArgon2Work == 0 {
		return mulSat(defaultTotalLockers, mulSat(uint64(l.MaxArgon2Time), uint64(min(l.MaxArgon2MemoryKiB, argon2MaxMemoryKiB))))
	}
	return l.MaxTotalArgon2Work
}

// mulSat is a*b, saturating instead of wrapping.
func mulSat(a, b uint64) uint64 {
	if a != 0 && b > ^uint64(0)/a {
		return ^uint64(0)
	}
	return a * b
}

func satAdd(a, b uint64) uint64 {
	if a > ^uint64(0)-b {
		return ^uint64(0)
	}
	return a + b
}

// work is what the KDFs of a keybag cost if every locker is tried.
type work struct {
	pbkdf2 uint64 // iterations
	argon2 uint64 // passes x KiB of memory
}

func (w *work) addPBKDF2(iter uint32) {
	w.pbkdf2 = satAdd(w.pbkdf2, uint64(iter))
}

func (w *work) addArgon2(time, memKiB uint32) {
	w.argon2 = satAdd(w.argon2, mulSat(uint64(time), uint64(memKiB)))
}

// total refuses a keybag with more lockers, or more total KDF work, than l
// allows. nLockers counts every locker entry, whatever its parameters; w adds
// up only those that pass the per-locker bounds, since the others are refused
// without a derivation.
func (l Limits) total(nLockers int, w work) error {
	switch {
	case uint64(nLockers) > l.maxLockers():
		return fmt.Errorf("%w: %d lockers in the keybag (at most %d)", ErrLimit, nLockers, l.maxLockers())
	case w.pbkdf2 > l.maxTotalPBKDF2():
		return fmt.Errorf("%w: %d PBKDF2 iterations across the keybag's lockers (at most %d in total)", ErrLimit, w.pbkdf2, l.maxTotalPBKDF2())
	case w.argon2 > l.maxTotalArgon2():
		return fmt.Errorf("%w: %d KiB-passes of Argon2 across the keybag's lockers (at most %d in total)", ErrLimit, w.argon2, l.maxTotalArgon2())
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
