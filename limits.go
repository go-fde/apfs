package apfs

import (
	"fmt"

	"github.com/go-encryptions/kdfbudget"
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
// The first three bound ONE locker. MaxLockers bounds how many a keybag may
// hold, checked before the first derivation; zero means 16, so a Limits written
// before it existed keeps working. Budget bounds the TOTAL work across the
// lockers: every derivation is charged to it before it runs.
type Limits struct {
	MaxPBKDF2Iterations uint32
	MaxArgon2Time       uint32
	MaxArgon2MemoryKiB  uint32

	// MaxLockers is the most passphrase lockers a keybag may hold. Zero
	// means 16.
	MaxLockers uint32

	// Budget bounds the total key-derivation work of ONE unlock (see
	// go-encryptions/kdfbudget). Nil means a fresh kdfbudget.Default() for
	// each unlock; kdfbudget.Unlimited() is for an image you trust. A Budget
	// is spent as it is used, so give each unlock its own: one shared across
	// unlocks runs out.
	Budget *kdfbudget.Budget
}

// forUnlock is l with a Budget: its own, or a fresh default one.
func (l Limits) forUnlock() Limits {
	if l.Budget == nil {
		l.Budget = kdfbudget.Default()
	}
	return l
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

// ErrLimit is a locker, or a keybag, that a Limits or its Budget refuses. It is
// kdfbudget.ErrLimit, so errors.Is matches either package's.
var ErrLimit = kdfbudget.ErrLimit

// chargePBKDF2 charges a PBKDF2-HMAC-SHA256 run producing keyLen bytes to the
// unlock's Budget, one charge per output block, before it is spent.
func (l Limits) chargePBKDF2(iters uint64, keyLen int) error {
	for blocks := (keyLen + 31) / 32; blocks > 0; blocks-- {
		if err := l.Budget.ChargePBKDF2(kdfbudget.CostSHA256, iters); err != nil {
			return err
		}
	}
	return nil
}

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

// The locker count. The bounds above are for ONE locker; a keybag holds many
// (about a thousand at 4 KiB blocks, sixteen thousand at 64 KiB) and an image
// needs no key material to ask for all of them, so their number is bounded
// too, before the first derivation, and one over the bound is ErrLimit, not
// "wrong passphrase".

// defaultMaxLockers is what Limits.MaxLockers == 0 means. macOS writes one
// passphrase locker per user plus recovery keys; sixteen is generous.
const defaultMaxLockers = 16

func (l Limits) maxLockers() uint64 {
	if l.MaxLockers == 0 {
		return defaultMaxLockers
	}
	return uint64(l.MaxLockers)
}

// lockerCount refuses a keybag with more passphrase lockers than l allows.
// n counts every locker entry, whatever its parameters.
//
// The total KDF work across the lockers is bounded by Limits.Budget.
func (l Limits) lockerCount(n int) error {
	if uint64(n) > l.maxLockers() {
		return fmt.Errorf("%w: %d lockers in the keybag (at most %d)", ErrLimit, n, l.maxLockers())
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
