package apfs

import (
	"bytes"
	"errors"
	"testing"

	"github.com/go-encryptions/kdfbudget"
)

// lockerImage is a legacy container holding n PBKDF2 passphrase lockers of
// iter iterations (none of which opens for "x") and a volume key entry.
func lockerImage(t *testing.T, n int, iter uint32) *memRW {
	t.Helper()
	locker := encodePBKDF2Locker(iter, nil, make([]byte, 24))
	var entries []rawEntry
	for range n {
		entries = append(entries, rawEntry{tag: kbTagVolumePassphrase, data: locker})
	}
	entries = append(entries, rawEntry{tag: kbTagVolumeKey, data: make([]byte, 24)})
	return hostileLegacyImage(t, 16, entries)
}

// A keybag of 1022 lockers used to be tried one by one (issue #35).
func TestLockerCountIsBounded(t *testing.T) {
	lim := Limits{MaxPBKDF2Iterations: 2000, MaxArgon2Time: 1, MaxArgon2MemoryKiB: 8}
	_, err := OpenFromLimited(lockerImage(t, 1022, 2000), []byte("x"), lim)
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("1022 lockers: err = %v, want ErrLimit", err)
	}
	if errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("a refusal must not read as a wrong passphrase: %v", err)
	}
}

func TestLockerCountIsBoundedUnderDefaultLimits(t *testing.T) {
	_, err := OpenFrom(lockerImage(t, 200, 1), []byte("x"))
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("200 lockers: err = %v, want ErrLimit", err)
	}
}

func TestLockerCountEdges(t *testing.T) {
	base := Limits{MaxPBKDF2Iterations: 100, MaxArgon2Time: 1, MaxArgon2MemoryKiB: 8}
	cases := []struct {
		name  string
		n     int
		max   uint32
		limit bool
	}{
		{"explicit, at the edge", 3, 3, false},
		{"explicit, one over", 4, 3, true},
		{"default 16", 16, 0, false},
		{"default 17", 17, 0, true},
	}
	for _, c := range cases {
		lim := base
		lim.MaxLockers = c.max
		_, err := OpenFromLimited(lockerImage(t, c.n, 100), []byte("x"), lim)
		if got := errors.Is(err, ErrLimit); got != c.limit {
			t.Errorf("%s: ErrLimit = %v (err = %v), want %v", c.name, got, err, c.limit)
		}
		if !c.limit && !errors.Is(err, ErrWrongPassphrase) {
			t.Errorf("%s: err = %v, want a wrong passphrase", c.name, err)
		}
	}
}

func TestAppleShapeLockerCount(t *testing.T) {
	pass := []byte("known")
	lim := Limits{MaxPBKDF2Iterations: 1000, MaxArgon2Time: 1, MaxArgon2MemoryKiB: 8, MaxLockers: 4}
	img, _, _ := appleShapeImageN(t, pass, 1000, 32, 4)
	if _, err := UnlockVolumeKey(bytes.NewReader(img), pass, lim); err != nil {
		t.Fatalf("4 KEKBLOBs at the edge: %v", err)
	}
	img, _, _ = appleShapeImageN(t, pass, 1000, 32, 5)
	_, err := UnlockVolumeKey(bytes.NewReader(img), pass, lim)
	if !errors.Is(err, ErrLimit) || errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("5 KEKBLOBs: err = %v, want ErrLimit", err)
	}
	img, _, _ = appleShapeImageN(t, pass, 1, 32, 17)
	_, err = UnlockVolumeKey(bytes.NewReader(img), pass, Limits{MaxPBKDF2Iterations: 1 << 20})
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("17 KEKBLOBs under the default count: err = %v, want ErrLimit", err)
	}
}

func TestLimitsZeroLockersMeansDefault(t *testing.T) {
	l := Limits{}
	if l.maxLockers() != 16 {
		t.Fatalf("default = %d", l.maxLockers())
	}
	l.MaxLockers = 2
	if l.maxLockers() != 2 {
		t.Fatalf("explicit = %d", l.maxLockers())
	}
}

// The keybag rewrite path (AddRecoveryKey and friends) walks the lockers too.
func TestRewritePathRefusesTooManyLockers(t *testing.T) {
	rw := lockerImage(t, 200, 1)
	before := append([]byte(nil), rw.buf...)
	err := AddRecoveryKey(rw, []byte("x"), []byte("recovery"))
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("AddRecoveryKey on 200 lockers: err = %v, want ErrLimit", err)
	}
	if !bytes.Equal(before, rw.buf) {
		t.Fatal("the image was modified")
	}
}

func argon2Image(t *testing.T, timeCost, memKiB uint32, par uint16) *memRW {
	t.Helper()
	locker := encodeArgon2idLocker(timeCost, memKiB, par, make([]byte, 16), make([]byte, 40))
	return hostileLegacyImage(t, 16, []rawEntry{
		{tag: kbTagVolumePassphrase, data: locker},
		{tag: kbTagVolumeKey, data: make([]byte, 24)},
	})
}

// 128 lockers of 4 GiB of Argon2 fill the default budget exactly; the 129th is
// refused before it derives anything. The first 128 are charged by hand: running
// them would take hours.
func TestBudgetRefusesThe129thFourGiBArgon2Locker(t *testing.T) {
	const memKiB = 4 << 20
	b := kdfbudget.Default()
	for i := range 128 {
		if err := b.ChargeArgon2(memKiB, 1, 1); err != nil {
			t.Fatalf("charge %d refused: %v", i+1, err)
		}
	}
	_, err := OpenFromLimited(argon2Image(t, 1, memKiB, 1), []byte("x"), Limits{
		MaxPBKDF2Iterations: 1, MaxArgon2Time: 1, MaxArgon2MemoryKiB: memKiB, Budget: b,
	})
	if !errors.Is(err, ErrLimit) || !errors.Is(err, kdfbudget.ErrLimit) || errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("129th 4 GiB locker: err = %v, want ErrLimit", err)
	}
}

func TestBudgetRefuses256ThreadLocker(t *testing.T) {
	// 256 would become 0 in argon2's uint8 and panic; the Budget refuses it
	// too when the per-locker Limits would not.
	for _, b := range []*kdfbudget.Budget{nil, kdfbudget.Unlimited()} {
		_, err := OpenFromLimited(argon2Image(t, 1, 1<<16, 256), []byte("x"), Limits{
			MaxPBKDF2Iterations: 1, MaxArgon2Time: 1000, MaxArgon2MemoryKiB: 1 << 20, Budget: b,
		})
		if !errors.Is(err, ErrLimit) {
			t.Fatalf("256 threads (budget %v): err = %v, want ErrLimit", b, err)
		}
	}
}

// The total work across lockers is bounded: each locker is within its limit,
// the keybag is not.
func TestBudgetBoundsTheTotalAcrossLockers(t *testing.T) {
	const iter = 100
	// PBKDF2-SHA256 costs 2 units per iteration: room for three lockers.
	mk := func(work uint64) Limits {
		return Limits{MaxPBKDF2Iterations: iter, MaxArgon2Time: 1, MaxArgon2MemoryKiB: 8, MaxLockers: 100,
			Budget: &kdfbudget.Budget{MaxMemory: 1 << 30, MaxThreads: 255, MaxWork: work}}
	}
	for _, c := range []struct {
		n     int
		limit bool
	}{{3, false}, {4, true}} {
		_, err := OpenFromLimited(lockerImage(t, c.n, iter), []byte("x"), mk(3*2*iter))
		if got := errors.Is(err, ErrLimit); got != c.limit {
			t.Errorf("%d lockers: ErrLimit = %v (err = %v), want %v", c.n, got, err, c.limit)
		}
		if !c.limit && !errors.Is(err, ErrWrongPassphrase) {
			t.Errorf("%d lockers: err = %v, want a wrong passphrase", c.n, err)
		}
	}
	lim := mk(3 * 2 * iter)
	lim.Budget = kdfbudget.Unlimited()
	if _, err := OpenFromLimited(lockerImage(t, 10, iter), []byte("x"), lim); errors.Is(err, ErrLimit) {
		t.Fatalf("an Unlimited budget refused: %v", err)
	}
}

func TestBudgetBoundsTheAppleShapeTotal(t *testing.T) {
	pass := []byte("known")
	img, _, _ := appleShapeImageN(t, pass, 100, 32, 5)
	lim := Limits{MaxPBKDF2Iterations: 100, MaxLockers: 100,
		Budget: &kdfbudget.Budget{MaxMemory: 1 << 30, MaxThreads: 255, MaxWork: 2 * 100}}
	_, err := UnlockVolumeKey(bytes.NewReader(img), pass, lim)
	// The passphrase opens the first KEKBLOB, within the budget.
	if err != nil {
		t.Fatalf("first KEKBLOB: %v", err)
	}
	// A wrong passphrase tries them all and runs out after the first.
	lim.Budget = &kdfbudget.Budget{MaxMemory: 1 << 30, MaxThreads: 255, MaxWork: 2 * 100}
	_, err = UnlockVolumeKey(bytes.NewReader(img), []byte("wrong"), lim)
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("5 KEKBLOBs, room for one: err = %v, want ErrLimit", err)
	}
}
