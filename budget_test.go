package apfs

import (
	"bytes"
	"errors"
	"testing"
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

// Every locker at the per-locker limit used to be derived: 1022 of them took
// 888 times as long as one (issue #35).
func TestLockerCountMultipliesTheKDFLimit(t *testing.T) {
	lim := Limits{MaxPBKDF2Iterations: 2000, MaxArgon2Time: 1, MaxArgon2MemoryKiB: 8}
	_, err := OpenFromLimited(lockerImage(t, 1022, 2000), []byte("x"), lim)
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("1022 lockers at the per-locker limit: err = %v, want ErrLimit", err)
	}
	if errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("a refusal must not read as a wrong passphrase: %v", err)
	}
}

func TestLockerCountIsBoundedUnderDefaultLimits(t *testing.T) {
	// Cheap lockers: the count alone is over the bound.
	_, err := OpenFrom(lockerImage(t, 200, 1), []byte("x"))
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("200 lockers: err = %v, want ErrLimit", err)
	}
}

func TestLockerBudgetEdges(t *testing.T) {
	const iter = 100
	base := Limits{MaxPBKDF2Iterations: iter, MaxArgon2Time: 1, MaxArgon2MemoryKiB: 8}
	cases := []struct {
		name  string
		n     int
		lim   func(Limits) Limits
		limit bool
	}{
		// Default total is 4 x the per-locker limit: 4 lockers pass, 5 do not.
		{"default total, at the edge", 4, nil, false},
		{"default total, one over", 5, nil, true},
		{"explicit total, at the edge", 7, func(l Limits) Limits { l.MaxTotalPBKDF2Iterations = 7 * iter; return l }, false},
		{"explicit total, one over", 8, func(l Limits) Limits { l.MaxTotalPBKDF2Iterations = 7 * iter; return l }, true},
		{"count, at the edge", 3, func(l Limits) Limits { l.MaxLockers = 3; l.MaxTotalPBKDF2Iterations = 1 << 40; return l }, false},
		{"count, one over", 4, func(l Limits) Limits { l.MaxLockers = 3; l.MaxTotalPBKDF2Iterations = 1 << 40; return l }, true},
		{"default count, 16 cheap lockers", 16, func(l Limits) Limits { l.MaxTotalPBKDF2Iterations = 1 << 40; return l }, false},
		{"default count, 17 cheap lockers", 17, func(l Limits) Limits { l.MaxTotalPBKDF2Iterations = 1 << 40; return l }, true},
	}
	for _, c := range cases {
		lim := base
		if c.lim != nil {
			lim = c.lim(lim)
		}
		_, err := OpenFromLimited(lockerImage(t, c.n, iter), []byte("x"), lim)
		if got := errors.Is(err, ErrLimit); got != c.limit {
			t.Errorf("%s: ErrLimit = %v (err = %v), want %v", c.name, got, err, c.limit)
		}
		if !c.limit && !errors.Is(err, ErrWrongPassphrase) {
			t.Errorf("%s: err = %v, want a wrong passphrase", c.name, err)
		}
	}
}

// A locker over the per-locker bound is refused without a derivation, so it
// adds nothing to the total: it must not make the keybag exceed the budget.
func TestLockerBudgetCountsOnlyWhatWouldRun(t *testing.T) {
	lim := Limits{MaxPBKDF2Iterations: 100, MaxArgon2Time: 1, MaxArgon2MemoryKiB: 8, MaxTotalPBKDF2Iterations: 100}
	over := encodePBKDF2Locker(1<<30, nil, make([]byte, 24))
	one := encodePBKDF2Locker(100, nil, make([]byte, 24))
	rw := hostileLegacyImage(t, 1, []rawEntry{
		{tag: kbTagVolumePassphrase, data: over},
		{tag: kbTagVolumePassphrase, data: over},
		{tag: kbTagVolumePassphrase, data: one},
		{tag: kbTagVolumeKey, data: make([]byte, 24)},
	})
	_, err := OpenFromLimited(rw, []byte("x"), lim)
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("err = %v, want the per-locker ErrLimit", err)
	}
	if bytes.Contains([]byte(err.Error()), []byte("across the keybag")) {
		t.Fatalf("the total was charged for refused lockers: %v", err)
	}
}

func TestArgon2LockerBudget(t *testing.T) {
	lim := Limits{MaxPBKDF2Iterations: 1, MaxArgon2Time: 1, MaxArgon2MemoryKiB: 16}
	locker := encodeArgon2idLocker(1, 16, 1, make([]byte, 16), make([]byte, 40))
	build := func(n int) *memRW {
		var entries []rawEntry
		for range n {
			entries = append(entries, rawEntry{tag: kbTagVolumePassphrase, data: locker})
		}
		entries = append(entries, rawEntry{tag: kbTagVolumeKey, data: make([]byte, 24)})
		return hostileLegacyImage(t, 1, entries)
	}
	// Total default: 4 x (1 pass x 16 KiB).
	if _, err := OpenFromLimited(build(4), []byte("x"), lim); errors.Is(err, ErrLimit) {
		t.Fatalf("4 Argon2 lockers refused at the edge: %v", err)
	}
	_, err := OpenFromLimited(build(5), []byte("x"), lim)
	if !errors.Is(err, ErrLimit) || !bytes.Contains([]byte(err.Error()), []byte("Argon2 across")) {
		t.Fatalf("5 Argon2 lockers: err = %v, want the Argon2 total ErrLimit", err)
	}
	lim.MaxTotalArgon2Work = 5 * 16
	if _, err := OpenFromLimited(build(5), []byte("x"), lim); errors.Is(err, ErrLimit) {
		t.Fatalf("explicit total of 5 lockers refused: %v", err)
	}
}

func TestAppleShapeLockerBudget(t *testing.T) {
	pass := []byte("known")
	lim := Limits{MaxPBKDF2Iterations: 1000, MaxArgon2Time: 1, MaxArgon2MemoryKiB: 8}
	// Default total: 4 x 1000 iterations.
	img, _, _ := appleShapeImageN(t, pass, 1000, 32, 4)
	if _, err := UnlockVolumeKey(bytes.NewReader(img), pass, lim); err != nil {
		t.Fatalf("4 KEKBLOBs at the edge: %v", err)
	}
	img, _, _ = appleShapeImageN(t, pass, 1000, 32, 5)
	_, err := UnlockVolumeKey(bytes.NewReader(img), pass, lim)
	if !errors.Is(err, ErrLimit) || errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("5 KEKBLOBs: err = %v, want ErrLimit", err)
	}
	// The count alone: 17 cheap KEKBLOBs.
	img, _, _ = appleShapeImageN(t, pass, 1, 32, 17)
	_, err = UnlockVolumeKey(bytes.NewReader(img), pass, Limits{MaxPBKDF2Iterations: 1 << 20, MaxTotalPBKDF2Iterations: 1 << 40})
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("17 KEKBLOBs: err = %v, want ErrLimit", err)
	}
}

func TestLimitsZeroTotalsMeanDefaults(t *testing.T) {
	l := Limits{MaxPBKDF2Iterations: 10, MaxArgon2Time: 3, MaxArgon2MemoryKiB: 5}
	if l.maxLockers() != 16 || l.maxTotalPBKDF2() != 40 || l.maxTotalArgon2() != 60 {
		t.Fatalf("defaults = %d, %d, %d", l.maxLockers(), l.maxTotalPBKDF2(), l.maxTotalArgon2())
	}
	l.MaxLockers, l.MaxTotalPBKDF2Iterations, l.MaxTotalArgon2Work = 2, 7, 9
	if l.maxLockers() != 2 || l.maxTotalPBKDF2() != 7 || l.maxTotalArgon2() != 9 {
		t.Fatalf("explicit = %d, %d, %d", l.maxLockers(), l.maxTotalPBKDF2(), l.maxTotalArgon2())
	}
	if mulSat(1<<63, 4) != ^uint64(0) || mulSat(0, 5) != 0 || mulSat(6, 7) != 42 {
		t.Fatal("mulSat")
	}
	if satAdd(^uint64(0), 1) != ^uint64(0) || satAdd(2, 3) != 5 {
		t.Fatal("satAdd")
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
