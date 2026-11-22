package apfs

import (
	"errors"
	"testing"
)

func TestArgon2ThreadsCap(t *testing.T) {
	base := Limits{MaxArgon2Time: 1, MaxArgon2MemoryKiB: 1 << 20}
	if DefaultMaxArgon2Threads != 4 || DefaultLimits.MaxArgon2MemoryKiB != 4<<20 {
		t.Fatalf("defaults moved: %d threads, %d KiB", DefaultMaxArgon2Threads, DefaultLimits.MaxArgon2MemoryKiB)
	}
	cases := []struct {
		name    string
		max     uint16
		threads uint64
		refused bool
	}{
		{"default allows 4", 0, 4, false},
		{"default refuses 5", 0, 5, true},
		{"default refuses 255", 0, 255, true},
		{"zero threads", 0, 0, true},
		{"explicit 8 allows 8", 8, 8, false},
		{"explicit 8 refuses 9", 8, 9, true},
		{"explicit 255 allows 255", 255, 255, false},
		{"above 255 clamps: 255 allowed", 1000, 255, false},
		{"above 255 clamps: 256 refused", 1000, 256, true},
	}
	for _, c := range cases {
		lim := base
		lim.MaxArgon2Threads = c.max
		err := lim.argon2(1, 8*max(c.threads, 1)+8, c.threads)
		if got := errors.Is(err, ErrLimit); got != c.refused {
			t.Errorf("%s: err = %v, refused = %v", c.name, err, got)
		}
	}
}

// A hostile locker asking for 5 threads is refused under DefaultLimits, with
// ErrLimit and no derivation, and allowed once the caller raises the cap.
func TestHostileArgon2ThreadsRefused(t *testing.T) {
	locker := encodeArgon2idLocker(1, 64, 5, make([]byte, 16), make([]byte, 40))
	img := func() *memRW {
		return hostileLegacyImage(t, 1, []rawEntry{
			{tag: kbTagVolumePassphrase, data: locker},
			{tag: kbTagVolumeKey, data: make([]byte, 24)},
		})
	}
	_, err := OpenFrom(img(), []byte("x"))
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("5 threads under DefaultLimits: err = %v, want ErrLimit", err)
	}
	lim := DefaultLimits
	lim.MaxArgon2Threads = 5
	_, err = OpenFromLimited(img(), []byte("x"), lim)
	if errors.Is(err, ErrLimit) || !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("5 threads with MaxArgon2Threads = 5: err = %v, want a wrong passphrase", err)
	}
}

// Parameters this package would refuse on opening are refused on writing, and
// a parallelism of 256 no longer reaches argon2's uint8.
func TestArgon2idFormatRefusesWhatOpenWouldRefuse(t *testing.T) {
	for _, p := range []Argon2idParams{
		{TimeCost: 1, MemoryKiB: 1024, Parallelism: 5},
		{TimeCost: 1, MemoryKiB: 1 << 20, Parallelism: 256},
		{TimeCost: 1, MemoryKiB: 1 << 20, Parallelism: 65535},
		{TimeCost: 1001, MemoryKiB: 1024, Parallelism: 1},
		{TimeCost: 1, MemoryKiB: 4, Parallelism: 1},
	} {
		rw := newMemRW(1 << 20)
		if dev, err := FormatArgon2idOn(rw, []byte("pw"), p); !errors.Is(err, ErrLimit) || dev != nil {
			t.Errorf("FormatArgon2idOn(%+v) = %v, %v, want ErrLimit", p, dev, err)
		}
		if !allZero(rw.buf) {
			t.Errorf("FormatArgon2idOn(%+v) wrote to the device before refusing", p)
		}
	}
	rw := newMemRW(1 << 20)
	dev, err := FormatOn(rw, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	_ = dev
	before := append([]byte(nil), rw.buf...)
	err = AddArgon2idPassphrase(rw, []byte("pw"), []byte("pw2"), Argon2idParams{TimeCost: 1, MemoryKiB: 1024, Parallelism: 5})
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("AddArgon2idPassphrase with 5 threads: err = %v, want ErrLimit", err)
	}
	if string(before) != string(rw.buf) {
		t.Fatal("the keybag was rewritten")
	}
	// The defaults (2 threads) and the cap itself (4) are written and read back.
	for _, par := range []uint16{0, 4} {
		rw := newMemRW(1 << 20)
		if _, err := FormatArgon2idOn(rw, []byte("pw"), Argon2idParams{TimeCost: 1, MemoryKiB: 1024, Parallelism: par}); err != nil {
			t.Fatalf("parallelism %d: %v", par, err)
		}
		if _, err := OpenFrom(rw, []byte("pw")); err != nil {
			t.Fatalf("parallelism %d does not open: %v", par, err)
		}
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
