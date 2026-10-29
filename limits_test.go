package apfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// imageWithLocker is a legacy-shape container whose only passphrase locker
// is locker, as an attacker would write it.
func imageWithLocker(locker []byte) *memRW {
	kb := make([]byte, nxBlockSize)
	off := writeKeybagHeader(kb, 0, 2)
	off = writeKeybagEntry(kb, off, kbTagVolumePassphrase, locker)
	writeKeybagEntry(kb, off, kbTagVolumeKey, mustRand(40))
	m := newMemRW(4 * nxBlockSize)
	copy(m.buf, buildNXSuperblock(nxBlockSize, 1, 1))
	copy(m.buf[nxBlockSize:], kb)
	return m
}

func argon2Locker(timeCost, memKiB uint32, threads uint16, wrapped []byte) []byte {
	salt := mustRand(16)
	b := make([]byte, 16+len(salt)+len(wrapped))
	binary.LittleEndian.PutUint16(b[0:2], kdfTypeArgon2id)
	binary.LittleEndian.PutUint32(b[4:8], timeCost)
	binary.LittleEndian.PutUint32(b[8:12], memKiB)
	binary.LittleEndian.PutUint16(b[12:14], threads)
	binary.LittleEndian.PutUint16(b[14:16], uint16(len(salt)))
	copy(b[16:], salt)
	copy(b[16+len(salt):], wrapped)
	return b
}

// openQuickly opens rw, failing the test if that takes more than a second
// or panics. Without the limits, every hostile locker below either panics in
// argon2 or runs for minutes to hours.
func openQuickly(t *testing.T, rw blockRW, lim Limits) error {
	t.Helper()
	type result struct {
		err   error
		panic any
	}
	done := make(chan result, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				done <- result{panic: p}
			}
		}()
		_, err := OpenFromLimited(rw, []byte("pass"), lim)
		done <- result{err: err}
	}()
	select {
	case r := <-done:
		if r.panic != nil {
			t.Fatalf("Open panicked: %v", r.panic)
		}
		return r.err
	case <-time.After(time.Second):
		t.Fatal("Open still running after 1s: the keybag's cost was not bounded")
		return nil
	}
}

func TestLimitsRefuseHostileLockers(t *testing.T) {
	kek := mustRand(40)
	cases := []struct {
		name   string
		locker []byte
	}{
		{"pbkdf2 2^31 iterations", buildLockerEntryData(mustRand(16), 1<<31, kek)},
		{"pbkdf2 zero iterations", buildLockerEntryData(mustRand(16), 0, kek)},
		{"pbkdf2 huge wrapped key", buildLockerEntryData(mustRand(16), 1<<31, mustRand(2000))},
		{"argon2 2^31 passes", argon2Locker(1<<31, 64, 1, kek)},
		{"argon2 zero passes", argon2Locker(0, 64, 1, kek)},
		{"argon2 2 TiB", argon2Locker(1, 1<<31, 1, kek)},
		{"argon2 below 8 KiB per thread", argon2Locker(1, 31, 4, kek)},
		{"argon2 256 threads (uint8 0)", argon2Locker(1, 8*256, 256, kek)},
		{"argon2 512 threads (uint8 0)", argon2Locker(1, 8*512, 512, kek)},
		{"argon2 zero threads", argon2Locker(1, 64, 0, kek)},
		{"argon2 huge wrapped key", argon2Locker(1, 64, 1, mustRand(2000))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := openQuickly(t, imageWithLocker(c.locker), DefaultLimits)
			if !errors.Is(err, ErrLimit) {
				t.Fatalf("err = %v, want ErrLimit", err)
			}
		})
	}
}

func TestLimitsAcceptBuiltImages(t *testing.T) {
	img := buildAPFSImage(t, []byte("pass"), []byte("payload"))
	if err := openQuickly(t, &memRW{buf: img}, DefaultLimits); err != nil {
		t.Fatalf("a 1000-iteration image: %v", err)
	}
	tight := Limits{MaxPBKDF2Iterations: 999, MaxArgon2Time: 1, MaxArgon2MemoryKiB: 64}
	if err := openQuickly(t, &memRW{buf: img}, tight); !errors.Is(err, ErrLimit) {
		t.Fatalf("1000 iterations under a 999 limit: err = %v, want ErrLimit", err)
	}

	m := newMemRW(4 * nxBlockSize)
	if _, err := FormatArgon2idOn(m, []byte("pass"), Argon2idParams{TimeCost: 1, MemoryKiB: 64, Parallelism: 1}); err != nil {
		t.Fatal(err)
	}
	if err := openQuickly(t, m, DefaultLimits); err != nil {
		t.Fatalf("an Argon2id image: %v", err)
	}
	if err := openQuickly(t, m, Limits{MaxPBKDF2Iterations: 1, MaxArgon2Time: 1, MaxArgon2MemoryKiB: 32}); !errors.Is(err, ErrLimit) {
		t.Fatalf("64 KiB under a 32 KiB limit: err = %v, want ErrLimit", err)
	}
}

// A wrong passphrase must still say so, not that a limit was hit.
func TestLimitsWrongPassphraseIsNotErrLimit(t *testing.T) {
	img := buildAPFSImage(t, []byte("right"), nil)
	_, err := OpenFrom(&memRW{buf: img}, []byte("wrong"))
	if err == nil || errors.Is(err, ErrLimit) {
		t.Fatalf("err = %v, want a passphrase error", err)
	}
}

func TestLimitsKEKBlob(t *testing.T) {
	var uuid [16]byte
	for _, c := range []struct {
		name    string
		iter    uint32
		wrapped []byte
		refused bool
	}{
		{"macOS-sized", 200000, bytes.Repeat([]byte{7}, 40), false},
		{"2^31 iterations", 1 << 31, bytes.Repeat([]byte{7}, 40), true},
		{"zero iterations", 0, bytes.Repeat([]byte{7}, 40), true},
		{"huge wrapped key", 1000, bytes.Repeat([]byte{7}, 2000), true},
	} {
		der, err := BuildKEKBlob(uuid, 0, c.wrapped, c.iter, mustRand(16), mustRand(8))
		if err != nil {
			t.Fatalf("%s: BuildKEKBlob: %v", c.name, err)
		}
		kb, err := ParseKEKBlob(der)
		if err != nil {
			t.Fatalf("%s: ParseKEKBlob: %v", c.name, err)
		}
		if err := DefaultLimits.kekBlob(kb); errors.Is(err, ErrLimit) != c.refused {
			t.Errorf("%s: err = %v, refused want %v", c.name, err, c.refused)
		}
	}
}

func TestLimitsArgon2MemoryCeiling(t *testing.T) {
	// A caller's limit above the structural 4 GiB does not lift it.
	lim := Limits{MaxArgon2Time: 1, MaxArgon2MemoryKiB: 1<<32 - 1}
	if err := lim.argon2(1, argon2MaxMemoryKiB+1, 1); !errors.Is(err, ErrLimit) {
		t.Fatalf("err = %v, want ErrLimit", err)
	}
}
