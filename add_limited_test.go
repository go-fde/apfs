package apfs

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-encryptions/kdfbudget"
)

func formatted(t *testing.T, pass []byte) (string, *os.File) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "c.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	dev, err := Format(path, pass)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	dev.Close()
	rw, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rw.Close() })
	return path, rw
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// Every rewrite function refuses a keybag of 200 lockers with ErrLimit and
// leaves the image alone (issue #35).
func TestAddLimitedRefusesHostileKeybag(t *testing.T) {
	priv := rsaKey(t)
	adds := map[string]func(rw blockRW) error{
		"AddRecoveryKeyLimited": func(rw blockRW) error {
			return AddRecoveryKeyLimited(rw, []byte("x"), []byte("r"), DefaultLimits)
		},
		"AddPassphraseLimited": func(rw blockRW) error {
			return AddPassphraseLimited(rw, []byte("x"), []byte("n"), DefaultLimits)
		},
		"AddArgon2idPassphraseLimited": func(rw blockRW) error {
			return AddArgon2idPassphraseLimited(rw, []byte("x"), []byte("n"), Argon2idParams{}, DefaultLimits)
		},
		"AddInstitutionalKeyLimited": func(rw blockRW) error {
			return AddInstitutionalKeyLimited(rw, []byte("x"), &priv.PublicKey, DefaultLimits)
		},
	}
	for name, add := range adds {
		rw := lockerImage(t, 200, 1)
		before := append([]byte(nil), rw.buf...)
		if err := add(rw); !errors.Is(err, ErrLimit) || errors.Is(err, ErrWrongPassphrase) {
			t.Errorf("%s: err = %v, want ErrLimit", name, err)
		}
		if !bytes.Equal(before, rw.buf) {
			t.Errorf("%s: the image was modified", name)
		}
	}
}

// A normal container takes each Limited variant and the new locker opens it.
func TestAddLimitedAcceptsNormalContainer(t *testing.T) {
	pass := []byte("primary")
	path, rw := formatted(t, pass)
	lim := Limits{MaxPBKDF2Iterations: 1 << 26, MaxArgon2Time: 10, MaxArgon2MemoryKiB: 1 << 16}
	small := Argon2idParams{TimeCost: 1, MemoryKiB: 64, Parallelism: 1}
	if err := AddPassphraseLimited(rw, pass, []byte("second"), lim); err != nil {
		t.Fatalf("AddPassphraseLimited: %v", err)
	}
	if err := AddRecoveryKeyLimited(rw, pass, []byte("recovery"), lim); err != nil {
		t.Fatalf("AddRecoveryKeyLimited: %v", err)
	}
	if err := AddArgon2idPassphraseLimited(rw, pass, []byte("third"), small, lim); err != nil {
		t.Fatalf("AddArgon2idPassphraseLimited: %v", err)
	}
	priv := rsaKey(t)
	if err := AddInstitutionalKeyLimited(rw, pass, &priv.PublicKey, lim); err != nil {
		t.Fatalf("AddInstitutionalKeyLimited: %v", err)
	}
	for _, p := range []string{"primary", "second", "recovery", "third"} {
		d, err := OpenLimited(path, []byte(p), lim)
		if err != nil {
			t.Fatalf("OpenLimited(%q): %v", p, err)
		}
		d.Close()
	}
	d, err := OpenFromWithPrivateKey(rw, priv)
	if err != nil {
		t.Fatalf("OpenFromWithPrivateKey: %v", err)
	}
	d.Close()
}

// The new locker's own derivation is charged: a spent Budget, or Argon2
// parameters the Budget refuses, derive nothing and write nothing.
func TestAddLimitedChargesTheNewLocker(t *testing.T) {
	pass := []byte("primary")
	_, rw := formatted(t, pass)
	before, err := os.ReadFile(rw.Name())
	if err != nil {
		t.Fatal(err)
	}
	spent := kdfbudget.Default()
	for range 128 {
		if err := spent.ChargeArgon2(4<<20, 1, 1); err != nil {
			t.Fatal(err)
		}
	}
	err = AddPassphraseLimited(rw, pass, []byte("n"), Limits{MaxPBKDF2Iterations: 1 << 26, Budget: spent})
	if !errors.Is(err, ErrLimit) {
		t.Errorf("spent budget: err = %v, want ErrLimit", err)
	}
	err = AddArgon2idPassphraseLimited(rw, pass, []byte("n"),
		Argon2idParams{TimeCost: 1, MemoryKiB: 1 << 16, Parallelism: 256},
		Limits{MaxPBKDF2Iterations: 1 << 26, Budget: kdfbudget.Unlimited()})
	if !errors.Is(err, ErrLimit) {
		t.Errorf("256 threads: err = %v, want ErrLimit", err)
	}
	after, err := os.ReadFile(rw.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("the image was modified")
	}
}

// The new locker's derivation is charged on its own, after the existing
// locker's: a Budget with room for the unlock but not for the wrap refuses.
func TestAddLimitedChargesTheWrapAfterTheUnlock(t *testing.T) {
	const total = 1 << 32 // kdfbudget.Default()
	probe := kdfbudget.Default()
	if err := probe.ChargePBKDF2(kdfbudget.CostSHA256, formatIterations); err != nil {
		t.Fatal(err)
	}
	r := probe.Spent() // one PBKDF2 run of a formatted container's locker
	room := func(left uint64) Limits {
		b := kdfbudget.Default()
		if err := b.ChargeCompressions(1, total-left); err != nil {
			t.Fatal(err)
		}
		if b.Spent() != total-left {
			t.Fatalf("Spent = %d, want %d: the default total moved", b.Spent(), total-left)
		}
		return Limits{MaxPBKDF2Iterations: 1 << 26, MaxArgon2Time: 10, MaxArgon2MemoryKiB: 1 << 16, Budget: b}
	}
	pass := []byte("primary")
	small := Argon2idParams{TimeCost: 1, MemoryKiB: 64, Parallelism: 1}
	adds := map[string]func(rw blockRW, lim Limits) error{
		"PBKDF2": func(rw blockRW, lim Limits) error { return AddPassphraseLimited(rw, pass, []byte("n"), lim) },
		"Argon2": func(rw blockRW, lim Limits) error {
			return AddArgon2idPassphraseLimited(rw, pass, []byte("n"), small, lim)
		},
	}
	for name, add := range adds {
		_, rw := formatted(t, pass)
		before, err := os.ReadFile(rw.Name())
		if err != nil {
			t.Fatal(err)
		}
		if err := add(rw, room(r)); !errors.Is(err, ErrLimit) {
			t.Errorf("%s with room for the unlock only: err = %v, want ErrLimit", name, err)
		}
		after, _ := os.ReadFile(rw.Name())
		if !bytes.Equal(before, after) {
			t.Errorf("%s: the image was modified", name)
		}
	}
	_, rw := formatted(t, pass)
	if err := AddPassphraseLimited(rw, pass, []byte("n"), room(2*r)); err != nil {
		t.Errorf("room for exactly both runs: %v", err)
	}
	_, rw = formatted(t, pass)
	if err := AddPassphraseLimited(rw, pass, []byte("n"), room(2*r-1)); !errors.Is(err, ErrLimit) {
		t.Errorf("one unit short of both runs: err = %v, want ErrLimit", err)
	}
}

// A keybag of entries carrying the key's fingerprint costs one RSA operation.
func TestOpenFromWithPrivateKeyStopsAtTheFirstMatch(t *testing.T) {
	priv := rsaKey(t)
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	fp := sha256.Sum256(der)
	entry := rawEntry{tag: kbTagInstitutionalKey, data: append(fp[:], make([]byte, 256)...)}
	entries := []rawEntry{{tag: kbTagVolumeKey, data: make([]byte, 24)}}
	for range 20 {
		entries = append(entries, entry)
	}
	// The first matching entry fails to decrypt and ends the unlock: one RSA
	// operation, not twenty.
	_, err = OpenFromWithPrivateKey(hostileLegacyImage(t, 16, entries), priv)
	if err == nil || errors.Is(err, ErrLimit) {
		t.Fatalf("20 matching entries: err = %v, want a decrypt failure", err)
	}
}
