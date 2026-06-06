package apfs

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"
)

// memRW is an in-memory blockRW used by the locker round-trip tests so we do
// not depend on a real file path. It grows on writes and supports random
// access. Tests never call Close on it.
type memRW struct {
	buf []byte
}

func newMemRW(size int) *memRW { return &memRW{buf: make([]byte, size)} }

func (m *memRW) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || int(off) >= len(m.buf) {
		return 0, nil
	}
	n := copy(p, m.buf[off:])
	return n, nil
}
func (m *memRW) WriteAt(p []byte, off int64) (int, error) {
	end := int(off) + len(p)
	if end > len(m.buf) {
		next := make([]byte, end)
		copy(next, m.buf)
		m.buf = next
	}
	n := copy(m.buf[int(off):], p)
	return n, nil
}
func (m *memRW) Close() error { return nil }

// TestArgon2id_RoundTrip formats an Argon2id-protected container, writes a
// payload sector, and re-opens with the same passphrase. We use minimal
// Argon2id parameters to keep the test fast.
func TestArgon2id_RoundTrip(t *testing.T) {
	rw := newMemRW(8 * nxBlockSize)
	pass := []byte("argon2id passphrase")
	dev, err := FormatArgon2idOn(rw, pass, Argon2idParams{TimeCost: 1, MemoryKiB: 8 * 1024, Parallelism: 1})
	if err != nil {
		t.Fatalf("FormatArgon2idOn: %v", err)
	}
	want := make([]byte, sectorSize)
	copy(want, []byte("argon2id payload"))
	if _, err := dev.WriteAt(want, int64(2*nxBlockSize)); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if err := dev.Close(); err != nil {
		t.Fatal(err)
	}
	dev2, err := OpenFrom(rw, pass)
	if err != nil {
		t.Fatalf("OpenFrom: %v", err)
	}
	got := make([]byte, sectorSize)
	if _, err := dev2.ReadAt(got, int64(2*nxBlockSize)); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("argon2id roundtrip mismatch")
	}
	if _, err := OpenFrom(rw, []byte("wrong")); err == nil {
		t.Fatal("OpenFrom with wrong passphrase succeeded")
	}
}

// TestPersonalRecoveryKey_RoundTrip formats a passphrase-protected container,
// adds a PRK, and verifies both credentials unlock the container while a
// random string does not.
func TestPersonalRecoveryKey_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prk.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	pass := []byte("primary passphrase")
	prk := []byte("ABCD-EFGH-IJKL-MNOP-QRST-UVWX")

	dev, err := Format(path, pass)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if err := dev.Close(); err != nil {
		t.Fatal(err)
	}

	rw, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := AddRecoveryKey(rw, pass, prk); err != nil {
		rw.Close()
		t.Fatalf("AddRecoveryKey: %v", err)
	}
	rw.Close()

	// Original passphrase still works.
	d1, err := Open(path, pass)
	if err != nil {
		t.Fatalf("Open with passphrase failed after AddRecoveryKey: %v", err)
	}
	d1.Close()
	// Recovery key works.
	d2, err := Open(path, prk)
	if err != nil {
		t.Fatalf("Open with recovery key failed: %v", err)
	}
	d2.Close()
	// Random key fails.
	if _, err := Open(path, []byte("not the recovery key")); err == nil {
		t.Fatal("Open with random key succeeded unexpectedly")
	}

	// Inspect that the new entry carries the well-known recovery UUID.
	rw2, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer rw2.Close()
	sb, err := parseNXSuperblock(rw2)
	if err != nil {
		t.Fatal(err)
	}
	kbData, err := readKeybag(rw2, sb)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := parseKeybag(kbData)
	if err != nil {
		t.Fatal(err)
	}
	var sawRecovery bool
	for _, e := range entries {
		if e.tag == kbTagVolumePassphrase && IsRecoveryKeyUUID(e.uuid) {
			sawRecovery = true
		}
	}
	if !sawRecovery {
		t.Fatal("no PRK entry stamped with recoveryKeyUUID found in keybag")
	}
}

// TestAddArgon2idPassphrase_AddsAdditionalLocker confirms we can mix KDFs in
// the same container.
func TestAddArgon2idPassphrase_AddsAdditionalLocker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mix.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	pass := []byte("first passphrase")
	dev, err := Format(path, pass)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	dev.Close()

	rw, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	pass2 := []byte("argon2id second passphrase")
	if err := AddArgon2idPassphrase(rw, pass, pass2, Argon2idParams{TimeCost: 1, MemoryKiB: 8 * 1024, Parallelism: 1}); err != nil {
		rw.Close()
		t.Fatalf("AddArgon2idPassphrase: %v", err)
	}
	rw.Close()

	for _, p := range [][]byte{pass, pass2} {
		d, err := Open(path, p)
		if err != nil {
			t.Fatalf("Open with credential %q: %v", string(p), err)
		}
		d.Close()
	}
}

// TestInstitutionalRecoveryKey_RoundTrip formats a passphrase-protected
// container, adds an IRK using a fresh RSA-2048 keypair, and verifies the
// matching private key unlocks the container while an unrelated keypair does
// not.
func TestInstitutionalRecoveryKey_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "irk.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	pass := []byte("primary passphrase")
	dev, err := Format(path, pass)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	dev.Close()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	rw, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := AddInstitutionalKey(rw, pass, &priv.PublicKey); err != nil {
		rw.Close()
		t.Fatalf("AddInstitutionalKey: %v", err)
	}
	rw.Close()

	// Passphrase still works.
	d1, err := Open(path, pass)
	if err != nil {
		t.Fatalf("Open with passphrase: %v", err)
	}
	d1.Close()

	// IRK private key works.
	d2, err := OpenWithPrivateKey(path, priv)
	if err != nil {
		t.Fatalf("OpenWithPrivateKey: %v", err)
	}
	d2.Close()

	// Unrelated keypair must NOT unlock.
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey other: %v", err)
	}
	if _, err := OpenWithPrivateKey(path, other); err == nil {
		t.Fatal("OpenWithPrivateKey with unrelated key unexpectedly succeeded")
	}
}

// TestKeybagFull_AppendRefuses confirms the rewrite path refuses to overflow
// the on-disk keybag extent rather than silently truncating data.
func TestKeybagFull_AppendRefuses(t *testing.T) {
	rw := newMemRW(8 * nxBlockSize)
	dev, err := FormatOn(rw, []byte("p"))
	if err != nil {
		t.Fatalf("FormatOn: %v", err)
	}
	dev.Close()

	// Add passphrases until the single-block extent fills up. The exact
	// number depends on entry size, but with PBKDF2 ≈ 90 bytes per locker
	// we will overflow after ~40 additions.
	var firstFailure error
	for i := 0; i < 200; i++ {
		err := AddPassphrase(rw, []byte("p"), []byte("loop"))
		if err != nil {
			firstFailure = err
			break
		}
	}
	if firstFailure == nil {
		t.Fatal("expected eventual keybag-full error, got none")
	}
}
