package apfs

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// failFormatRW is a blockRW that returns a write error after failAfter
// successful WriteAt calls.
type failFormatRW struct {
	failAfter int
	callCount int
}

func (r *failFormatRW) ReadAt(p []byte, off int64) (int, error) { return len(p), nil }
func (r *failFormatRW) WriteAt(p []byte, off int64) (int, error) {
	r.callCount++
	if r.callCount > r.failAfter {
		return 0, errors.New("mock write error")
	}
	return len(p), nil
}
func (r *failFormatRW) Close() error { return nil }

func TestFormat_NotExist(t *testing.T) {
	_, err := Format(filepath.Join(t.TempDir(), "nofile.apfs"), []byte("pass"))
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

// TestFormat_Success creates an APFS FDE container, writes payload data to
// block 2, closes, reopens with Open, and verifies the round-trip.
func TestFormat_Success(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	passphrase := []byte("apfs format test pass")
	dev, err := Format(path, passphrase)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	want := make([]byte, sectorSize)
	copy(want, []byte("hello from apfs format"))
	payloadOff := int64(2 * nxBlockSize)
	if _, err := dev.WriteAt(want, payloadOff); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if err := dev.Close(); err != nil {
		t.Fatal(err)
	}

	dev2, err := Open(path, passphrase)
	if err != nil {
		t.Fatalf("Open after Format: %v", err)
	}
	defer dev2.Close()

	got := make([]byte, sectorSize)
	if _, err := dev2.ReadAt(got, payloadOff); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("roundtrip mismatch: got %q want %q", got[:20], want[:20])
	}
}

// TestFormatOn_Success performs the same round-trip as TestFormat_Success but
// via FormatOn with an in-memory readWriteAt buffer.
func TestFormatOn_Success(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}

	passphrase := []byte("apfs formaton test")
	dev, err := FormatOn(f, passphrase)
	if err != nil {
		f.Close()
		t.Fatalf("FormatOn: %v", err)
	}

	want := make([]byte, sectorSize)
	copy(want, []byte("formaton payload"))
	payloadOff := int64(2 * nxBlockSize)
	if _, err := dev.WriteAt(want, payloadOff); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if err := dev.Close(); err != nil {
		t.Fatal(err)
	}

	dev2, err := Open(path, passphrase)
	if err != nil {
		t.Fatalf("Open after FormatOn: %v", err)
	}
	defer dev2.Close()

	got := make([]byte, sectorSize)
	if _, err := dev2.ReadAt(got, payloadOff); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestFormatOn_SuperblockWriteError(t *testing.T) {
	_, err := FormatOn(&failFormatRW{failAfter: 0}, []byte("pass"))
	if err == nil {
		t.Fatal("expected error when superblock write fails")
	}
}

func TestFormatOn_KeybagWriteError(t *testing.T) {
	_, err := FormatOn(&failFormatRW{failAfter: 1}, []byte("pass"))
	if err == nil {
		t.Fatal("expected error when keybag write fails")
	}
}

func TestAESKeyWrap_RoundTrip(t *testing.T) {
	kek := make([]byte, 32)
	plaintext := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i)
	}
	for i := range plaintext {
		plaintext[i] = byte(i + 32)
	}

	wrapped, err := aesKeyWrap(kek, plaintext)
	if err != nil {
		t.Fatalf("aesKeyWrap: %v", err)
	}
	unwrapped, err := aesKeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("aesKeyUnwrap: %v", err)
	}
	if !bytes.Equal(unwrapped, plaintext) {
		t.Fatal("roundtrip mismatch")
	}
}

func TestAESKeyWrap_NotMultipleOf8(t *testing.T) {
	_, err := aesKeyWrap(make([]byte, 32), make([]byte, 10))
	if err == nil {
		t.Fatal("expected error for non-multiple-of-8 plaintext")
	}
}

func TestAESKeyWrap_BadKEK(t *testing.T) {
	_, err := aesKeyWrap(make([]byte, 7), make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for invalid AES key size")
	}
}
