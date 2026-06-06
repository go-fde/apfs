package apfs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestAESKeyWrap_Public_RoundTrip covers the public AESKeyWrap /
// AESKeyUnwrap aliases (the internals already have round-trip tests).
func TestAESKeyWrap_Public_RoundTrip(t *testing.T) {
	kek := bytes.Repeat([]byte{0x11}, 32)
	plain := bytes.Repeat([]byte{0x22}, 32)
	wrapped, err := AESKeyWrap(kek, plain)
	if err != nil {
		t.Fatalf("AESKeyWrap: %v", err)
	}
	got, err := AESKeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("AESKeyUnwrap: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip mismatch")
	}
}

// TestEncryptVolumeBlock_RoundTrip covers EncryptVolumeBlock and
// DecryptVolumeBlock — these are public XTS wrappers around the
// internal keybag-at-rest layer.
func TestEncryptVolumeBlock_RoundTrip(t *testing.T) {
	vek := bytes.Repeat([]byte{0xA5}, 32)
	plain := bytes.Repeat([]byte{0x5A}, nxBlockSize)
	const paddr uint64 = 42
	ct, err := EncryptVolumeBlock(plain, vek, paddr)
	if err != nil {
		t.Fatalf("EncryptVolumeBlock: %v", err)
	}
	if bytes.Equal(ct, plain) {
		t.Fatal("ciphertext equals plaintext")
	}
	pt, err := DecryptVolumeBlock(ct, vek, paddr)
	if err != nil {
		t.Fatalf("DecryptVolumeBlock: %v", err)
	}
	if !bytes.Equal(pt, plain) {
		t.Fatal("round-trip mismatch")
	}
}

// TestPackKeybagBlock covers the exported PackKeybagBlock helper.
func TestPackKeybagBlock(t *testing.T) {
	entry := KeybagEntry{
		UUID: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Tag:  KBTagVolumeKey,
		Data: []byte("vekblob bytes"),
	}
	block := PackKeybagBlock([]KeybagEntry{entry})
	if len(block) != nxBlockSize {
		t.Fatalf("PackKeybagBlock: len=%d, want %d", len(block), nxBlockSize)
	}
}

// TestParseKEKBlob_RoundTrip exercises BuildKEKBlob → ParseKEKBlob and
// therefore drives ParseKEKBlob, skipDERSeqHeader, decodeDERLen,
// skipDERVersionField, and skipDERField.
func TestParseKEKBlob_RoundTrip(t *testing.T) {
	uuid := [16]byte{0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
		0x11, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	wrappedKEK := bytes.Repeat([]byte{0x77}, 40)
	hmacSalt := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	pbkdf2Salt := bytes.Repeat([]byte{0x55}, 16)

	der, err := BuildKEKBlob(uuid, 0, wrappedKEK, 200000, pbkdf2Salt, hmacSalt)
	if err != nil {
		t.Fatalf("BuildKEKBlob: %v", err)
	}
	parsed, err := ParseKEKBlob(der)
	if err != nil {
		t.Fatalf("ParseKEKBlob: %v", err)
	}
	if parsed.UUID != uuid {
		t.Errorf("UUID mismatch: got %x, want %x", parsed.UUID, uuid)
	}
	if !bytes.Equal(parsed.WrappedKey, wrappedKEK) {
		t.Errorf("WrappedKey mismatch")
	}
	if parsed.Iterations != 200000 {
		t.Errorf("Iterations: got %d, want 200000", parsed.Iterations)
	}
	if !bytes.Equal(parsed.PBKDF2Salt, pbkdf2Salt) {
		t.Errorf("PBKDF2Salt mismatch")
	}
}

// TestParseVEKBlob_RoundTrip exercises BuildVEKBlob → ParseVEKBlob.
func TestParseVEKBlob_RoundTrip(t *testing.T) {
	uuid := [16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00}
	salt := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x12, 0x34}
	wrappedVEK := bytes.Repeat([]byte{0x42}, 40)
	der, err := BuildVEKBlob(uuid, 0x100_3995, wrappedVEK, salt)
	if err != nil {
		t.Fatalf("BuildVEKBlob: %v", err)
	}
	parsed, err := ParseVEKBlob(der)
	if err != nil {
		t.Fatalf("ParseVEKBlob: %v", err)
	}
	if parsed.UUID != uuid {
		t.Errorf("UUID mismatch")
	}
	if !bytes.Equal(parsed.WrappedKey, wrappedVEK) {
		t.Errorf("WrappedKey mismatch")
	}
}

// TestParseVEKBlob_BadOuter pins the early-exit error branch.
func TestParseVEKBlob_BadOuter(t *testing.T) {
	if _, err := ParseVEKBlob([]byte{0x01, 0x02}); err == nil {
		t.Fatal("expected error for too-short input")
	}
	if _, err := ParseVEKBlob([]byte{0x31, 0x00, 0x00, 0x00}); err == nil {
		t.Fatal("expected error for bad outer tag")
	}
}

// TestParseKEKBlob_BadOuter pins the early-exit error branch.
func TestParseKEKBlob_BadOuter(t *testing.T) {
	if _, err := ParseKEKBlob([]byte{0x01}); err == nil {
		t.Fatal("expected error for too-short input")
	}
	if _, err := ParseKEKBlob([]byte{0x31, 0x00, 0x00, 0x00}); err == nil {
		t.Fatal("expected error for bad outer tag")
	}
}

// TestFormatArgon2id covers the path-based file wrapper (formatPath +
// FormatArgon2id). We use minimal Argon2id parameters to keep it fast.
func TestFormatArgon2id(t *testing.T) {
	path := filepath.Join(t.TempDir(), "argon.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	pass := []byte("argon2id format passphrase")
	dev, err := FormatArgon2id(path, pass, Argon2idParams{TimeCost: 1, MemoryKiB: 8 * 1024, Parallelism: 1})
	if err != nil {
		t.Fatalf("FormatArgon2id: %v", err)
	}
	if err := dev.Close(); err != nil {
		t.Fatal(err)
	}
	// Re-open via Open() (the file-based path) to round-trip.
	dev2, err := Open(path, pass)
	if err != nil {
		t.Fatalf("Open after FormatArgon2id: %v", err)
	}
	dev2.Close()
}

// TestFormatArgon2id_OpenError covers the formatPath error path
// (file does not exist).
func TestFormatArgon2id_OpenError(t *testing.T) {
	if _, err := FormatArgon2id(filepath.Join(t.TempDir(), "nope/none"), []byte("x"), Argon2idParams{TimeCost: 1, MemoryKiB: 8 * 1024, Parallelism: 1}); err == nil {
		t.Fatal("expected error for unopenable path")
	}
}

// TestArgon2idParams_ResolveZeros covers the default-fill branches in
// Argon2idParams.resolve when callers leave fields as zero.
func TestArgon2idParams_ResolveZeros(t *testing.T) {
	t1, m1, p1 := (Argon2idParams{}).resolve()
	if t1 == 0 || m1 == 0 || p1 == 0 {
		t.Fatalf("resolve(zero): expected defaults, got t=%d m=%d p=%d", t1, m1, p1)
	}
}

// TestApfsRandBytes_PanicsOnRngFailure covers the panic branch in
// apfsRandBytes via fault injection on apfsRandReadFn.
func TestApfsRandBytes_PanicsOnRngFailure(t *testing.T) {
	prev := apfsRandReadFn
	apfsRandReadFn = func(b []byte) (int, error) {
		return 0, &fakeRNGError{}
	}
	defer func() { apfsRandReadFn = prev }()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	_ = apfsRandBytes(16)
}

type fakeRNGError struct{}

func (*fakeRNGError) Error() string { return "synthetic rng failure" }

