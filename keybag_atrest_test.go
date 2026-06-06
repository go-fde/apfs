package apfs

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// TestKeybagAtRest_RoundTrip validates that a freshly-built keybag
// block round-trips through encryptKeybagAtRest → decryptKeybagAtRest
// and ends up byte-identical to the input.
func TestKeybagAtRest_RoundTrip(t *testing.T) {
	var uuid [16]byte
	if _, err := rand.Read(uuid[:]); err != nil {
		t.Fatal(err)
	}
	plain := packKeybagBlock([]rawEntry{
		{tag: kbTagVolumeKey, data: bytes.Repeat([]byte{0x42}, 40)},
	})
	const paddr = 104
	key := containerKeybagKey(uuid)

	cipher, err := encryptKeybagAtRest(plain, key, paddr)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Equal(cipher, plain) {
		t.Fatal("ciphertext equals plaintext — encryption is a no-op")
	}
	got, err := decryptKeybagAtRest(cipher, key, paddr)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip mismatch:\nwant=%s\ngot =%s",
			hex.EncodeToString(plain[:64]),
			hex.EncodeToString(got[:64]))
	}
}

// TestKeybagAtRest_PaddrAffectsCiphertext ensures the at-rest cipher is
// keyed on paddr — encrypting the same plaintext at a different paddr
// must produce different ciphertext, otherwise relocating a keybag
// would silently work and Apple's tweak design would be defeated.
func TestKeybagAtRest_PaddrAffectsCiphertext(t *testing.T) {
	var uuid [16]byte
	rand.Read(uuid[:])
	key := containerKeybagKey(uuid)
	plain := packKeybagBlock([]rawEntry{{tag: kbTagVolumeKey, data: make([]byte, 32)}})

	c1, _ := encryptKeybagAtRest(plain, key, 104)
	c2, _ := encryptKeybagAtRest(plain, key, 105)
	if bytes.Equal(c1, c2) {
		t.Fatal("ciphertext at paddr=104 == ciphertext at paddr=105 (XTS tweak ignored)")
	}
}

// TestKeybagAtRest_VolumeKeybagKey verifies the volume-keybag path uses
// the volume UUID concatenated with itself (NOT the VEK — that would
// be circular, since the volume keybag is what holds the wrapped VEK).
// apfs-fuse's KeyManager::LoadKeybag passes the volume UUID directly
// into the same `uuid || uuid` recipe used for the container keybag.
func TestKeybagAtRest_VolumeKeybagKey(t *testing.T) {
	var volUUID [16]byte
	rand.Read(volUUID[:])
	plain := packKeybagBlock([]rawEntry{
		{tag: kbTagVolumePassphrase, data: bytes.Repeat([]byte{0xAB}, 56)},
	})
	const paddr = 102

	cipher, err := EncryptVolumeKeybag(plain, volUUID, paddr)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := DecryptVolumeKeybag(cipher, volUUID, paddr)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("volume-keybag round-trip failed")
	}

	// Cross-check: encrypting with the same UUID via the generic
	// helper must produce identical ciphertext (i.e. volumeKeybagKey
	// and keybagXTSKey aren't drifting).
	cipher2, err := encryptKeybagAtRest(plain, keybagXTSKey(volUUID), paddr)
	if err != nil {
		t.Fatalf("encrypt via keybagXTSKey: %v", err)
	}
	if !bytes.Equal(cipher, cipher2) {
		t.Fatal("volumeKeybagKey and keybagXTSKey produce different ciphertext")
	}
}

// TestKeybagAtRest_RejectsBadInput exercises the input validation paths.
func TestKeybagAtRest_RejectsBadInput(t *testing.T) {
	key := make([]byte, 32)
	if _, err := encryptKeybagAtRest(make([]byte, 100), key, 0); err == nil {
		t.Fatal("expected error for non-block-multiple input")
	}
	if _, err := encryptKeybagAtRest(make([]byte, nxBlockSize), make([]byte, 7), 0); err == nil {
		t.Fatal("expected error for bad key length")
	}
}

// TestKeybagAtRest_DecryptedBytesAreParseable decrypts an encrypted
// keybag and confirms the resulting plaintext is recognisable by our
// parseKeybag — i.e. the obj_phys.type byte stays at the right offset
// after the round trip.
func TestKeybagAtRest_DecryptedBytesAreParseable(t *testing.T) {
	var uuid [16]byte
	rand.Read(uuid[:])
	plain := packKeybagBlock([]rawEntry{
		{tag: kbTagVolumeKey, data: bytes.Repeat([]byte{0x33}, 40)},
		{tag: kbTagVolumePassphrase, data: bytes.Repeat([]byte{0x55}, 80)},
	})
	cipher, err := encryptKeybagAtRest(plain, containerKeybagKey(uuid), 104)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	dec, err := decryptKeybagAtRest(cipher, containerKeybagKey(uuid), 104)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	entries, err := parseKeybag(dec)
	if err != nil {
		t.Fatalf("parseKeybag(decrypted): %v\n%s", err, hex.Dump(dec[:64]))
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].tag != kbTagVolumeKey || entries[1].tag != kbTagVolumePassphrase {
		t.Fatalf("entry tags=%d,%d, want %d,%d",
			entries[0].tag, entries[1].tag, kbTagVolumeKey, kbTagVolumePassphrase)
	}
	// Sanity: nbytes inside the decrypted kb_locker matches the entry-area length.
	got := binary.LittleEndian.Uint32(dec[36:40])
	if got == 0 || got > nxBlockSize-keybagEntryAreaStart {
		t.Fatalf("kb_locker.nbytes=%d out of range", got)
	}
}
