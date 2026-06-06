package apfs

// keybag_chain_test.go is the integration test for everything we've
// reverse-engineered from Apple's reference DMG: it builds a complete
// container-keybag → volume-keybag → wrapped-KEK → wrapped-VEK chain
// the *same* way Apple's mkfs path does, encrypts both keybags at rest
// with the right XTS keys, and then unwraps the VEK from a passphrase
// by walking the chain in reverse.
//
// If this test ever breaks, it means one of the three layers we
// implemented (at-rest XTS, ASN.1 VEKBLOB/KEKBLOB, AES-KW chain) has
// drifted from the on-the-wire shape Apple's apfs.kext expects, and a
// FormatContainerEncrypted writer using these primitives would produce
// containers Apple cannot mount.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// TestKeybagChain_PassphraseUnlocksVEK builds a fully Apple-shape
// encrypted-container keybag pair (container keybag + volume keybag),
// then walks the structure end-to-end with only the passphrase, the
// container UUID, the volume UUID, and the on-disk paddrs of both
// keybags, recovering the VEK byte-for-byte.
func TestKeybagChain_PassphraseUnlocksVEK(t *testing.T) {
	// ── 1. Generate the per-instance secret material. ────────────────
	var containerUUID, volumeUUID [16]byte
	if _, err := rand.Read(containerUUID[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(volumeUUID[:]); err != nil {
		t.Fatal(err)
	}
	vek := make([]byte, 32)
	kek := make([]byte, 32)
	rand.Read(vek)
	rand.Read(kek)
	pbkdf2Salt := make([]byte, 16)
	rand.Read(pbkdf2Salt)
	vekHMACSalt := make([]byte, 8)
	rand.Read(vekHMACSalt)
	kekHMACSalt := make([]byte, 8)
	rand.Read(kekHMACSalt)
	const iterations = 100_000
	passphrase := []byte("TestKeybagChain-passphrase!")
	const containerKBPaddr uint64 = 104
	const volumeKBPaddr uint64 = 102

	// ── 2. Wrap the keys. ─────────────────────────────────────────────
	derivedKey := pbkdf2.Key(passphrase, pbkdf2Salt, iterations, 32, sha256.New)
	wrappedKEK, err := aesKeyWrap(derivedKey, kek)
	if err != nil {
		t.Fatalf("wrap KEK: %v", err)
	}
	wrappedVEK, err := aesKeyWrap(kek, vek)
	if err != nil {
		t.Fatalf("wrap VEK: %v", err)
	}

	// ── 3. Build the volume keybag (one tag=3 entry: KEKBLOB). ────────
	kekBlob, err := BuildKEKBlob(volumeUUID, 0, wrappedKEK, iterations, pbkdf2Salt, kekHMACSalt)
	if err != nil {
		t.Fatalf("BuildKEKBlob: %v", err)
	}
	volumeKBPlain := packKeybagBlock([]rawEntry{
		{uuid: volumeUUID, tag: kbTagVolumePassphrase, data: kekBlob},
	})
	volumeKBCipher, err := EncryptVolumeKeybag(volumeKBPlain, volumeUUID, volumeKBPaddr)
	if err != nil {
		t.Fatalf("EncryptVolumeKeybag: %v", err)
	}

	// ── 4. Build the container keybag (tag=3 prange + tag=2 VEKBLOB). ─
	prangeData := make([]byte, 16)
	binary.LittleEndian.PutUint64(prangeData[:8], volumeKBPaddr)
	binary.LittleEndian.PutUint64(prangeData[8:], 1)
	vekBlob, err := BuildVEKBlob(volumeUUID, 0, wrappedVEK, vekHMACSalt)
	if err != nil {
		t.Fatalf("BuildVEKBlob: %v", err)
	}
	containerKBPlain := packKeybagBlock([]rawEntry{
		{uuid: volumeUUID, tag: kbTagWrappedKEK /*=3*/, data: prangeData},
		{uuid: volumeUUID, tag: kbTagVolumeKey /*=2*/, data: vekBlob},
	})
	containerKBCipher, err := EncryptContainerKeybag(containerKBPlain, containerUUID, containerKBPaddr)
	if err != nil {
		t.Fatalf("EncryptContainerKeybag: %v", err)
	}

	// ── 5. Now unlock end-to-end as the kext would. ───────────────────
	// 5a. Decrypt container keybag with the container UUID.
	gotContainerKB, err := DecryptContainerKeybag(containerKBCipher, containerUUID, containerKBPaddr)
	if err != nil {
		t.Fatalf("DecryptContainerKeybag: %v", err)
	}
	containerEntries, err := parseKeybag(gotContainerKB)
	if err != nil {
		t.Fatalf("parseKeybag(container): %v", err)
	}
	if len(containerEntries) != 2 {
		t.Fatalf("container keybag entry count = %d, want 2", len(containerEntries))
	}

	// 5b. From the tag=3 entry, locate the volume keybag.
	var foundVolKBPaddr, foundVolKBLen uint64
	var vekBlobBytes []byte
	for _, e := range containerEntries {
		switch e.tag {
		case kbTagWrappedKEK: // tag=3 in the container keybag = volume-unlock-records prange
			if len(e.data) != 16 {
				t.Fatalf("tag=3 data len %d, want 16", len(e.data))
			}
			foundVolKBPaddr = binary.LittleEndian.Uint64(e.data[:8])
			foundVolKBLen = binary.LittleEndian.Uint64(e.data[8:])
		case kbTagVolumeKey: // tag=2 = wrapped VEK (VEKBLOB)
			vekBlobBytes = append([]byte{}, e.data...)
		}
	}
	if foundVolKBPaddr != volumeKBPaddr || foundVolKBLen != 1 {
		t.Fatalf("recovered prange = (%d, %d), want (%d, 1)", foundVolKBPaddr, foundVolKBLen, volumeKBPaddr)
	}
	if vekBlobBytes == nil {
		t.Fatal("no tag=2 (VEKBLOB) entry in container keybag")
	}

	// 5c. Decrypt volume keybag with the volume UUID.
	gotVolumeKB, err := DecryptVolumeKeybag(volumeKBCipher, volumeUUID, volumeKBPaddr)
	if err != nil {
		t.Fatalf("DecryptVolumeKeybag: %v", err)
	}
	volumeEntries, err := parseKeybag(gotVolumeKB)
	if err != nil {
		t.Fatalf("parseKeybag(volume): %v", err)
	}
	if len(volumeEntries) != 1 || volumeEntries[0].tag != kbTagVolumePassphrase {
		t.Fatalf("volume keybag shape unexpected: %+v", volumeEntries)
	}

	// 5d. Parse the KEKBLOB and the VEKBLOB to extract the wrapped
	// keys, the salt, and the iteration count.
	kekInner, kekSalt, kekIters := decodeBlobInnerForTest(t, volumeEntries[0].data, true /*hasPBKDF2*/)
	vekInner, _, _ := decodeBlobInnerForTest(t, vekBlobBytes, false)
	gotWrappedKEK := kekInner.wrappedKey
	gotPBKDF2Salt := kekInner.pbkdf2Salt
	gotIterations := kekIters
	gotWrappedVEK := vekInner.wrappedKey

	// 5e. PBKDF2-derive the unwrap key from the passphrase, unwrap the
	// KEK, then unwrap the VEK.
	gotDerivedKey := pbkdf2.Key(passphrase, gotPBKDF2Salt, int(gotIterations), 32, sha256.New)
	gotKEK, err := aesKeyUnwrap(gotDerivedKey, gotWrappedKEK)
	if err != nil {
		t.Fatalf("unwrap KEK: %v", err)
	}
	gotVEK, err := aesKeyUnwrap(gotKEK, gotWrappedVEK)
	if err != nil {
		t.Fatalf("unwrap VEK: %v", err)
	}
	if !bytes.Equal(gotVEK, vek) {
		t.Fatalf("recovered VEK doesn't match:\n got %x\nwant %x", gotVEK, vek)
	}

	// Sanity: salt round-trips, KEK round-trips, iterations match.
	if !bytes.Equal(gotKEK, kek) {
		t.Fatalf("recovered KEK doesn't match")
	}
	if !bytes.Equal(gotPBKDF2Salt, pbkdf2Salt) {
		t.Fatalf("recovered PBKDF2 salt doesn't match")
	}
	if gotIterations != iterations {
		t.Fatalf("recovered iterations = %d, want %d", gotIterations, iterations)
	}
	_ = kekSalt // kept here to document the field; not asserted because
	// the outer salt at [2] is independent from the inner PBKDF2 salt.
}

// blobParse holds the inner-keyblob fields a parser pulls out of a
// VEKBLOB or KEKBLOB during the unlock walk.
type blobParse struct {
	uuid       [16]byte
	wrappedKey []byte
	pbkdf2Salt []byte // KEKBLOB only
}

// decodeBlobInnerForTest parses the bytes our BuildVEKBlob /
// BuildKEKBlob produced — just enough to recover what the unlock walk
// needs. This is a test-only ad-hoc parser; the real unlock path will
// gain a proper one once it's plumbed through to FormatContainerEncrypted.
func decodeBlobInnerForTest(t *testing.T, der []byte, hasPBKDF2 bool) (blobParse, []byte, uint32) {
	t.Helper()
	if der[0] != 0x30 {
		t.Fatalf("blob outer not a SEQUENCE: %x", der[0])
	}
	bodyOff := 2
	if der[1]&0x80 != 0 {
		bodyOff = 2 + int(der[1]&0x7F)
	}
	body := der[bodyOff:]
	pos := 0
	// [0] version
	if body[pos] != 0x80 {
		t.Fatalf("expected [0] tag, got %x", body[pos])
	}
	pos += 2 + int(body[pos+1])
	// [1] HMAC
	if body[pos] != 0x81 {
		t.Fatalf("expected [1] tag, got %x", body[pos])
	}
	hmacLen, hmacContent := decodeLen(body, pos+1)
	pos = hmacContent + hmacLen
	// [2] salt
	if body[pos] != 0x82 {
		t.Fatalf("expected [2] tag, got %x", body[pos])
	}
	saltLen, saltOff := decodeLen(body, pos+1)
	outerSalt := body[saltOff : saltOff+saltLen]
	pos = saltOff + saltLen
	// [3] inner SEQUENCE (constructed)
	if body[pos] != 0xa3 {
		t.Fatalf("expected [3] CONSTRUCTED tag, got %x", body[pos])
	}
	innerLen, innerOff := decodeLen(body, pos+1)
	inner := body[innerOff : innerOff+innerLen]

	// Walk inner: [0] version, [1] uuid, [2] flags blob, [3] wrapped key,
	// optionally [4] iterations + [5] PBKDF2 salt.
	var p blobParse
	ipos := 0
	// [0]
	if inner[ipos] != 0x80 {
		t.Fatalf("inner [0] tag %x", inner[ipos])
	}
	ipos += 2 + int(inner[ipos+1])
	// [1] uuid
	if inner[ipos] != 0x81 {
		t.Fatalf("inner [1] tag %x", inner[ipos])
	}
	uuidLen, uuidOff := decodeLen(inner, ipos+1)
	if uuidLen != 16 {
		t.Fatalf("inner [1] len %d, want 16", uuidLen)
	}
	copy(p.uuid[:], inner[uuidOff:uuidOff+uuidLen])
	ipos = uuidOff + uuidLen
	// [2] flags
	if inner[ipos] != 0x82 {
		t.Fatalf("inner [2] tag %x", inner[ipos])
	}
	flagsLen, flagsOff := decodeLen(inner, ipos+1)
	ipos = flagsOff + flagsLen
	// [3] wrapped key
	if inner[ipos] != 0x83 {
		t.Fatalf("inner [3] tag %x", inner[ipos])
	}
	wkLen, wkOff := decodeLen(inner, ipos+1)
	p.wrappedKey = append([]byte{}, inner[wkOff:wkOff+wkLen]...)
	ipos = wkOff + wkLen

	var iterations uint32
	if hasPBKDF2 {
		// [4] iterations
		if inner[ipos] != 0x84 {
			t.Fatalf("inner [4] tag %x", inner[ipos])
		}
		itLen, itOff := decodeLen(inner, ipos+1)
		for i := 0; i < itLen; i++ {
			iterations = (iterations << 8) | uint32(inner[itOff+i])
		}
		ipos = itOff + itLen
		// [5] PBKDF2 salt
		if inner[ipos] != 0x85 {
			t.Fatalf("inner [5] tag %x", inner[ipos])
		}
		psLen, psOff := decodeLen(inner, ipos+1)
		p.pbkdf2Salt = append([]byte{}, inner[psOff:psOff+psLen]...)
	}

	return p, outerSalt, iterations
}

