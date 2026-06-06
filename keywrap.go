package apfs

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// KDF type identifiers stored in the first 2 bytes of a locker entry.
const (
	kdfTypeArgon2id = 0x0001
	kdfTypePBKDF2   = 0x0002
)

// unlockVEK walks the container key bag and tries each passphrase locker
// entry until one yields a valid KEK that in turn unwraps the VEK.
//
// The walk dispatches on nx_flags & NX_CRYPTO_SW:
//
//   - NX_CRYPTO_SW set (Apple shape): the container keybag is encrypted
//     at rest with `containerUUID || containerUUID`. After decryption,
//     it carries a tag=3 prange entry pointing at a separate volume
//     keybag (encrypted with `volumeUUID || volumeUUID`) plus a tag=2
//     entry containing an ASN.1 VEKBLOB. The volume keybag's tag=3
//     entry carries an ASN.1 KEKBLOB with PBKDF2 parameters + wrapped
//     KEK. Both blobs verify under HMAC-SHA256 over the [3] envelope.
//
//   - NX_CRYPTO_SW clear (legacy self-consistent shape): one plaintext
//     keybag with a tag=3 PBKDF2 locker (kdfType + iterations + salt +
//     wrappedKEK) and a tag=2 raw AES-KW(KEK, VEK). Used by older
//     Format-emitted images and by package tests.
func unlockVEK(rw io.ReaderAt, passphrase []byte) ([]byte, error) {
	sb, err := parseNXSuperblock(rw)
	if err != nil {
		return nil, err
	}
	if sb.flags&nxFlagCryptoSW != 0 {
		return unlockVEKAppleShape(rw, sb, passphrase)
	}
	return unlockVEKLegacy(rw, sb, passphrase)
}

// unlockVEKLegacy handles containers produced by this package's
// pre-F-2 Format / FormatOn / FormatArgon2id, where the keybag was
// plaintext on disk and used a proprietary PBKDF2 / Argon2id locker
// shape rather than Apple's ASN.1 VEKBLOB / KEKBLOB.
func unlockVEKLegacy(rw io.ReaderAt, sb *nxSuperblock, passphrase []byte) ([]byte, error) {
	kbData, err := readKeybag(rw, sb)
	if err != nil {
		return nil, err
	}
	entries, err := parseKeybag(kbData)
	if err != nil {
		return nil, err
	}
	lockers := findPassphraseLockers(entries)
	if len(lockers) == 0 {
		return nil, fmt.Errorf("apfs: no passphrase locker found in key bag")
	}
	volumeKeyEntries := findVolumeKeyEntries(entries)
	for _, locker := range lockers {
		vek, err := tryUnlock(locker, volumeKeyEntries, passphrase)
		if err == nil {
			return vek, nil
		}
	}
	return nil, fmt.Errorf("apfs: wrong passphrase or unsupported key derivation")
}

// unlockVEKAppleShape handles containers produced by
// FormatContainerEncrypted (or by Apple's apfs.kext via
// `diskutil apfs encryptVolume`).
func unlockVEKAppleShape(rw io.ReaderAt, sb *nxSuperblock, passphrase []byte) ([]byte, error) {
	// 1. Read + decrypt the container keybag.
	containerKBCipher, err := readKeybag(rw, sb)
	if err != nil {
		return nil, err
	}
	containerKBPlain, err := DecryptContainerKeybag(containerKBCipher, sb.uuid, sb.keybagBlock)
	if err != nil {
		return nil, fmt.Errorf("apfs: decrypt container keybag: %w", err)
	}
	containerEntries, err := parseKeybag(containerKBPlain)
	if err != nil {
		return nil, fmt.Errorf("apfs: parse container keybag: %w", err)
	}

	// 2. Walk container entries: tag=3 (volume kb prange) + tag=2 (VEKBLOB).
	var (
		volumeUUID    [16]byte
		volumeKBPaddr uint64
		vekBlobBytes  []byte
		gotVolumeKB   bool
	)
	for _, e := range containerEntries {
		switch e.tag {
		case kbTagVolumePassphrase: // 3 in container kb = KB_TAG_VOLUME_UNLOCK_RECORDS
			if len(e.data) != 16 {
				continue
			}
			volumeUUID = e.uuid
			volumeKBPaddr = binary.LittleEndian.Uint64(e.data[:8])
			gotVolumeKB = true
		case kbTagVolumeKey: // 2
			vekBlobBytes = append([]byte{}, e.data...)
		}
	}
	if !gotVolumeKB || vekBlobBytes == nil {
		return nil, fmt.Errorf("apfs: container keybag missing tag=2 / tag=3 entries")
	}

	// 3. Read + decrypt the volume keybag with the volume UUID.
	volumeKBCipher := make([]byte, sb.blockSize)
	if _, err := rw.ReadAt(volumeKBCipher, int64(volumeKBPaddr)*int64(sb.blockSize)); err != nil {
		return nil, fmt.Errorf("apfs: read volume keybag: %w", err)
	}
	volumeKBPlain, err := DecryptVolumeKeybag(volumeKBCipher, volumeUUID, volumeKBPaddr)
	if err != nil {
		return nil, fmt.Errorf("apfs: decrypt volume keybag: %w", err)
	}
	volumeEntries, err := parseKeybag(volumeKBPlain)
	if err != nil {
		return nil, fmt.Errorf("apfs: parse volume keybag: %w", err)
	}

	// 4. Find the KEKBLOB (tag=3 = KB_TAG_VOLUME_PASSPHRASE) and recover
	// the KEK from the passphrase, then unwrap the VEK from the VEKBLOB.
	for _, e := range volumeEntries {
		if e.tag != kbTagVolumePassphrase {
			continue
		}
		kekBlob, err := ParseKEKBlob(e.data)
		if err != nil {
			continue
		}
		derivedKey := pbkdf2.Key(passphrase, kekBlob.PBKDF2Salt, int(kekBlob.Iterations), 32, sha256.New)
		kek, err := aesKeyUnwrap(derivedKey, kekBlob.WrappedKey)
		if err != nil {
			continue
		}
		vekBlob, err := ParseVEKBlob(vekBlobBytes)
		if err != nil {
			return nil, fmt.Errorf("apfs: parse VEKBLOB: %w", err)
		}
		vek, err := aesKeyUnwrap(kek, vekBlob.WrappedKey)
		if err != nil {
			continue
		}
		return vek, nil
	}
	return nil, fmt.Errorf("apfs: wrong passphrase or no acceptable KEK locker")
}

// tryUnlock attempts to unlock the KEK in a single locker entry and then
// unwrap the VEK with the recovered KEK.
func tryUnlock(locker keybagEntry, vkEntries []keybagEntry, passphrase []byte) ([]byte, error) {
	lk, err := parseLockerEntry(locker.data)
	if err != nil {
		return nil, err
	}
	kek, err := deriveAndUnwrapKEK(lk, passphrase)
	if err != nil {
		return nil, err
	}
	return unwrapVEK(vkEntries, kek)
}

// deriveAndUnwrapKEK derives the key-encryption key from the passphrase and
// uses it to AES-unwrap the wrapped KEK stored in the locker entry.
func deriveAndUnwrapKEK(lk *kbLocker, passphrase []byte) ([]byte, error) {
	// The wrapped KEK is 40 bytes for a 256-bit key (32 + 8 AES-KW overhead).
	// Determine the expected unwrapped key size from the wrapped size.
	kekSize, err := wrappedToKeySize(len(lk.wrappedKEK))
	if err != nil {
		return nil, err
	}
	var kek []byte
	switch lk.kdfType {
	case kdfTypePBKDF2:
		kek = pbkdf2.Key(passphrase, lk.salt, int(lk.iterations), kekSize, sha256.New)
	case kdfTypeArgon2id:
		if lk.timeCost == 0 || lk.memoryKiB == 0 || lk.parallelism == 0 {
			return nil, fmt.Errorf("apfs: invalid Argon2id parameters")
		}
		kek = argon2.IDKey(passphrase, lk.salt, lk.timeCost, lk.memoryKiB, uint8(lk.parallelism), uint32(kekSize))
	default:
		return nil, fmt.Errorf("apfs: unsupported KDF type 0x%04x", lk.kdfType)
	}
	return aesKeyUnwrap(kek, lk.wrappedKEK)
}

// wrappedToKeySize maps an AES-KW ciphertext length to the plaintext key size.
// AES-KW always adds 8 bytes of integrity data to the wrapped key.
func wrappedToKeySize(wrappedLen int) (int, error) {
	if wrappedLen < 24 || (wrappedLen-8)%8 != 0 {
		return 0, fmt.Errorf("apfs: invalid wrapped key length %d", wrappedLen)
	}
	return wrappedLen - 8, nil
}

// unwrapVEK iterates volume-key entries and tries to AES-unwrap each one
// with kek. The first successful unwrap is returned.
func unwrapVEK(vkEntries []keybagEntry, kek []byte) ([]byte, error) {
	if len(vkEntries) == 0 {
		return nil, fmt.Errorf("apfs: no volume key entry found in key bag")
	}
	for _, vke := range vkEntries {
		vek, err := aesKeyUnwrap(kek, vke.data)
		if err == nil {
			return vek, nil
		}
	}
	return nil, fmt.Errorf("apfs: failed to unwrap volume key with derived KEK")
}

// aesKeyUnwrap implements RFC 3394 AES Key Unwrap.
//
// The algorithm uses the AES block cipher in a specific 6-round Feistel
// network to check integrity and recover the plaintext key. The input is
// the wrapped key (keyLen + 8 bytes) and the wrapping key. The output is
// the plaintext key, or an error if the integrity check fails.
func aesKeyUnwrap(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped) < 24 || len(wrapped)%8 != 0 {
		return nil, fmt.Errorf("apfs: keywrap: invalid wrapped key length %d", len(wrapped))
	}
	n := len(wrapped)/8 - 1 // number of 64-bit key-data blocks
	// A is the integrity check register, initialised to the first 8 bytes.
	var a [8]byte
	copy(a[:], wrapped[:8])
	// R holds the n key-data semi-blocks.
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], wrapped[8+i*8:])
	}
	block, err := newAESBlock(kek)
	if err != nil {
		return nil, fmt.Errorf("apfs: keywrap: AES init: %w", err)
	}
	// Unwrap: 6 rounds, each round decrypts all n semi-blocks.
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			t := uint64(n*j + i + 1)
			xorA := xorUint64BigEndian(a[:], t)
			b := make([]byte, 16)
			copy(b[:8], xorA)
			copy(b[8:], r[i])
			block.Decrypt(b, b)
			copy(a[:], b[:8])
			copy(r[i], b[8:])
		}
	}
	// Verify the integrity check value (must be the RFC 3394 default IV).
	expected := [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	if a != expected {
		return nil, fmt.Errorf("apfs: keywrap: integrity check failed (wrong passphrase?)")
	}
	plaintext := make([]byte, n*8)
	for i, rb := range r {
		copy(plaintext[i*8:], rb)
	}
	return plaintext, nil
}

// xorUint64BigEndian XORs a big-endian uint64 in src with v, returning 8 bytes.
func xorUint64BigEndian(src []byte, v uint64) []byte {
	val := binary.BigEndian.Uint64(src) ^ v
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, val)
	return out
}

// AESKeyWrap is a public alias of aesKeyWrap. It implements RFC 3394
// AES Key Wrap; the format-time encrypted-container writer in
// pkg/go-filesystems/apfs uses it to wrap the KEK with a passphrase-
// derived key and the VEK with the KEK.
func AESKeyWrap(kek, plaintext []byte) ([]byte, error) {
	return aesKeyWrap(kek, plaintext)
}

// AESKeyUnwrap is a public alias of aesKeyUnwrap.
func AESKeyUnwrap(kek, wrapped []byte) ([]byte, error) {
	return aesKeyUnwrap(kek, wrapped)
}

// aesKeyWrap implements RFC 3394 AES Key Wrap (the inverse of aesKeyUnwrap).
// plaintext must be a multiple of 8 bytes.
func aesKeyWrap(kek, plaintext []byte) ([]byte, error) {
	if len(plaintext)%8 != 0 {
		return nil, fmt.Errorf("apfs: keywrap: plaintext must be a multiple of 8 bytes, got %d", len(plaintext))
	}
	n := len(plaintext) / 8
	a := [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], plaintext[i*8:])
	}
	block, err := newAESBlock(kek)
	if err != nil {
		return nil, fmt.Errorf("apfs: keywrap: AES init: %w", err)
	}
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			b := make([]byte, 16)
			copy(b[:8], a[:])
			copy(b[8:], r[i])
			block.Encrypt(b, b)
			copy(a[:], b[:8])
			t := uint64(n*j + i + 1)
			copy(a[:], xorUint64BigEndian(a[:], t))
			copy(r[i], b[8:])
		}
	}
	out := make([]byte, 8+len(plaintext))
	copy(out[:8], a[:])
	for i, rb := range r {
		copy(out[8+i*8:], rb)
	}
	return out, nil
}
