package apfs

// keybag_atrest.go implements Apple's at-rest encryption layer for APFS
// keybag blocks. The recipe (validated 2026-05-09 against a
// `diskutil apfs encryptVolume`-produced reference DMG; see
// pkg/go-filesystems/apfs/probe_apple_keybag_darwin_test.go) is:
//
//   • AES-XTS-128 (32-byte combined key)
//   • Container keybag key:  containerUUID concatenated with itself
//   • Volume keybag key:     volumeUUID    concatenated with itself
//   • XTS sector size:       512 bytes  (NOT the 4096 block size)
//   • XTS tweak (unit no.):  paddr × 8 + sector_index_within_block
//
// Both keybags use the SAME recipe — only the UUID differs. apfs-fuse's
// KeyManager::LoadKeybag passes the appropriate UUID directly:
// container UUID for the container keybag, volume UUID for the volume
// keybag. The VEK is *not* used at this layer; using it would be
// circular (the volume keybag is what produces the VEK).
//
// Each 4096-byte keybag block is processed as 8 sub-sectors, with the
// first sector keyed at unit `paddr * 8`. This is asymmetric from the
// per-volume-data block encryption (where the unit is the byte offset
// divided by 512); the keybag layer always counts from `paddr × 8` even
// if the keybag lives at a non-zero offset inside a GPT-wrapped image.

import (
	"crypto/aes"
	"fmt"

	"golang.org/x/crypto/xts"
)

const (
	// keybagXTSSectorSize is the XTS sector size used for keybag at-rest
	// encryption. APFS uses 512 (not the 4096-byte block size).
	keybagXTSSectorSize = 512

	// keybagXTSSectorsPerBlock is the number of 512-byte sub-sectors in
	// a 4096-byte keybag block.
	keybagXTSSectorsPerBlock = nxBlockSize / keybagXTSSectorSize
)

// keybagXTSKey returns the AES-XTS key used to encrypt a keybag at
// rest: the supplied UUID concatenated with itself (32 bytes total).
// Apple uses container UUID for the container keybag and volume UUID
// for the volume keybag; the recipe is identical otherwise.
func keybagXTSKey(uuid [16]byte) []byte {
	out := make([]byte, 32)
	copy(out[:16], uuid[:])
	copy(out[16:], uuid[:])
	return out
}

// containerKeybagKey is keybagXTSKey applied to the container UUID.
// Kept as an explicit name so call sites at the format layer read
// clearly ("this is the container keybag").
func containerKeybagKey(containerUUID [16]byte) []byte {
	return keybagXTSKey(containerUUID)
}

// volumeKeybagKey is keybagXTSKey applied to the volume UUID. Apple's
// apfs.kext encrypts the volume keybag at rest with this key — NOT
// with the VEK (which would be circular: the volume keybag is what
// holds the wrapped VEK).
func volumeKeybagKey(volumeUUID [16]byte) []byte {
	return keybagXTSKey(volumeUUID)
}

// encryptKeybagAtRest encrypts plaintext (a multiple of nxBlockSize bytes,
// typically one block) in place using AES-XTS-128 with the supplied key
// and a base unit derived from paddr. Returns the encrypted bytes.
//
// key must be 32 bytes (AES-128-XTS) or 64 bytes (AES-256-XTS). For the
// container keybag use containerKeybagKey(uuid); for the volume keybag
// use the VEK directly.
func encryptKeybagAtRest(plaintext []byte, key []byte, paddr uint64) ([]byte, error) {
	return processKeybagAtRest(plaintext, key, paddr, true)
}

// decryptKeybagAtRest is the inverse of encryptKeybagAtRest.
func decryptKeybagAtRest(ciphertext []byte, key []byte, paddr uint64) ([]byte, error) {
	return processKeybagAtRest(ciphertext, key, paddr, false)
}

// DecryptContainerKeybag decrypts a raw container-keybag block (or a
// contiguous run of them) read at paddr from a software-encrypted APFS
// container, using only the container UUID. This is the recipe Apple's
// apfs.kext applies to bytes pointed to by the NX SuperBlock's
// nx_keylocker field — see pkg/go-filesystems/apfs/probe_apple_keybag_darwin_test.go
// for the empirical validation that produced this implementation.
//
// ciphertext length must be a multiple of the APFS block size (4096).
// The volume keybag, by contrast, is encrypted with the VEK rather than
// the container UUID — call decryptKeybagAtRest directly with the VEK
// in that path (or use the higher-level unlock flow once it lands).
func DecryptContainerKeybag(ciphertext []byte, containerUUID [16]byte, paddr uint64) ([]byte, error) {
	return decryptKeybagAtRest(ciphertext, containerKeybagKey(containerUUID), paddr)
}

// EncryptContainerKeybag is the inverse of DecryptContainerKeybag. The
// future FormatContainerEncrypted writer in pkg/go-filesystems/apfs uses
// this to seal the container keybag before writing it to disk.
func EncryptContainerKeybag(plaintext []byte, containerUUID [16]byte, paddr uint64) ([]byte, error) {
	return encryptKeybagAtRest(plaintext, containerKeybagKey(containerUUID), paddr)
}

// DecryptVolumeKeybag decrypts a raw volume-keybag block using the
// volume UUID. The volume keybag is referenced by the container
// keybag's tag=3 (KB_TAG_VOLUME_UNLOCK_RECORDS) entry (which carries an
// apfs_prange to its on-disk location). Apple's apfs.kext applies the
// same `uuid || uuid` AES-XTS recipe as for the container keybag, but
// keyed on the volume UUID rather than the container UUID.
func DecryptVolumeKeybag(ciphertext []byte, volumeUUID [16]byte, paddr uint64) ([]byte, error) {
	return decryptKeybagAtRest(ciphertext, volumeKeybagKey(volumeUUID), paddr)
}

// EncryptVolumeKeybag is the inverse of DecryptVolumeKeybag.
func EncryptVolumeKeybag(plaintext []byte, volumeUUID [16]byte, paddr uint64) ([]byte, error) {
	return encryptKeybagAtRest(plaintext, volumeKeybagKey(volumeUUID), paddr)
}

// EncryptVolumeBlock encrypts a 4 KiB volume metadata or file-data
// block at rest using the VEK. Apple's apfs.kext applies this layer to
// every block reachable from the volume superblock (APSB, volume OMAP,
// FS-tree root, snap-meta / extent-ref trees, and file data blocks)
// when the container has NX_CRYPTO_SW set.
//
// The recipe is identical to the keybag at-rest XTS layer: 512-byte
// XTS sectors with tweak = paddr × 8 + sector_index_within_block. The
// only difference is the key — the VEK rather than a UUID-derived
// value. vek must be 32 bytes (AES-128-XTS) or 64 bytes (AES-256-XTS).
func EncryptVolumeBlock(plaintext []byte, vek []byte, paddr uint64) ([]byte, error) {
	return encryptKeybagAtRest(plaintext, vek, paddr)
}

// DecryptVolumeBlock is the inverse of EncryptVolumeBlock.
func DecryptVolumeBlock(ciphertext []byte, vek []byte, paddr uint64) ([]byte, error) {
	return decryptKeybagAtRest(ciphertext, vek, paddr)
}

// KeybagEntry is the public form of a single keybag entry consumed by
// PackKeybagBlock. Tag values are the package constants KBTagVolumeKey
// (2) and KBTagVolumeUnlockRecords / KBTagVolumePassphrase (both 3 —
// the meaning depends on which keybag the entry lives in).
type KeybagEntry struct {
	UUID [16]byte
	Tag  uint16
	Data []byte
}

// Public mirrors of the unexported keybag-tag constants. The 0x0003
// tag is overloaded by Apple: in the *container* keybag it's
// KB_TAG_VOLUME_UNLOCK_RECORDS (data = apfs_prange to the volume
// keybag); in the *volume* keybag it's KB_TAG_VOLUME_PASSPHRASE
// (data = KEKBLOB DER).
const (
	KBTagVolumeKey            = uint16(kbTagVolumeKey)
	KBTagVolumeUnlockRecords  = uint16(kbTagVolumePassphrase) // 3
	KBTagVolumePassphrase     = uint16(kbTagVolumePassphrase) // 3 (alias)
)

// PackKeybagBlock builds a 4096-byte plaintext keybag block carrying
// the supplied entries, with the proper 32-byte obj_phys header
// (o_type = APFS_OBJECT_TYPE_MEDIA_KEYBAG / 0x6b657973, oid = 0
// matching Apple's reference, sealed Fletcher-64 cksum) and 16-byte
// apfs_kb_locker. Entries are 16-byte aligned per Apple's apfs-fuse
// reference.
//
// The returned block is *plaintext* — call EncryptContainerKeybag or
// EncryptVolumeKeybag (with the appropriate UUID and paddr) before
// writing to disk.
func PackKeybagBlock(entries []KeybagEntry) []byte {
	raws := make([]rawEntry, len(entries))
	for i, e := range entries {
		raws[i] = rawEntry{uuid: e.UUID, tag: e.Tag, data: e.Data}
	}
	return packKeybagBlock(raws)
}

func processKeybagAtRest(in []byte, key []byte, paddr uint64, encrypt bool) ([]byte, error) {
	if len(in)%nxBlockSize != 0 {
		return nil, fmt.Errorf("apfs: keybag at-rest: input length %d is not a multiple of block size %d", len(in), nxBlockSize)
	}
	if len(key) != 32 && len(key) != 64 {
		return nil, fmt.Errorf("apfs: keybag at-rest: key must be 32 or 64 bytes, got %d", len(key))
	}
	c, err := xts.NewCipher(aes.NewCipher, key)
	if err != nil {
		return nil, fmt.Errorf("apfs: keybag at-rest: xts cipher: %w", err)
	}
	out := make([]byte, len(in))
	for blockOff := 0; blockOff < len(in); blockOff += nxBlockSize {
		blockPaddr := paddr + uint64(blockOff/nxBlockSize)
		baseUnit := blockPaddr * keybagXTSSectorsPerBlock
		for s := 0; s < keybagXTSSectorsPerBlock; s++ {
			off := blockOff + s*keybagXTSSectorSize
			src := in[off : off+keybagXTSSectorSize]
			dst := out[off : off+keybagXTSSectorSize]
			if encrypt {
				c.Encrypt(dst, src, baseUnit+uint64(s))
			} else {
				c.Decrypt(dst, src, baseUnit+uint64(s))
			}
		}
	}
	return out, nil
}
