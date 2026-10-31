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
// Each keybag block of B bytes is processed as B/512 sub-sectors, with the
// first keyed at unit `paddr * B/512` -- `paddr * 8` for the common 4096-byte
// block (apfs-fuse KeyMgmt.cpp: cs_factor = blocksize / 0x200). The exported
// functions without a block size assume 4096; DecryptKeybagBlocks and its
// siblings take the container's. This is asymmetric from the
// per-volume-data block encryption (where the unit is the byte offset
// divided by 512); the keybag layer always counts from `paddr × 8` even
// if the keybag lives at a non-zero offset inside a GPT-wrapped image.

import (
	"crypto/aes"
	"fmt"

	"github.com/go-encryptions/xts"
)

const (
	// keybagXTSSectorSize is the XTS sector size used for keybag at-rest
	// encryption. APFS uses 512 (not the 4096-byte block size).
	keybagXTSSectorSize = 512
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
//
// It assumes 4096-byte blocks, as the exported functions without a block
// size do; DecryptKeybagBlocks and its siblings take the container's.
func encryptKeybagAtRest(plaintext []byte, key []byte, paddr uint64) ([]byte, error) {
	return processKeybagAtRest(plaintext, key, paddr, nxBlockSize, true)
}

// decryptKeybagAtRest is the inverse of encryptKeybagAtRest.
func decryptKeybagAtRest(ciphertext []byte, key []byte, paddr uint64) ([]byte, error) {
	return processKeybagAtRest(ciphertext, key, paddr, nxBlockSize, false)
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
	KBTagVolumeKey           = uint16(kbTagVolumeKey)
	KBTagVolumeUnlockRecords = uint16(kbTagVolumePassphrase) // 3
	KBTagVolumePassphrase    = uint16(kbTagVolumePassphrase) // 3 (alias)
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

// DecryptKeybagBlocks decrypts keybag blocks of blockSize bytes read at
// paddr, keyed by uuid: the container's for the container keybag, the
// volume's for the volume keybag. The XTS data units are 512 bytes, and the
// first is paddr × blockSize/512 -- the container's block size, not 4096
// (apfs-fuse KeyMgmt.cpp, KeyManager::DecryptBlocks: cs_factor =
// GetBlocksize() / 0x200, uno = block * cs_factor). blockSize is a power of
// two from 4096 to 65536 (NX_MINIMUM_BLOCK_SIZE to NX_MAXIMUM_BLOCK_SIZE).
func DecryptKeybagBlocks(ciphertext []byte, uuid [16]byte, paddr uint64, blockSize uint32) ([]byte, error) {
	return processKeybagAtRest(ciphertext, keybagXTSKey(uuid), paddr, blockSize, false)
}

// EncryptKeybagBlocks is the inverse of DecryptKeybagBlocks.
func EncryptKeybagBlocks(plaintext []byte, uuid [16]byte, paddr uint64, blockSize uint32) ([]byte, error) {
	return processKeybagAtRest(plaintext, keybagXTSKey(uuid), paddr, blockSize, true)
}

// DecryptVolumeBlocks decrypts volume blocks of blockSize bytes read at
// paddr with the VEK: the same data units as DecryptKeybagBlocks.
func DecryptVolumeBlocks(ciphertext []byte, vek []byte, paddr uint64, blockSize uint32) ([]byte, error) {
	return processKeybagAtRest(ciphertext, vek, paddr, blockSize, false)
}

// EncryptVolumeBlocks is the inverse of DecryptVolumeBlocks.
func EncryptVolumeBlocks(plaintext []byte, vek []byte, paddr uint64, blockSize uint32) ([]byte, error) {
	return processKeybagAtRest(plaintext, vek, paddr, blockSize, true)
}

func processKeybagAtRest(in []byte, key []byte, paddr uint64, blockSize uint32, encrypt bool) ([]byte, error) {
	if blockSize < nxMinBlockSize || blockSize > nxMaxBlockSize || blockSize&(blockSize-1) != 0 {
		return nil, fmt.Errorf("apfs: keybag at-rest: block size %d is not a power of two in [%d, %d]", blockSize, nxMinBlockSize, nxMaxBlockSize)
	}
	if len(in)%int(blockSize) != 0 {
		return nil, fmt.Errorf("apfs: keybag at-rest: input length %d is not a multiple of block size %d", len(in), blockSize)
	}
	if len(key) != 32 && len(key) != 64 {
		return nil, fmt.Errorf("apfs: keybag at-rest: key must be 32 or 64 bytes, got %d", len(key))
	}
	c, err := xts.NewCipher(aes.NewCipher, key)
	if err != nil {
		return nil, fmt.Errorf("apfs: keybag at-rest: xts cipher: %w", err)
	}
	// The data units of consecutive blocks are consecutive, so the whole
	// run is one cryptSectors call starting at paddr × sectors-per-block.
	out := append([]byte(nil), in...)
	if err := cryptSectors(c, out, paddr*uint64(blockSize/keybagXTSSectorSize), encrypt); err != nil {
		return nil, err
	}
	return out, nil
}
