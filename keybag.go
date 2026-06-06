package apfs

import (
	"encoding/binary"
	"fmt"
	"io"
)

// parseNXSuperblock reads the NX container superblock from block 0 of rw.
// It validates the magic and extracts the block size and keybag location
// from nx_keylocker (offset 1296 — see nxKeylockerOffset). Earlier versions
// of this package read at offsets 64-79 (which is nx_incompatible_features),
// a self-consistent bug that prevented reading any Apple-authored container.
func parseNXSuperblock(rw io.ReaderAt) (*nxSuperblock, error) {
	buf := make([]byte, nxBlockSize)
	if _, err := rw.ReadAt(buf, 0); err != nil {
		return nil, fmt.Errorf("apfs: read superblock: %w", err)
	}
	// Offset 32: object type magic (4 bytes, little-endian).
	magic := string(buf[32:36])
	if magic != nxSuperblockMagic {
		return nil, fmt.Errorf("apfs: not an APFS container (got magic %q)", magic)
	}
	// Offset 36: block size (uint32, little-endian).
	blockSize := binary.LittleEndian.Uint32(buf[36:40])
	if blockSize == 0 {
		blockSize = nxBlockSize
	}
	// nx_keylocker (apfs_prange) at offset 1296: paddr (8) + block_count (8).
	keybagBlock := binary.LittleEndian.Uint64(buf[nxKeylockerOffset : nxKeylockerOffset+8])
	keybagBlocks := binary.LittleEndian.Uint64(buf[nxKeylockerOffset+8 : nxKeylockerOffset+16])
	// nx_flags at offset 1264 (bit 0x4 = NX_CRYPTO_SW) and
	// nx_uuid at offset 72 — both needed when the container is
	// software-encrypted, since unlockVEK decrypts the container
	// keybag with `uuid || uuid` AES-XTS before parsing it.
	flags := binary.LittleEndian.Uint64(buf[1264:1272])
	var uuid [16]byte
	copy(uuid[:], buf[72:88])
	return &nxSuperblock{
		blockSize:    blockSize,
		keybagBlock:  keybagBlock,
		keybagBlocks: keybagBlocks,
		flags:        flags,
		uuid:         uuid,
	}, nil
}

// readKeybag reads the raw key bag bytes from the container.
func readKeybag(rw io.ReaderAt, sb *nxSuperblock) ([]byte, error) {
	if sb.keybagBlock == 0 || sb.keybagBlocks == 0 {
		return nil, fmt.Errorf("apfs: no key bag present in container superblock")
	}
	totalBytes := int64(sb.keybagBlocks) * int64(sb.blockSize)
	buf := make([]byte, totalBytes)
	off := int64(sb.keybagBlock) * int64(sb.blockSize)
	if _, err := rw.ReadAt(buf, off); err != nil {
		return nil, fmt.Errorf("apfs: read keybag: %w", err)
	}
	return buf, nil
}

// parseKeybag parses the obj_phys header, apfs_kb_locker, and entries
// from a raw keybag block. Layout:
//
//	+0   obj_phys (32 bytes; type at +24 must be mediaKeybagObjType)
//	+32  kb_locker: version(2) + nkeys(2) + nbytes(4) + 8 bytes padding
//	+48  entries (16-byte aligned)
func parseKeybag(data []byte) ([]keybagEntry, error) {
	if len(data) < keybagEntryAreaStart {
		return nil, fmt.Errorf("apfs: keybag too short (%d bytes)", len(data))
	}
	objType := binary.LittleEndian.Uint32(data[24:28])
	if objType != mediaKeybagObjType {
		return nil, fmt.Errorf("apfs: keybag obj_phys.type 0x%x (want 0x%x)",
			objType, mediaKeybagObjType)
	}
	version := binary.LittleEndian.Uint16(data[32:34])
	if version != keybagVersion {
		return nil, fmt.Errorf("apfs: unsupported keybag version %d", version)
	}
	numEntries := int(binary.LittleEndian.Uint16(data[34:36]))
	return parseKeybagEntries(data[keybagEntryAreaStart:], numEntries)
}

// parseKeybagEntries decodes numEntries sequential keybag entries from data.
func parseKeybagEntries(data []byte, numEntries int) ([]keybagEntry, error) {
	entries := make([]keybagEntry, 0, numEntries)
	off := 0
	for i := 0; i < numEntries; i++ {
		// Each entry: 16-byte UUID + 2-byte tag + 2-byte keylen + 4-byte padding + data.
		const entryHeaderLen = 24
		if off+entryHeaderLen > len(data) {
			return nil, fmt.Errorf("apfs: keybag entry %d: truncated", i)
		}
		var e keybagEntry
		copy(e.uuid[:], data[off:off+16])
		e.tag = binary.LittleEndian.Uint16(data[off+16 : off+18])
		e.keylen = binary.LittleEndian.Uint16(data[off+18 : off+20])
		// 4 bytes padding at off+20
		off += entryHeaderLen
		if off+int(e.keylen) > len(data) {
			return nil, fmt.Errorf("apfs: keybag entry %d: data truncated (want %d, have %d)", i, e.keylen, len(data)-off)
		}
		e.data = make([]byte, e.keylen)
		copy(e.data, data[off:off+int(e.keylen)])
		off += int(e.keylen)
		// Entries are 16-byte aligned per Apple's apfs-fuse reference.
		if rem := off % keybagEntryAlignment; rem != 0 {
			off += keybagEntryAlignment - rem
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// parseLockerEntry decodes the KDF parameters and wrapped KEK from the data
// field of a kbTagVolumePassphrase keybag entry. Both PBKDF2 (kdfType =
// 0x0002) and Argon2id (kdfType = 0x0001) layouts are recognised. Any other
// kdfType is parsed using the PBKDF2 layout so structural errors (truncated
// salt, etc.) are still surfaced; deriveAndUnwrapKEK rejects unknown types
// before key derivation runs.
func parseLockerEntry(data []byte) (*kbLocker, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("apfs: locker entry too short")
	}
	kdfType := binary.LittleEndian.Uint16(data[0:2])
	// data[2:4] is padding
	if kdfType == kdfTypeArgon2id {
		return parseArgon2idLocker(data, kdfType)
	}
	return parsePBKDF2Locker(data, kdfType)
}

// parsePBKDF2Locker decodes a PBKDF2 locker entry (see kbLocker doc comment).
func parsePBKDF2Locker(data []byte, kdfType uint16) (*kbLocker, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("apfs: PBKDF2 locker entry too short")
	}
	iterations := binary.LittleEndian.Uint32(data[4:8])
	saltLen := int(binary.LittleEndian.Uint16(data[8:10]))
	if 10+saltLen > len(data) {
		return nil, fmt.Errorf("apfs: PBKDF2 locker entry: salt truncated")
	}
	salt := make([]byte, saltLen)
	copy(salt, data[10:10+saltLen])
	wrappedKEK := make([]byte, len(data)-(10+saltLen))
	copy(wrappedKEK, data[10+saltLen:])
	return &kbLocker{
		kdfType:    kdfType,
		iterations: iterations,
		salt:       salt,
		wrappedKEK: wrappedKEK,
	}, nil
}

// parseArgon2idLocker decodes an Argon2id locker entry (see kbLocker doc).
func parseArgon2idLocker(data []byte, kdfType uint16) (*kbLocker, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("apfs: Argon2id locker entry too short")
	}
	timeCost := binary.LittleEndian.Uint32(data[4:8])
	memoryKiB := binary.LittleEndian.Uint32(data[8:12])
	parallelism := binary.LittleEndian.Uint16(data[12:14])
	saltLen := int(binary.LittleEndian.Uint16(data[14:16]))
	if 16+saltLen > len(data) {
		return nil, fmt.Errorf("apfs: Argon2id locker entry: salt truncated")
	}
	salt := make([]byte, saltLen)
	copy(salt, data[16:16+saltLen])
	wrappedKEK := make([]byte, len(data)-(16+saltLen))
	copy(wrappedKEK, data[16+saltLen:])
	return &kbLocker{
		kdfType:     kdfType,
		timeCost:    timeCost,
		memoryKiB:   memoryKiB,
		parallelism: parallelism,
		salt:        salt,
		wrappedKEK:  wrappedKEK,
	}, nil
}

// encodePBKDF2Locker serialises a PBKDF2 locker entry to the on-disk byte
// layout consumed by parsePBKDF2Locker.
func encodePBKDF2Locker(iterations uint32, salt, wrappedKEK []byte) []byte {
	if len(salt) > 0xFFFF {
		panic("apfs: salt too large")
	}
	out := make([]byte, 10+len(salt)+len(wrappedKEK))
	binary.LittleEndian.PutUint16(out[0:2], kdfTypePBKDF2)
	// out[2:4] padding = 0
	binary.LittleEndian.PutUint32(out[4:8], iterations)
	binary.LittleEndian.PutUint16(out[8:10], uint16(len(salt)))
	copy(out[10:], salt)
	copy(out[10+len(salt):], wrappedKEK)
	return out
}

// encodeArgon2idLocker serialises an Argon2id locker entry to the on-disk
// byte layout consumed by parseArgon2idLocker.
func encodeArgon2idLocker(timeCost, memoryKiB uint32, parallelism uint16, salt, wrappedKEK []byte) []byte {
	if len(salt) > 0xFFFF {
		panic("apfs: salt too large")
	}
	out := make([]byte, 16+len(salt)+len(wrappedKEK))
	binary.LittleEndian.PutUint16(out[0:2], kdfTypeArgon2id)
	// out[2:4] padding = 0
	binary.LittleEndian.PutUint32(out[4:8], timeCost)
	binary.LittleEndian.PutUint32(out[8:12], memoryKiB)
	binary.LittleEndian.PutUint16(out[12:14], parallelism)
	binary.LittleEndian.PutUint16(out[14:16], uint16(len(salt)))
	copy(out[16:], salt)
	copy(out[16+len(salt):], wrappedKEK)
	return out
}

// findPassphraseLockers returns all keybag entries of type kbTagVolumePassphrase.
func findPassphraseLockers(entries []keybagEntry) []keybagEntry {
	var lockers []keybagEntry
	for _, e := range entries {
		if e.tag == kbTagVolumePassphrase {
			lockers = append(lockers, e)
		}
	}
	return lockers
}

// findVolumeKeyEntries returns all keybag entries of type kbTagVolumeKey.
func findVolumeKeyEntries(entries []keybagEntry) []keybagEntry {
	var vks []keybagEntry
	for _, e := range entries {
		if e.tag == kbTagVolumeKey {
			vks = append(vks, e)
		}
	}
	return vks
}
