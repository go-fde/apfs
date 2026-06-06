package apfs

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

const (
	formatIterations = 1000
	formatSaltLen    = 16
	formatVEKSize    = 32
	formatKEKSize    = 32
)

// Format creates a new APFS FDE container at path, writing the NX superblock
// and key bag blocks and protecting them with passphrase. The file must
// already exist. Returns an opened Device ready for payload I/O.
func Format(path string, passphrase []byte) (*Device, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("apfs: format %s: %w", path, err)
	}
	dev, err := FormatOn(f, passphrase)
	if err != nil {
		f.Close()
		return nil, err
	}
	return dev, nil
}

// FormatOn creates a new APFS FDE container on rw, writing the NX superblock
// and key bag blocks and protecting them with passphrase. Returns an opened
// Device ready for payload I/O.
func FormatOn(rw blockRW, passphrase []byte) (*Device, error) {
	return formatDevice(rw, passphrase)
}

// formatDevice is the shared implementation for Format and FormatOn.
func formatDevice(rw blockRW, passphrase []byte) (*Device, error) {
	vek := apfsRandBytes(formatVEKSize)
	kek := apfsRandBytes(formatKEKSize)
	salt := apfsRandBytes(formatSaltLen)
	if err := writeAPFSContainer(rw, passphrase, vek, kek, salt); err != nil {
		return nil, err
	}
	enc, _ := newXTSCipher(vek)
	return &Device{f: rw, enc: enc}, nil
}

// writeAPFSContainer derives keys, wraps them, and writes the container metadata.
func writeAPFSContainer(rw blockRW, passphrase, vek, kek, salt []byte) error {
	derivedKey := pbkdf2.Key(passphrase, salt, formatIterations, formatKEKSize, sha256.New)
	wrappedKEK, err := aesKeyWrap(derivedKey, kek)
	if err != nil {
		return fmt.Errorf("apfs: format: wrap kek: %w", err)
	}
	wrappedVEK, err := aesKeyWrap(kek, vek)
	if err != nil {
		return fmt.Errorf("apfs: format: wrap vek: %w", err)
	}
	if _, err := rw.WriteAt(nxSuperblockBytes(), 0); err != nil {
		return fmt.Errorf("apfs: format: write superblock: %w", err)
	}
	if _, err := rw.WriteAt(keybagBlockBytes(salt, wrappedKEK, wrappedVEK), int64(nxBlockSize)); err != nil {
		return fmt.Errorf("apfs: format: write keybag: %w", err)
	}
	return nil
}

// nxSuperblockBytes builds the 4096-byte NX container superblock block.
//
// The keybag is placed at block 1 with extent length 1 (i.e. immediately
// after the superblock). Apple's apfs.kext / fsck_apfs look for this in
// nx_keylocker at byte offset 1296 of the NX SuperBlock; earlier versions
// of this package wrote at offset 64, which is nx_incompatible_features
// — a self-consistent bug that broke any attempt at Apple interop.
func nxSuperblockBytes() []byte {
	buf := make([]byte, nxBlockSize)
	copy(buf[32:36], nxSuperblockMagic)
	binary.LittleEndian.PutUint32(buf[36:40], uint32(nxBlockSize))
	binary.LittleEndian.PutUint64(buf[nxKeylockerOffset:nxKeylockerOffset+8], 1)
	binary.LittleEndian.PutUint64(buf[nxKeylockerOffset+8:nxKeylockerOffset+16], 1)
	return buf
}

// keybagBlockBytes builds the 4096-byte key bag block with one passphrase
// locker (tag kbTagVolumePassphrase) and one volume-key entry (tag kbTagVolumeKey).
func keybagBlockBytes(salt, wrappedKEK, wrappedVEK []byte) []byte {
	return packKeybagBlock([]rawEntry{
		{tag: kbTagVolumePassphrase, data: encodePBKDF2Locker(uint32(formatIterations), salt, wrappedKEK)},
		{tag: kbTagVolumeKey, data: wrappedVEK},
	})
}

// rawEntry is a (tag, data) pair representing one keybag entry to be written.
type rawEntry struct {
	uuid [16]byte
	tag  uint16
	data []byte
}

// packKeybagBlock packs entries into a freshly allocated 4096-byte keybag
// block. The block layout is:
//
//	+0   apfs_obj_phys (32 bytes; cksum + oid=0 + xid=2 + type=mediaKeybagObjType + subtype=0)
//	+32  apfs_kb_locker header: version(2) + nkeys(2) + nbytes(4) + padding(8)
//	+48  16-byte-aligned entries
//
// obj_phys.cksum (offset 0..7) is filled with Fletcher-64 over bytes
// [8..end] before returning — apfs.kext / fsck_apfs validate this on
// every keybag read and reject "Bad message" otherwise. Field values
// match Apple's reference: oid=0 (Apple convention for keybags), xid
// non-zero (= formatCurrentXID = 2 in the wrapping container format),
// type = APFS_OBJECT_TYPE_MEDIA_KEYBAG with no storage-class flags.
func packKeybagBlock(entries []rawEntry) []byte {
	buf := make([]byte, nxBlockSize)
	// obj_phys.oid at +8: Apple's reference DMG leaves this zero for
	// keybags (verified across two independently-encrypted reference
	// DMGs in TestProbe_TwoAppleReferences).
	binary.LittleEndian.PutUint64(buf[8:16], 0)
	// obj_phys.xid at +16: non-zero placeholder so fsck_apfs's keybag
	// reader sees a valid creation transaction. 2 matches our
	// formatCurrentXID in the wrapping container format.
	binary.LittleEndian.PutUint64(buf[16:24], 2)
	// obj_phys.type at +24 (subtype at +28 stays zero).
	binary.LittleEndian.PutUint32(buf[24:28], mediaKeybagObjType)
	// apfs_kb_locker header at +32.
	binary.LittleEndian.PutUint16(buf[32:34], keybagVersion)
	binary.LittleEndian.PutUint16(buf[34:36], uint16(len(entries)))
	// nbytes (buf[36:40]) is patched in below once we know the byte count.
	off := keybagEntryAreaStart
	for _, e := range entries {
		off = appendEntryUUID(buf, off, e.uuid, int(e.tag), e.data)
	}
	// kl_nbytes is the total length (in bytes) of the kb_locker INCLUDING
	// its 16-byte header — i.e. from byte 32 (after obj_phys) to the end
	// of the last entry's 16-byte-aligned padding. Apple's apfs.kext /
	// fsck_apfs reject "Bad message" when this counts entries-only
	// (off-by-16). Verified against Apple's reference (which has nbytes
	// = 0xE0 = 224 for two entries totalling 208 bytes of entry data
	// plus the 16-byte kb_locker header).
	const kbLockerHeaderStart = 32
	binary.LittleEndian.PutUint32(buf[36:40], uint32(off-kbLockerHeaderStart))
	// Seal: compute Fletcher-64 over buf[8:] and store at buf[0:8].
	cksum := fletcher64(buf[8:])
	binary.LittleEndian.PutUint64(buf[0:8], cksum)
	return buf
}

// fletcher64 implements the APFS Fletcher-64 variant. The algorithm
// processes 4-byte little-endian words and computes a checksum that
// makes the sum of all words (including a 64-bit appended cksum word)
// equal zero modulo (2^32 - 1). Mirrors go-filesystems/apfs/format.go's
// implementation; duplicated here to avoid a cross-package dependency
// from this lower-level package.
func fletcher64(buf []byte) uint64 {
	const mod = (uint64(1) << 32) - 1
	var s1, s2 uint64
	for i := 0; i+4 <= len(buf); i += 4 {
		w := uint64(binary.LittleEndian.Uint32(buf[i : i+4]))
		s1 = (s1 + w) % mod
		s2 = (s2 + s1) % mod
	}
	c1 := mod - ((s1 + s2) % mod)
	c2 := mod - ((s1 + c1) % mod)
	return (c2 << 32) | c1
}

// appendEntryUUID writes a keybag entry into buf at byte offset off and
// returns the next available offset (16-byte aligned).
// Entries are rounded up to keybagEntryAlignment (16) per Apple's apfs-fuse
// reference; earlier versions used 8-byte alignment.
func appendEntryUUID(buf []byte, off int, uuid [16]byte, tag int, data []byte) int {
	const hLen = 24
	copy(buf[off:off+16], uuid[:])
	binary.LittleEndian.PutUint16(buf[off+16:], uint16(tag))
	binary.LittleEndian.PutUint16(buf[off+18:], uint16(len(data)))
	// buf[off+20:off+24]: padding = 0
	copy(buf[off+hLen:], data)
	off += hLen + len(data)
	if rem := off % keybagEntryAlignment; rem != 0 {
		off += keybagEntryAlignment - rem
	}
	return off
}

// apfsRandReadFn is the crypto-rand entry point used by apfsRandBytes.
// Tests override it to drive the panic branch; production never does.
var apfsRandReadFn = rand.Read

// apfsRandBytes returns n cryptographically random bytes. A failure here
// would indicate a broken crypto-RNG which the caller cannot do anything
// sensible about — we panic rather than propagate, matching the practical
// behaviour of every modern OS.
func apfsRandBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := apfsRandReadFn(b); err != nil {
		panic("apfs: crypto/rand.Read failed: " + err.Error())
	}
	return b
}
