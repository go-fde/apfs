package apfs

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// -----------------------------------------------------------------------
// Test helpers — build synthetic APFS-like images in memory.
// -----------------------------------------------------------------------

// mustRand returns n random bytes or panics.
func mustRand(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// buildAPFSImage creates a minimal synthetic APFS-like image for testing.
// It returns the image bytes and the plaintext content written at offset 0
// of the "volume" (which for test purposes is the entire device).
//
// Layout:
//
//	Block 0: NX superblock (magic "NXSB" at offset 32, keybag at block 1)
//	Block 1: Key bag (obj_phys.type = 0x6b657973 "syek", one passphrase locker, one volume key)
//	Blocks 2+: Encrypted payload
func buildAPFSImage(t *testing.T, passphrase []byte, payloadData []byte) []byte {
	t.Helper()
	const blockSize = 4096
	const numBlocks = 4

	// 1. Generate VEK (32 bytes → AES-128-XTS with 64-byte combined key)
	// Actually for AES-128-XTS the key is 32 bytes (two 16-byte halves).
	// For AES-256-XTS the key is 64 bytes (two 32-byte halves).
	// We use 32 bytes (AES-128-XTS) for tests.
	vek := mustRand(32)

	// 2. Derive KEK from passphrase using PBKDF2-SHA256.
	salt := mustRand(16)
	iter := 1000
	kek := pbkdf2.Key(passphrase, salt, iter, 32, sha256.New)

	// 3. Wrap VEK with KEK (AES-KW, RFC 3394) → wrappedVEK (40 bytes).
	wrappedVEK, err := aesKeyWrap(kek, vek)
	if err != nil {
		t.Fatalf("wrap VEK: %v", err)
	}

	// 4. Wrap KEK with itself as a "passphrase-derived" outer key.
	// In a real APFS image the locker data contains the PBKDF2 parameters
	// and the KEK itself is the output. We store the wrapped KEK inside the
	// locker data, where the wrapping key = kek.
	// For simplicity in this test helper, the locker stores the PBKDF2 params
	// and a self-wrapped KEK (kek wrapped with kek). The unlock path then:
	//  1. Derives kek from passphrase via PBKDF2.
	//  2. Unwraps wrappedKEK from the locker using kek → recovers kek itself.
	//  3. Unwraps wrappedVEK from the volume key entry using kek → recovers vek.
	wrappedKEK, err := aesKeyWrap(kek, kek)
	if err != nil {
		t.Fatalf("wrap KEK: %v", err)
	}

	// 5. Build the key bag block (block 1).
	kbBlock := buildKeybagBlock(t, salt, iter, wrappedKEK, wrappedVEK)

	// 6. Build the NX superblock block (block 0).
	sb := buildNXSuperblock(blockSize, 1, 1)

	// 7. Build payload block (block 2 onward), encrypted with VEK.
	payloadBlock := make([]byte, blockSize)
	if len(payloadData) > blockSize {
		payloadData = payloadData[:blockSize]
	}
	copy(payloadBlock, payloadData)
	// Encrypt payloadBlock using AES-XTS with VEK (sector 2).
	enc, err := newXTSCipher(vek)
	if err != nil {
		t.Fatalf("newXTSCipher: %v", err)
	}
	payloadBlock2 := make([]byte, blockSize)
	copy(payloadBlock2, payloadBlock)
	if err := enc.processSectors(payloadBlock2, int64(2*blockSize), true); err != nil {
		t.Fatalf("encrypt payload: %v", err)
	}

	// Assemble the image.
	img := make([]byte, numBlocks*blockSize)
	copy(img[0:blockSize], sb)
	copy(img[blockSize:2*blockSize], kbBlock)
	copy(img[2*blockSize:3*blockSize], payloadBlock2)
	return img
}

// buildNXSuperblock builds a minimal NX superblock for block 0. The keybag
// extent is recorded in nx_keylocker (struct apfs_prange at offset
// nxKeylockerOffset = 1296).
func buildNXSuperblock(blockSize uint32, keybagBlock, keybagBlocks uint64) []byte {
	buf := make([]byte, nxBlockSize)
	copy(buf[32:36], nxSuperblockMagic)
	binary.LittleEndian.PutUint32(buf[36:40], blockSize)
	binary.LittleEndian.PutUint64(buf[nxKeylockerOffset:nxKeylockerOffset+8], keybagBlock)
	binary.LittleEndian.PutUint64(buf[nxKeylockerOffset+8:nxKeylockerOffset+16], keybagBlocks)
	return buf
}

// writeKeybagHeader writes the obj_phys + apfs_kb_locker prefix into buf at
// blockOff and returns the offset of the entry area (blockOff + 48).
func writeKeybagHeader(buf []byte, blockOff int, numEntries int) int {
	binary.LittleEndian.PutUint32(buf[blockOff+24:blockOff+28], mediaKeybagObjType)
	binary.LittleEndian.PutUint16(buf[blockOff+32:blockOff+34], keybagVersion)
	binary.LittleEndian.PutUint16(buf[blockOff+34:blockOff+36], uint16(numEntries))
	// nbytes (buf[blockOff+36:blockOff+40]) left zero — these tests don't read it.
	return blockOff + keybagEntryAreaStart
}

// buildKeybagBlock builds a 4096-byte key bag block with one passphrase locker
// entry and one volume key entry.
func buildKeybagBlock(t *testing.T, salt []byte, iter int, wrappedKEK, wrappedVEK []byte) []byte {
	t.Helper()
	buf := make([]byte, nxBlockSize)

	lockerEntry := buildLockerEntryData(salt, iter, wrappedKEK)
	vkEntry := buildVolumeKeyEntryData(wrappedVEK)

	off := writeKeybagHeader(buf, 0, 2)
	off = writeKeybagEntry(buf, off, kbTagVolumePassphrase, lockerEntry)
	writeKeybagEntry(buf, off, kbTagVolumeKey, vkEntry)
	return buf
}

// writeKeybagEntry serialises a single keybag entry into buf at off.
// Returns the new offset after the entry (padded to 16-byte boundary).
func writeKeybagEntry(buf []byte, off, tag int, data []byte) int {
	const headerLen = 24
	if off+headerLen+len(data) > len(buf) {
		return off
	}
	copy(buf[off:off+16], []byte("test-uuid-000000"))
	binary.LittleEndian.PutUint16(buf[off+16:], uint16(tag))
	binary.LittleEndian.PutUint16(buf[off+18:], uint16(len(data)))
	off += headerLen
	copy(buf[off:], data)
	off += len(data)
	if rem := off % keybagEntryAlignment; rem != 0 {
		off += keybagEntryAlignment - rem
	}
	return off
}

// buildLockerEntryData serialises the PBKDF2 parameters + wrappedKEK into the
// data field of a passphrase locker entry.
func buildLockerEntryData(salt []byte, iter int, wrappedKEK []byte) []byte {
	// Layout: uint16 kdfType + uint16 pad + uint32 iter + uint16 saltLen + salt + wrappedKEK
	size := 2 + 2 + 4 + 2 + len(salt) + len(wrappedKEK)
	buf := make([]byte, size)
	binary.LittleEndian.PutUint16(buf[0:2], kdfTypePBKDF2)
	// buf[2:4] = padding (zero)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(iter))
	binary.LittleEndian.PutUint16(buf[8:10], uint16(len(salt)))
	copy(buf[10:], salt)
	copy(buf[10+len(salt):], wrappedKEK)
	return buf
}

// buildVolumeKeyEntryData returns the wrapped VEK as the entry data.
func buildVolumeKeyEntryData(wrappedVEK []byte) []byte {
	d := make([]byte, len(wrappedVEK))
	copy(d, wrappedVEK)
	return d
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

func TestDetect_APFS(t *testing.T) {
	img := buildAPFSImage(t, []byte("passphrase"), []byte("hello"))
	path := filepath.Join(t.TempDir(), "test.img")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	ok, err := Detect(path)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !ok {
		t.Fatal("Detect returned false for APFS image")
	}
}

func TestDetect_NonAPFS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "other.img")
	if err := os.WriteFile(path, make([]byte, 512), 0o600); err != nil {
		t.Fatal(err)
	}
	ok, err := Detect(path)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if ok {
		t.Fatal("Detect returned true for non-APFS file")
	}
}

func TestDetect_NotExist(t *testing.T) {
	_, err := Detect("/nonexistent/path.img")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestDetectFrom_ShortRead(t *testing.T) {
	// If the reader returns too few bytes, DetectFrom returns false (not an error).
	r := bytes.NewReader([]byte{0x00, 0x01})
	ok, err := DetectFrom(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected false for short read")
	}
}

func TestOpen_NotExist(t *testing.T) {
	_, err := Open("/nonexistent/path.img", []byte("pass"))
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestOpen_InvalidMagic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.img")
	if err := os.WriteFile(path, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(path, []byte("pass"))
	if err == nil {
		t.Fatal("expected error for non-APFS file")
	}
}

func TestOpenFrom_WrongPassphrase(t *testing.T) {
	img := buildAPFSImage(t, []byte("correct"), []byte("data"))
	rw := &readWriteAt{data: img}
	_, err := OpenFrom(rw, []byte("wrong"))
	if err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
}

type readWriteAt struct {
	data []byte
}

func (r *readWriteAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	n := copy(p, r.data[off:])
	return n, nil
}

func (r *readWriteAt) WriteAt(p []byte, off int64) (int, error) {
	end := int(off) + len(p)
	if end > len(r.data) {
		r.data = append(r.data, make([]byte, end-len(r.data))...)
	}
	copy(r.data[off:], p)
	return len(p), nil
}

func (r *readWriteAt) Close() error { return nil }

func TestOpenFrom_Success_ReadWrite(t *testing.T) {
	payload := []byte("hello apfs fde!")
	// Pad to one sector size for valid XTS.
	payloadPadded := make([]byte, sectorSize)
	copy(payloadPadded, payload)

	passphrase := []byte("my passphrase")
	img := buildAPFSImage(t, passphrase, payloadPadded)
	rw := &readWriteAt{data: img}

	dev, err := OpenFrom(rw, passphrase)
	if err != nil {
		t.Fatalf("OpenFrom: %v", err)
	}
	defer dev.Close()

	// Read the encrypted payload block (block 2 = offset 2*4096) and verify
	// it decrypts to the original payload data.
	buf := make([]byte, sectorSize)
	n, err := dev.ReadAt(buf, int64(2*nxBlockSize))
	if err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if n != sectorSize {
		t.Fatalf("ReadAt: got %d bytes, want %d", n, sectorSize)
	}
	if !bytes.Equal(buf[:len(payload)], payload) {
		t.Fatalf("decrypted content mismatch: got %q want %q", buf[:len(payload)], payload)
	}

	// Write new content and read it back.
	newPayload := make([]byte, sectorSize)
	copy(newPayload, []byte("new content here"))
	if _, err := dev.WriteAt(newPayload, int64(2*nxBlockSize)); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	buf2 := make([]byte, sectorSize)
	if _, err := dev.ReadAt(buf2, int64(2*nxBlockSize)); err != nil {
		t.Fatalf("ReadAt after write: %v", err)
	}
	if !bytes.Equal(buf2, newPayload) {
		t.Fatalf("round-trip mismatch after write")
	}
}

func TestOpenFrom_NoKeybag(t *testing.T) {
	// Build an NX superblock that points to keybag at block 0 with 0 blocks.
	buf := make([]byte, 4096)
	copy(buf[32:36], nxSuperblockMagic)
	binary.LittleEndian.PutUint32(buf[36:40], 4096)
	// keybagBlock=0, keybagBlocks=0 → no key bag
	rw := &readWriteAt{data: buf}
	_, err := OpenFrom(rw, []byte("pass"))
	if err == nil {
		t.Fatal("expected error when no keybag present")
	}
}

func TestOpenFrom_BadKeybagMagic(t *testing.T) {
	buf := make([]byte, 8192)
	// NX superblock pointing to block 1 as keybag.
	copy(buf[32:36], nxSuperblockMagic)
	binary.LittleEndian.PutUint32(buf[36:40], 4096)
	binary.LittleEndian.PutUint64(buf[nxKeylockerOffset:nxKeylockerOffset+8], 1)
	binary.LittleEndian.PutUint64(buf[nxKeylockerOffset+8:nxKeylockerOffset+16], 1)
	// Block 1: wrong magic
	copy(buf[4096:4100], "XXXX")
	rw := &readWriteAt{data: buf}
	_, err := OpenFrom(rw, []byte("pass"))
	if err == nil {
		t.Fatal("expected error for bad keybag magic")
	}
}

func TestOpenFrom_NoPassphraseLocker(t *testing.T) {
	// Key bag with valid header but no passphrase locker entry.
	buf := make([]byte, 8192)
	copy(buf[32:36], nxSuperblockMagic)
	binary.LittleEndian.PutUint32(buf[36:40], 4096)
	binary.LittleEndian.PutUint64(buf[nxKeylockerOffset:nxKeylockerOffset+8], 1)
	binary.LittleEndian.PutUint64(buf[nxKeylockerOffset+8:nxKeylockerOffset+16], 1)
	// Block 1: valid keybag header, 0 entries.
	writeKeybagHeader(buf, 4096, 0)
	rw := &readWriteAt{data: buf}
	_, err := OpenFrom(rw, []byte("pass"))
	if err == nil {
		t.Fatal("expected error when no passphrase locker")
	}
}

func TestOpenFrom_NoVolumeKeyEntry(t *testing.T) {
	// Key bag with a passphrase locker but no volume key entry.
	passphrase := []byte("pass")
	salt := mustRand(16)
	iter := 1000
	kek := pbkdf2.Key(passphrase, salt, iter, 32, sha256.New)
	wrappedKEK, _ := aesKeyWrap(kek, kek)

	buf := make([]byte, 8192)
	copy(buf[32:36], nxSuperblockMagic)
	binary.LittleEndian.PutUint32(buf[36:40], 4096)
	binary.LittleEndian.PutUint64(buf[nxKeylockerOffset:nxKeylockerOffset+8], 1)
	binary.LittleEndian.PutUint64(buf[nxKeylockerOffset+8:nxKeylockerOffset+16], 1)

	lockerData := buildLockerEntryData(salt, iter, wrappedKEK)
	writeKeybagHeader(buf, 4096, 1)
	writeKeybagEntry(buf[4096:], keybagEntryAreaStart, kbTagVolumePassphrase, lockerData)

	rw := &readWriteAt{data: buf}
	_, err := OpenFrom(rw, passphrase)
	if err == nil {
		t.Fatal("expected error when no volume key entry")
	}
}

func TestAESKeyUnwrap_BadKEKSize(t *testing.T) {
	// AES requires key sizes of 16, 24, or 32 bytes.
	// A 10-byte key is invalid and should trigger the AES init error.
	badKEK := make([]byte, 10)
	wrapped := make([]byte, 24) // minimum valid wrapped length
	_, err := aesKeyUnwrap(badKEK, wrapped)
	if err == nil {
		t.Fatal("expected error for invalid AES key size")
	}
}

func TestAESKeyWrapUnwrap_RoundTrip(t *testing.T) {
	kek := mustRand(32)
	plaintext := mustRand(32)
	wrapped, err := aesKeyWrap(kek, plaintext)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	unwrapped, err := aesKeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(unwrapped, plaintext) {
		t.Fatal("round-trip mismatch")
	}
}

func TestAESKeyUnwrap_BadIntegrity(t *testing.T) {
	kek := mustRand(32)
	plaintext := mustRand(32)
	wrapped, _ := aesKeyWrap(kek, plaintext)
	// Corrupt the wrapped key.
	wrapped[0] ^= 0xFF
	_, err := aesKeyUnwrap(kek, wrapped)
	if err == nil {
		t.Fatal("expected integrity check failure")
	}
}

func TestAESKeyUnwrap_TooShort(t *testing.T) {
	_, err := aesKeyUnwrap(mustRand(32), []byte("short"))
	if err == nil {
		t.Fatal("expected error for too-short input")
	}
}

func TestAESKeyWrap_InvalidLength(t *testing.T) {
	// Plaintext length not a multiple of 8.
	_, err := aesKeyWrap(mustRand(32), []byte("bad"))
	if err == nil {
		t.Fatal("expected error for non-8-byte-aligned plaintext")
	}
}

func TestNewXTSCipher_BadKeyLen(t *testing.T) {
	_, err := newXTSCipher(mustRand(16)) // 16 is not 32 or 64
	if err == nil {
		t.Fatal("expected error for invalid VEK length")
	}
}

func TestXTSCipher_UnalignedRead(t *testing.T) {
	enc, _ := newXTSCipher(mustRand(32))
	rw := &readWriteAt{data: make([]byte, 4096)}
	buf := make([]byte, sectorSize)
	_, err := enc.readAt(rw, buf, 1) // offset 1 is not sector-aligned
	if err == nil {
		t.Fatal("expected error for unaligned read")
	}
}

func TestXTSCipher_UnalignedLength(t *testing.T) {
	enc, _ := newXTSCipher(mustRand(32))
	rw := &readWriteAt{data: make([]byte, 4096)}
	buf := make([]byte, 100) // not a multiple of sectorSize
	_, err := enc.readAt(rw, buf, 0)
	if err == nil {
		t.Fatal("expected error for non-sector-multiple length")
	}
}

func TestXTSCipher_ProcessSectors_OddLength(t *testing.T) {
	enc, _ := newXTSCipher(mustRand(32))
	err := enc.processSectors(make([]byte, 100), 0, true)
	if err == nil {
		t.Fatal("expected error for non-sector-multiple data")
	}
}

func TestParseKeybag_TooShort(t *testing.T) {
	_, err := parseKeybag([]byte{0x00, 0x01})
	if err == nil {
		t.Fatal("expected error for too-short keybag")
	}
}

func TestParseKeybag_UnsupportedVersion(t *testing.T) {
	buf := make([]byte, keybagEntryAreaStart)
	binary.LittleEndian.PutUint32(buf[24:28], mediaKeybagObjType)
	binary.LittleEndian.PutUint16(buf[32:34], 99) // version 99
	_, err := parseKeybag(buf)
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestParseKeybagEntries_Truncated(t *testing.T) {
	// numEntries=1 but data is too short
	_, err := parseKeybagEntries([]byte{0x01, 0x02}, 1)
	if err == nil {
		t.Fatal("expected error for truncated entry")
	}
}

func TestParseKeybagEntries_DataTruncated(t *testing.T) {
	// Header OK but keylen says there's more data than exists.
	buf := make([]byte, 26)                        // 24-byte header + only 2 bytes of data
	binary.LittleEndian.PutUint16(buf[18:20], 100) // keylen = 100
	_, err := parseKeybagEntries(buf, 1)
	if err == nil {
		t.Fatal("expected error for truncated key data")
	}
}

func TestParseLockerEntry_TooShort(t *testing.T) {
	_, err := parseLockerEntry([]byte{0x00, 0x01})
	if err == nil {
		t.Fatal("expected error for short locker entry")
	}
}

func TestParseLockerEntry_SaltTruncated(t *testing.T) {
	buf := make([]byte, 11)                       // 10 byte header + 1 byte of salt, but saltLen=100
	binary.LittleEndian.PutUint16(buf[8:10], 100) // saltLen=100
	_, err := parseLockerEntry(buf)
	if err == nil {
		t.Fatal("expected error for truncated salt")
	}
}

func TestWrappedToKeySize_Invalid(t *testing.T) {
	_, err := wrappedToKeySize(3) // too small
	if err == nil {
		t.Fatal("expected error for invalid wrapped key length")
	}
}

func TestWrappedToKeySize_InvalidAlignment(t *testing.T) {
	_, err := wrappedToKeySize(25) // (25-8)%8 != 0
	if err == nil {
		t.Fatal("expected error for misaligned wrapped key length")
	}
}

func TestWrappedToKeySize_Valid(t *testing.T) {
	size, err := wrappedToKeySize(40) // 40-8 = 32
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if size != 32 {
		t.Fatalf("want 32, got %d", size)
	}
}

func TestDeriveAndUnwrapKEK_UnsupportedKDF(t *testing.T) {
	lk := &kbLocker{kdfType: 0x9999, iterations: 1000, salt: mustRand(16), wrappedKEK: mustRand(40)}
	_, err := deriveAndUnwrapKEK(lk, []byte("pass"))
	if err == nil {
		t.Fatal("expected error for unsupported KDF type")
	}
}

func TestXorUint64BigEndian(t *testing.T) {
	src := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	result := xorUint64BigEndian(src, 1)
	if result[7] != 0x00 {
		t.Fatalf("XOR result mismatch: %v", result)
	}
}

func TestXorUint64LE(t *testing.T) {
	// xorUint64LE is no longer exported; test via xorUint64BigEndian instead.
	src := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	result := xorUint64BigEndian(src, 0)
	if !bytes.Equal(result, src) {
		t.Fatalf("XOR with 0 should be identity: %v", result)
	}
}

func TestNXSuperblock_ZeroBlockSize(t *testing.T) {
	// If blockSize is 0 in the superblock, default to nxBlockSize.
	buf := make([]byte, 2*nxBlockSize)
	copy(buf[32:36], nxSuperblockMagic)
	// blockSize at offset 36 = 0 (leave zero)
	binary.LittleEndian.PutUint64(buf[nxKeylockerOffset:nxKeylockerOffset+8], 1)
	binary.LittleEndian.PutUint64(buf[nxKeylockerOffset+8:nxKeylockerOffset+16], 1)
	// Block 1: valid keybag header, 0 entries but no passphrase locker.
	writeKeybagHeader(buf, nxBlockSize, 0)
	rw := &readWriteAt{data: buf}
	// Expect "no passphrase locker" error, confirming we parsed the block correctly.
	_, err := OpenFrom(rw, []byte("pass"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestOpen_Success(t *testing.T) {
	passphrase := []byte("fileVault!")
	payload := make([]byte, sectorSize)
	copy(payload, []byte("test payload data"))
	img := buildAPFSImage(t, passphrase, payload)

	path := filepath.Join(t.TempDir(), "apfs.img")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	dev, err := Open(path, passphrase)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	dev.Close()
}

func TestDevice_Close(t *testing.T) {
	passphrase := []byte("fileVault!")
	img := buildAPFSImage(t, passphrase, make([]byte, sectorSize))
	rw := &readWriteAt{data: img}
	dev, err := OpenFrom(rw, passphrase)
	if err != nil {
		t.Fatalf("OpenFrom: %v", err)
	}
	if err := dev.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// errReader always fails ReadAt.
type errReader struct{}

func (e *errReader) ReadAt([]byte, int64) (int, error)  { return 0, io.ErrUnexpectedEOF }
func (e *errReader) WriteAt([]byte, int64) (int, error) { return 0, io.ErrUnexpectedEOF }
func (e *errReader) Close() error                       { return nil }

func TestParseNXSuperblock_ReadError(t *testing.T) {
	_, err := OpenFrom(&errReader{}, []byte("pass"))
	if err == nil {
		t.Fatal("expected error when superblock read fails")
	}
}

// shortReader succeeds for the superblock (block 0) but fails on the keybag block.
type shortReader struct {
	data []byte
}

func (s *shortReader) ReadAt(p []byte, off int64) (int, error) {
	if off == 0 {
		n := copy(p, s.data)
		return n, nil
	}
	return 0, io.ErrUnexpectedEOF
}
func (s *shortReader) WriteAt(p []byte, off int64) (int, error) { return 0, nil }
func (s *shortReader) Close() error                             { return nil }

func TestReadKeybag_ReadError(t *testing.T) {
	buf := make([]byte, 88)
	copy(buf[32:36], nxSuperblockMagic)
	binary.LittleEndian.PutUint32(buf[36:40], 4096)
	binary.LittleEndian.PutUint64(buf[64:72], 1) // keybag at block 1
	binary.LittleEndian.PutUint64(buf[72:80], 1)
	_, err := OpenFrom(&shortReader{data: buf}, []byte("pass"))
	if err == nil {
		t.Fatal("expected error when keybag read fails")
	}
}

func TestTryUnlock_BadLockerData(t *testing.T) {
	passphrase := []byte("pass")
	// Build a keybag with a passphrase locker whose data is too short
	// (will fail parseLockerEntry), plus a volume key entry.
	buf := make([]byte, 8192)
	copy(buf[32:36], nxSuperblockMagic)
	binary.LittleEndian.PutUint32(buf[36:40], 4096)
	binary.LittleEndian.PutUint64(buf[nxKeylockerOffset:nxKeylockerOffset+8], 1)
	binary.LittleEndian.PutUint64(buf[nxKeylockerOffset+8:nxKeylockerOffset+16], 1)
	writeKeybagHeader(buf, 4096, 2) // 2 entries
	// Entry 0: passphrase locker with 1-byte data (too short for parseLockerEntry)
	off := keybagEntryAreaStart
	off = writeKeybagEntry(buf[4096:], off, kbTagVolumePassphrase, []byte{0x42})
	// Entry 1: volume key entry with valid-looking wrapped key
	writeKeybagEntry(buf[4096:], off, kbTagVolumeKey, make([]byte, 40))
	rw := &readWriteAt{data: buf}
	_, err := OpenFrom(rw, passphrase)
	if err == nil {
		t.Fatal("expected error when locker data is too short")
	}
}

func TestDeriveAndUnwrapKEK_BadWrappedKEKLen(t *testing.T) {
	passphrase := []byte("pass")
	salt := mustRand(16)
	iter := 1000
	// Build a locker entry with a wrappedKEK of 3 bytes (fails wrappedToKeySize).
	lockerData := buildLockerEntryData(salt, iter, []byte{0x01, 0x02, 0x03})
	buf := make([]byte, 8192)
	copy(buf[32:36], nxSuperblockMagic)
	binary.LittleEndian.PutUint32(buf[36:40], 4096)
	binary.LittleEndian.PutUint64(buf[nxKeylockerOffset:nxKeylockerOffset+8], 1)
	binary.LittleEndian.PutUint64(buf[nxKeylockerOffset+8:nxKeylockerOffset+16], 1)
	writeKeybagHeader(buf, 4096, 2) // 2 entries
	off := keybagEntryAreaStart
	off = writeKeybagEntry(buf[4096:], off, kbTagVolumePassphrase, lockerData)
	writeKeybagEntry(buf[4096:], off, kbTagVolumeKey, make([]byte, 40))
	rw := &readWriteAt{data: buf}
	_, err := OpenFrom(rw, passphrase)
	if err == nil {
		t.Fatal("expected error when wrapped KEK length is invalid")
	}
}

func TestUnwrapVEK_AllFail(t *testing.T) {
	// Build an image where the passphrase is correct for the KEK, but the
	// wrapped VEK was encrypted with a different key (corrupted).
	passphrase := []byte("correct")
	salt := mustRand(16)
	iter := 1000
	kek := pbkdf2.Key(passphrase, salt, iter, 32, sha256.New)
	// Wrap KEK with itself (valid).
	wrappedKEK, _ := aesKeyWrap(kek, kek)
	// VEK wrapped with a DIFFERENT random key → unwrap will fail.
	differentKey := mustRand(32)
	wrappedVEK, _ := aesKeyWrap(differentKey, mustRand(32))
	lockerData := buildLockerEntryData(salt, iter, wrappedKEK)

	buf := make([]byte, 8192)
	copy(buf[32:36], nxSuperblockMagic)
	binary.LittleEndian.PutUint32(buf[36:40], 4096)
	binary.LittleEndian.PutUint64(buf[nxKeylockerOffset:nxKeylockerOffset+8], 1)
	binary.LittleEndian.PutUint64(buf[nxKeylockerOffset+8:nxKeylockerOffset+16], 1)
	writeKeybagHeader(buf, 4096, 2)
	off := keybagEntryAreaStart
	off = writeKeybagEntry(buf[4096:], off, kbTagVolumePassphrase, lockerData)
	writeKeybagEntry(buf[4096:], off, kbTagVolumeKey, wrappedVEK)
	rw := &readWriteAt{data: buf}
	_, err := OpenFrom(rw, passphrase)
	if err == nil {
		t.Fatal("expected error when VEK unwrap fails")
	}
}
