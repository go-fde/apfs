package apfs

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"

	"github.com/go-encryptions/xts"
)

// xtscipher implements AES-XTS block encryption/decryption as used by APFS.
// The XTS tweak is the sector number (byte offset / sectorSize).
type xtscipher struct {
	enc        *xts.Cipher
	sectorSize int
}

// newXTSCipher creates an AES-XTS cipher from a VEK.
// vek must be 32 bytes (AES-128-XTS) or 64 bytes (AES-256-XTS).
func newXTSCipher(vek []byte) (*xtscipher, error) {
	if len(vek) != 32 && len(vek) != 64 {
		return nil, fmt.Errorf("apfs: cipher: VEK must be 32 or 64 bytes, got %d", len(vek))
	}
	// xts.NewCipher cannot fail when key is exactly 32 or 64 bytes.
	c, _ := xts.NewCipher(aes.NewCipher, vek)
	return &xtscipher{enc: c, sectorSize: sectorSize}, nil
}

// newAESBlock creates an AES block cipher. Centralised to allow testing.
func newAESBlock(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}

// readAt reads and decrypts data from rw into p.
func (x *xtscipher) readAt(rw io.ReaderAt, p []byte, off int64) (int, error) {
	n, err := readAligned(rw, p, off, x.sectorSize)
	if err != nil {
		return n, err
	}
	// A short read (n < len(p)) can leave a partial sector; refuse to
	// decrypt it rather than hand back half-processed data.
	if err := x.processSectors(p[:n], off, false); err != nil {
		return 0, err
	}
	return n, nil
}

// checkAligned refuses an access that is not whole sectors at a sector
// boundary: XTS works on whole sectors, and a partial one would either be
// stored unencrypted or under the wrong tweak.
func checkAligned(n int, off int64, sectorSize int) error {
	switch {
	case off < 0:
		return fmt.Errorf("apfs: negative offset %d", off)
	case off%int64(sectorSize) != 0:
		return fmt.Errorf("apfs: unaligned offset %d (sector size %d)", off, sectorSize)
	case n%sectorSize != 0:
		return fmt.Errorf("apfs: length %d is not a multiple of sector size %d", n, sectorSize)
	}
	return nil
}

// writeAt encrypts p and writes it to rw. It refuses, before writing
// anything, a p whose length or an off that is not a sector multiple, and it
// never writes when encryption fails.
func (x *xtscipher) writeAt(rw interface {
	WriteAt([]byte, int64) (int, error)
}, p []byte, off int64) (int, error) {
	if err := checkAligned(len(p), off, x.sectorSize); err != nil {
		return 0, err
	}
	encrypted := make([]byte, len(p))
	copy(encrypted, p)
	if err := x.processSectors(encrypted, off, true); err != nil {
		return 0, err
	}
	return rw.WriteAt(encrypted, off)
}

// processSectors encrypts or decrypts p in-place, sector by sector.
// off is the byte offset of p[0] in the underlying device.
func (x *xtscipher) processSectors(p []byte, off int64, encrypt bool) error {
	return cryptSectors(x.enc, p, uint64(off/int64(x.sectorSize)), encrypt)
}

// readAligned reads from rw into p, ensuring the access is sector-aligned.
// If off is not sector-aligned, it returns an error because XTS requires
// sector-aligned reads.
func readAligned(rw io.ReaderAt, p []byte, off int64, sectorSize int) (int, error) {
	if err := checkAligned(len(p), off, sectorSize); err != nil {
		return 0, err
	}
	return rw.ReadAt(p, off)
}
