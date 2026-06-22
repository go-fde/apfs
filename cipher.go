package apfs

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"

	"github.com/go-fde/apfs/internal/xts"
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
	// processSectors cannot fail here because readAligned already verified
	// alignment and sector-multiple length.
	_ = x.processSectors(p[:n], off, false)
	return n, nil
}

// writeAt encrypts p and writes it to rw.
// p must be sector-aligned in length and off must be a sector boundary;
// these preconditions are enforced by the public WriteAt method.
func (x *xtscipher) writeAt(rw interface {
	WriteAt([]byte, int64) (int, error)
}, p []byte, off int64) (int, error) {
	encrypted := make([]byte, len(p))
	copy(encrypted, p)
	// processSectors cannot fail here because the public WriteAt validates
	// alignment before calling writeAt.
	_ = x.processSectors(encrypted, off, true)
	return rw.WriteAt(encrypted, off)
}

// processSectors encrypts or decrypts p in-place, sector by sector.
// off is the byte offset of p[0] in the underlying device.
func (x *xtscipher) processSectors(p []byte, off int64, encrypt bool) error {
	if len(p)%x.sectorSize != 0 {
		return fmt.Errorf("apfs: cipher: data length %d is not a multiple of sector size %d", len(p), x.sectorSize)
	}
	sectorNum := uint64(off / int64(x.sectorSize))
	for i := 0; i < len(p); i += x.sectorSize {
		sector := p[i : i+x.sectorSize]
		if encrypt {
			x.enc.Encrypt(sector, sector, sectorNum)
		} else {
			x.enc.Decrypt(sector, sector, sectorNum)
		}
		sectorNum++
	}
	return nil
}

// readAligned reads from rw into p, ensuring the access is sector-aligned.
// If off is not sector-aligned, it returns an error because XTS requires
// sector-aligned reads.
func readAligned(rw io.ReaderAt, p []byte, off int64, sectorSize int) (int, error) {
	if off%int64(sectorSize) != 0 {
		return 0, fmt.Errorf("apfs: unaligned read at offset %d (sector size %d)", off, sectorSize)
	}
	if len(p)%sectorSize != 0 {
		return 0, fmt.Errorf("apfs: read length %d is not a multiple of sector size %d", len(p), sectorSize)
	}
	return rw.ReadAt(p, off)
}
