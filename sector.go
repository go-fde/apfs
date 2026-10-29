package apfs

import (
	"crypto/aes"
	"errors"
	"fmt"
	"io"

	"github.com/go-encryptions/xts"
)

// SectorSize is the AES-XTS data-unit size APFS software encryption uses:
// 512 bytes, whatever the container block size. A block of B bytes at
// physical address paddr is B/512 consecutive data units whose tweaks start
// at paddr*(B/512) (apfs-fuse ApfsVolume::ReadBlocks, cs_factor).
const SectorSize = sectorSize

// ErrWrongPassphrase is returned when at least one passphrase locker was
// tried and none of them unwrapped with the passphrase given. It is distinct
// from ErrLimit (a locker the Limits refused before running its KDF) and from
// structural errors (no keybag, a malformed one).
var ErrWrongPassphrase = errors.New("apfs: wrong passphrase")

// SectorCipher is AES-XTS over 512-byte data units with an explicit 64-bit
// data-unit number as the tweak. It is what a reader needs to decrypt only
// the blocks APFS encrypts -- file-system tree nodes whose object-map entry
// carries OMAP_VAL_ENCRYPTED, and file extents (tweak base = crypto_id) --
// while reading the plaintext container metadata raw, which a Device (that
// decrypts every byte) cannot do.
//
// A SectorCipher is safe for concurrent use.
type SectorCipher struct {
	c *xts.Cipher
}

// NewSectorCipher returns a SectorCipher keyed with vek: 32 bytes for
// AES-128-XTS (key1 = vek[:16], key2 = vek[16:]) or 64 for AES-256-XTS.
func NewSectorCipher(vek []byte) (*SectorCipher, error) {
	if len(vek) != 32 && len(vek) != 64 {
		return nil, fmt.Errorf("apfs: sector cipher: VEK must be 32 or 64 bytes, got %d", len(vek))
	}
	c, err := xts.NewCipher(aes.NewCipher, vek)
	if err != nil {
		return nil, fmt.Errorf("apfs: sector cipher: %w", err)
	}
	return &SectorCipher{c: c}, nil
}

// Decrypt decrypts p in place. p must be a whole number of 512-byte data
// units; p[0:512] uses tweak first, the next unit first+1, and so on. The
// unit number wraps modulo 2^64 like the uint64 it is on disk.
func (s *SectorCipher) Decrypt(p []byte, first uint64) error {
	return cryptSectors(s.c, p, first, false)
}

// Encrypt is the inverse of Decrypt.
func (s *SectorCipher) Encrypt(p []byte, first uint64) error {
	return cryptSectors(s.c, p, first, true)
}

// cryptSectors is the one XTS loop of the package: Device, SectorCipher and
// the keybag at-rest layer all go through it.
func cryptSectors(c *xts.Cipher, p []byte, first uint64, encrypt bool) error {
	if len(p)%sectorSize != 0 {
		return fmt.Errorf("apfs: cipher: data length %d is not a multiple of sector size %d", len(p), sectorSize)
	}
	n := first
	for i := 0; i < len(p); i += sectorSize {
		u := p[i : i+sectorSize]
		if encrypt {
			c.Encrypt(u, u, n)
		} else {
			c.Decrypt(u, u, n)
		}
		n++
	}
	return nil
}

// VolumeKey is what UnlockVolumeKey recovers: the volume encryption key and
// the UUID of the volume it belongs to (from the container keybag). The UUID
// is zero for the legacy keybag shape this package's Format writes, which
// does not name a volume.
type VolumeKey struct {
	VEK        []byte
	VolumeUUID [16]byte
}

// UnlockVolumeKey walks the keybags of the container in r (container keybag
// -> volume keybag -> KEK -> VEK, Apple File System Reference, "Accessing
// Encrypted Objects") with passphrase and returns the volume key, without
// wrapping r in a Device. lim bounds the key derivation a keybag can ask for.
//
// Errors: ErrLimit (wrapped) when a locker asks for more than lim allows and
// none opened; ErrWrongPassphrase (wrapped) when lockers were tried and none
// opened; anything else is a structural error in the image.
func UnlockVolumeKey(r io.ReaderAt, passphrase []byte, lim Limits) (VolumeKey, error) {
	return unlockVolumeKey(r, passphrase, lim)
}
