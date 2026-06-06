// Package apfs provides pure-Go support for APFS FileVault 2 full-disk
// encryption (FDE). It implements the APFS key bag format and AES-XTS
// block-level decryption as documented in the Apple File System Reference.
//
// # Overview
//
// APFS FileVault 2 encrypts each block of a volume using AES-XTS with a
// Volume Encryption Key (VEK). The VEK is stored encrypted inside a Key
// Encryption Key (KEK), which in turn is wrapped using AES key-wrap (RFC 3394)
// with a key derived from the user's passphrase via PBKDF2-SHA256.
//
// This package reads the APFS container key bag, locates the matching
// passphrase key-bag entry, unwraps the KEK and then the VEK, and exposes a
// [Device] that transparently decrypts blocks on ReadAt and encrypts on
// WriteAt.
//
// # Usage
//
//	dev, err := apfs.Open("/dev/disk2s1", []byte("my passphrase"))
//	if err != nil { log.Fatal(err) }
//	defer dev.Close()
//
//	// ReadAt / WriteAt offsets are block-absolute (relative to offset 0 of the
//	// underlying device, not the payload start).
//	buf := make([]byte, 4096)
//	_, err = dev.ReadAt(buf, 0)
//
// # Supported ciphers
//
//   - AES-128-XTS (128-bit VEK, used when key_size = 16)
//   - AES-256-XTS (256-bit VEK, used when key_size = 32)
//
// Both use the block's absolute sector index (offset / 512) as the XTS tweak.
//
// # Supported unlock paths
//
//   - PBKDF2-SHA256 passphrase locker (the default, see Format).
//   - Argon2id passphrase locker (see FormatArgon2id, AddArgon2idPassphrase).
//   - Personal Recovery Key (see AddRecoveryKey; unlock with Open using the
//     recovery key as the passphrase).
//   - Institutional Recovery Key with RSA-OAEP wrapping (see
//     AddInstitutionalKey, OpenWithPrivateKey).
//
// # Limitations
//
//   - Read-only iSCSI / remote devices: only ReadAt is guaranteed stable.
//   - T2 / Secure Enclave mediated keys require hardware access.
//   - Argon2id and IRK locker layouts are package-defined; Apple does not
//     publicly document on-disk formats for them, so containers produced by
//     this package using those mechanisms are not interoperable with macOS.
package apfs

import (
	"fmt"
	"io"
	"os"
)

// blockRW is the minimal interface required from an underlying block device.
type blockRW interface {
	io.ReaderAt
	WriteAt([]byte, int64) (int, error)
	io.Closer
}

// Device is an unlocked APFS encrypted device. Its ReadAt and WriteAt methods
// transparently decrypt / encrypt blocks using the Volume Encryption Key.
type Device struct {
	f   blockRW
	enc *xtscipher
}

// Open opens the APFS encrypted volume at path and unlocks it using passphrase.
// The path may be a raw disk device or an image file.
func Open(path string, passphrase []byte) (*Device, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("apfs: open %s: %w", path, err)
	}
	dev, err := openDevice(f, passphrase)
	if err != nil {
		f.Close()
		return nil, err
	}
	return dev, nil
}

// OpenFrom unlocks an APFS encrypted volume from any read-write-closable block
// device. This allows the package to be layered on top of, e.g., a QCOW2
// device. Close on the returned Device also closes rw.
func OpenFrom(rw blockRW, passphrase []byte) (*Device, error) {
	return openDevice(rw, passphrase)
}

// openDevice is the shared implementation for Open and OpenFrom.
func openDevice(rw blockRW, passphrase []byte) (*Device, error) {
	vek, err := unlockVEK(rw, passphrase)
	if err != nil {
		return nil, err
	}
	// newXTSCipher cannot fail here because unlockVEK always returns a 32- or
	// 64-byte key after successful key unwrapping.
	enc, _ := newXTSCipher(vek)
	return &Device{f: rw, enc: enc}, nil
}

// Detect reports whether the data at path looks like an APFS container.
// It checks for the APFS container superblock magic "NXSB".
func Detect(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	return detectFrom(f)
}

// DetectFrom reports whether rw looks like an APFS container by checking the
// NX superblock magic at offset 32 of block 0.
func DetectFrom(rw io.ReaderAt) (bool, error) {
	return detectFrom(rw)
}

// detectFrom is the shared implementation for Detect and DetectFrom.
func detectFrom(r io.ReaderAt) (bool, error) {
	buf := make([]byte, 4)
	if _, err := r.ReadAt(buf, 32); err != nil {
		return false, nil
	}
	return string(buf) == nxSuperblockMagic, nil
}

// ReadAt reads data from the underlying device starting at byte offset off.
// If the volume is encrypted, the data is decrypted before being returned.
// The offset is absolute (relative to the start of the device).
func (d *Device) ReadAt(p []byte, off int64) (int, error) {
	return d.enc.readAt(d.f, p, off)
}

// WriteAt encrypts p and writes it to the underlying device at byte offset off.
// The offset is absolute (relative to the start of the device).
func (d *Device) WriteAt(p []byte, off int64) (int, error) {
	return d.enc.writeAt(d.f, p, off)
}

// Close releases the underlying file or device.
func (d *Device) Close() error {
	return d.f.Close()
}
