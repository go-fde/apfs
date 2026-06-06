package apfs

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// argon2idKey is a thin wrapper over golang.org/x/crypto/argon2.IDKey to keep
// callers in this file free of direct argon2 imports.
func argon2idKey(passphrase, salt []byte, t, m uint32, par uint16, keyLen int) []byte {
	return argon2.IDKey(passphrase, salt, t, m, uint8(par), uint32(keyLen))
}

// wrapKEKWithPBKDF2 derives a PBKDF2-SHA256 key and uses it to AES-KW-wrap
// the supplied KEK. Mirrors wrapKEKWithArgon2id for symmetry.
func wrapKEKWithPBKDF2(passphrase, kek, salt []byte, iterations int) ([]byte, error) {
	derived := pbkdf2.Key(passphrase, salt, iterations, formatKEKSize, sha256.New)
	wrapped, err := aesKeyWrap(derived, kek)
	if err != nil {
		return nil, fmt.Errorf("apfs: pbkdf2 wrap kek: %w", err)
	}
	return wrapped, nil
}

// osOpenFile opens path in read-write mode and returns it as a blockRW. It is
// the only place we touch *os.File for the new APIs so tests can substitute
// osOpenRW (which defaults to this).
func osOpenFile(path string) (blockRW, error) {
	return os.OpenFile(path, os.O_RDWR, 0o600)
}

// recoveryKeyUUID is the UUID this package stamps on Personal Recovery Key
// (PRK) lockers. Apple uses a well-known UUID for the recovery user on
// HFS+ FileVault; APFS does not publicly document a single UUID, so this
// package adopts a fixed value to mark PRK lockers and distinguish them from
// regular passphrase lockers when iterating the keybag.
var recoveryKeyUUID = [16]byte{
	0xEB, 0xC6, 0xC0, 0x64, 0x00, 0x00, 0x11, 0xAA,
	0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC,
}

// IsRecoveryKeyUUID reports whether u matches the well-known PRK UUID stamped
// by this package on Personal Recovery Key keybag entries.
func IsRecoveryKeyUUID(u [16]byte) bool { return u == recoveryKeyUUID }

// Argon2id default parameters used by AddArgon2idPassphrase / FormatArgon2id
// when the caller does not override them. They target ~50 MiB and a few
// hundred ms on a contemporary CPU; tune to your threat model.
const (
	defaultArgon2idTime    = uint32(2)
	defaultArgon2idMemKiB  = uint32(64 * 1024)
	defaultArgon2idThreads = uint16(2)
)

// Argon2idParams selects time/memory/parallelism for an Argon2id locker.
// Zero fields fall back to the defaults above.
type Argon2idParams struct {
	TimeCost    uint32
	MemoryKiB   uint32
	Parallelism uint16
}

func (p Argon2idParams) resolve() (uint32, uint32, uint16) {
	t, m, par := p.TimeCost, p.MemoryKiB, p.Parallelism
	if t == 0 {
		t = defaultArgon2idTime
	}
	if m == 0 {
		m = defaultArgon2idMemKiB
	}
	if par == 0 {
		par = defaultArgon2idThreads
	}
	return t, m, par
}

// FormatArgon2id is the Argon2id-protected counterpart of Format. The key bag
// will contain a single Argon2id locker (kdfType = 0x0001) protecting the
// container's KEK.
func FormatArgon2id(path string, passphrase []byte, params Argon2idParams) (*Device, error) {
	return formatPath(path, func(rw blockRW) (*Device, error) {
		return FormatArgon2idOn(rw, passphrase, params)
	})
}

// FormatArgon2idOn is the FormatOn equivalent for Argon2id-protected containers.
func FormatArgon2idOn(rw blockRW, passphrase []byte, params Argon2idParams) (*Device, error) {
	vek := apfsRandBytes(formatVEKSize)
	kek := apfsRandBytes(formatKEKSize)
	salt := apfsRandBytes(formatSaltLen)
	t, m, par := params.resolve()
	wrappedKEK, err := wrapKEKWithArgon2id(passphrase, kek, salt, t, m, par)
	if err != nil {
		return nil, err
	}
	wrappedVEK, err := aesKeyWrap(kek, vek)
	if err != nil {
		return nil, fmt.Errorf("apfs: argon2id format: wrap vek: %w", err)
	}
	if _, err := rw.WriteAt(nxSuperblockBytes(), 0); err != nil {
		return nil, fmt.Errorf("apfs: argon2id format: write superblock: %w", err)
	}
	kbBlock := packKeybagBlock([]rawEntry{
		{tag: kbTagVolumePassphrase, data: encodeArgon2idLocker(t, m, par, salt, wrappedKEK)},
		{tag: kbTagVolumeKey, data: wrappedVEK},
	})
	if _, err := rw.WriteAt(kbBlock, int64(nxBlockSize)); err != nil {
		return nil, fmt.Errorf("apfs: argon2id format: write keybag: %w", err)
	}
	enc, _ := newXTSCipher(vek)
	return &Device{f: rw, enc: enc}, nil
}

// wrapKEKWithArgon2id derives an Argon2id key from passphrase+salt and uses
// it to AES-KW-wrap the supplied KEK.
func wrapKEKWithArgon2id(passphrase, kek, salt []byte, t, m uint32, par uint16) ([]byte, error) {
	derived := argon2idKey(passphrase, salt, t, m, par, formatKEKSize)
	wrapped, err := aesKeyWrap(derived, kek)
	if err != nil {
		return nil, fmt.Errorf("apfs: argon2id wrap kek: %w", err)
	}
	return wrapped, nil
}

// AddRecoveryKey rewrites the keybag of an existing container to add a
// Personal Recovery Key (PRK) locker. unlock recovers the master KEK with the
// supplied existingPassphrase (or recovery key) and re-wraps the same KEK
// under the new recoveryKey using PBKDF2-SHA256. The PRK locker is tagged
// with the well-known recoveryKeyUUID so callers can distinguish it.
func AddRecoveryKey(rw blockRW, existingPassphrase, recoveryKey []byte) error {
	return addPassphraseLocker(rw, existingPassphrase, recoveryKey, recoveryKeyUUID, kdfTypePBKDF2, Argon2idParams{})
}

// AddPassphrase rewrites the keybag to add an additional regular passphrase
// locker (PBKDF2). Useful when a container needs more than one passphrase to
// unlock — for example a personal one and a shared one.
func AddPassphrase(rw blockRW, existingPassphrase, newPassphrase []byte) error {
	var zero [16]byte
	return addPassphraseLocker(rw, existingPassphrase, newPassphrase, zero, kdfTypePBKDF2, Argon2idParams{})
}

// AddArgon2idPassphrase rewrites the keybag to add an additional passphrase
// locker that uses Argon2id (kdfType = 0x0001) for key derivation.
func AddArgon2idPassphrase(rw blockRW, existingPassphrase, newPassphrase []byte, params Argon2idParams) error {
	var zero [16]byte
	return addPassphraseLocker(rw, existingPassphrase, newPassphrase, zero, kdfTypeArgon2id, params)
}

// addPassphraseLocker is the shared implementation that recovers the KEK with
// existingPassphrase and writes a new locker (PBKDF2 or Argon2id) under
// newPassphrase, tagged with the supplied UUID.
func addPassphraseLocker(rw blockRW, existingPassphrase, newPassphrase []byte, uuid [16]byte, kdfType uint16, params Argon2idParams) error {
	kek, vekKBE, sb, kbData, err := recoverKEKAndKeybag(rw, existingPassphrase)
	if err != nil {
		return err
	}
	salt := apfsRandBytes(formatSaltLen)
	var lockerData []byte
	switch kdfType {
	case kdfTypePBKDF2:
		wrapped, werr := wrapKEKWithPBKDF2(newPassphrase, kek, salt, formatIterations)
		if werr != nil {
			return werr
		}
		lockerData = encodePBKDF2Locker(formatIterations, salt, wrapped)
	case kdfTypeArgon2id:
		t, m, par := params.resolve()
		wrapped, werr := wrapKEKWithArgon2id(newPassphrase, kek, salt, t, m, par)
		if werr != nil {
			return werr
		}
		lockerData = encodeArgon2idLocker(t, m, par, salt, wrapped)
	default:
		return fmt.Errorf("apfs: add locker: unsupported kdfType 0x%04x", kdfType)
	}
	newEntry := rawEntry{uuid: uuid, tag: kbTagVolumePassphrase, data: lockerData}
	return rewriteKeybagAppending(rw, sb, kbData, vekKBE, newEntry)
}

// AddInstitutionalKey rewrites the keybag to add an Institutional Recovery
// Key locker. existingPassphrase recovers the KEK and pub is used to RSA-OAEP
// encrypt the KEK. The entry UUID is the SHA-256 fingerprint of the public
// key DER (truncated to 16 bytes) so multiple IRKs can coexist without
// collision.
func AddInstitutionalKey(rw blockRW, existingPassphrase []byte, pub *rsa.PublicKey) error {
	if pub == nil {
		return fmt.Errorf("apfs: institutional key: nil public key")
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("apfs: institutional key: marshal public key: %w", err)
	}
	fingerprint := sha256.Sum256(pubDER)
	kek, vekKBE, sb, kbData, err := recoverKEKAndKeybag(rw, existingPassphrase)
	if err != nil {
		return err
	}
	encKEK, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, kek, nil)
	if err != nil {
		return fmt.Errorf("apfs: institutional key: rsa encrypt: %w", err)
	}
	payload := make([]byte, 32+len(encKEK))
	copy(payload[:32], fingerprint[:])
	copy(payload[32:], encKEK)
	var uuid [16]byte
	copy(uuid[:], fingerprint[:16])
	newEntry := rawEntry{uuid: uuid, tag: kbTagInstitutionalKey, data: payload}
	return rewriteKeybagAppending(rw, sb, kbData, vekKBE, newEntry)
}

// OpenWithPrivateKey opens an APFS FDE container at path and unlocks it using
// the supplied RSA private key against any institutional recovery key locker
// it carries.
func OpenWithPrivateKey(path string, priv *rsa.PrivateKey) (*Device, error) {
	return openPath(path, func(rw blockRW) (*Device, error) {
		return OpenFromWithPrivateKey(rw, priv)
	})
}

// OpenFromWithPrivateKey is the OpenFrom equivalent for IRK unlock.
func OpenFromWithPrivateKey(rw blockRW, priv *rsa.PrivateKey) (*Device, error) {
	if priv == nil {
		return nil, fmt.Errorf("apfs: institutional key: nil private key")
	}
	sb, err := parseNXSuperblock(rw)
	if err != nil {
		return nil, err
	}
	kbData, err := readKeybag(rw, sb)
	if err != nil {
		return nil, err
	}
	entries, err := parseKeybag(kbData)
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("apfs: institutional key: marshal public key: %w", err)
	}
	fingerprint := sha256.Sum256(pubDER)
	for _, e := range entries {
		if e.tag != kbTagInstitutionalKey || len(e.data) < 32 {
			continue
		}
		if !bytes.Equal(e.data[:32], fingerprint[:]) {
			continue
		}
		kek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, e.data[32:], nil)
		if err != nil {
			return nil, fmt.Errorf("apfs: institutional key: rsa decrypt: %w", err)
		}
		vek, err := unwrapVEK(findVolumeKeyEntries(entries), kek)
		if err != nil {
			return nil, err
		}
		enc, _ := newXTSCipher(vek)
		return &Device{f: rw, enc: enc}, nil
	}
	return nil, fmt.Errorf("apfs: no institutional recovery key entry matches the supplied private key")
}

// recoverKEKAndKeybag opens rw, walks the keybag, and uses passphrase to
// recover the master KEK. It returns the KEK plus the keybag entries that
// must be preserved when rewriting (the volume-key entry plus the raw keybag
// bytes for re-emission).
func recoverKEKAndKeybag(rw blockRW, passphrase []byte) ([]byte, keybagEntry, *nxSuperblock, []byte, error) {
	sb, err := parseNXSuperblock(rw)
	if err != nil {
		return nil, keybagEntry{}, nil, nil, err
	}
	kbData, err := readKeybag(rw, sb)
	if err != nil {
		return nil, keybagEntry{}, nil, nil, err
	}
	entries, err := parseKeybag(kbData)
	if err != nil {
		return nil, keybagEntry{}, nil, nil, err
	}
	vkEntries := findVolumeKeyEntries(entries)
	if len(vkEntries) == 0 {
		return nil, keybagEntry{}, nil, nil, fmt.Errorf("apfs: rewrite keybag: no volume-key entry")
	}
	for _, locker := range findPassphraseLockers(entries) {
		lk, err := parseLockerEntry(locker.data)
		if err != nil {
			continue
		}
		kek, err := deriveAndUnwrapKEK(lk, passphrase)
		if err != nil {
			continue
		}
		// Confirm KEK unwraps the VEK (defence in depth).
		if _, err := unwrapVEK(vkEntries, kek); err != nil {
			continue
		}
		return kek, vkEntries[0], sb, kbData, nil
	}
	return nil, keybagEntry{}, nil, nil, fmt.Errorf("apfs: rewrite keybag: passphrase did not unlock any locker")
}

// rewriteKeybagAppending preserves every existing entry and appends newEntry
// at the end, then writes the recomposed keybag back at the same on-disk
// location. It only touches the keybag block(s); the NX superblock is left
// alone.
func rewriteKeybagAppending(rw blockRW, sb *nxSuperblock, kbData []byte, _ keybagEntry, newEntry rawEntry) error {
	existing, err := parseKeybag(kbData)
	if err != nil {
		return err
	}
	rebuilt := make([]rawEntry, 0, len(existing)+1)
	for _, e := range existing {
		rebuilt = append(rebuilt, rawEntry{uuid: e.uuid, tag: e.tag, data: e.data})
	}
	rebuilt = append(rebuilt, newEntry)
	if err := writeKeybagBlocks(rw, sb, rebuilt); err != nil {
		return err
	}
	return nil
}

// writeKeybagBlocks serialises entries into one or more contiguous keybag
// blocks at the location declared by sb. It refuses to expand the on-disk
// extent: if the new entry list does not fit, the caller must allocate more
// blocks first (out of scope for this initial PRK/IRK implementation).
func writeKeybagBlocks(rw blockRW, sb *nxSuperblock, entries []rawEntry) error {
	if sb.keybagBlocks == 0 {
		return fmt.Errorf("apfs: keybag extent has zero blocks")
	}
	blockSize := int(sb.blockSize)
	if blockSize == 0 {
		blockSize = nxBlockSize
	}
	totalBytes := int(sb.keybagBlocks) * blockSize
	out := make([]byte, totalBytes)
	// obj_phys.type at +24 (cksum/oid/xid/subtype left zero — at-rest
	// encryption + Fletcher-64 checksum are the layer above, still WIP).
	binary.LittleEndian.PutUint32(out[24:28], mediaKeybagObjType)
	// apfs_kb_locker header at +32: version(2) + nkeys(2) + nbytes(4) + 8-byte pad.
	binary.LittleEndian.PutUint16(out[32:34], keybagVersion)
	binary.LittleEndian.PutUint16(out[34:36], uint16(len(entries)))
	off := keybagEntryAreaStart
	for _, e := range entries {
		const hLen = 24
		need := hLen + len(e.data)
		if rem := (off + need) % keybagEntryAlignment; rem != 0 {
			need += keybagEntryAlignment - rem
		}
		if off+need > totalBytes {
			return fmt.Errorf("apfs: keybag extent (%d blocks) is full; cannot append entry", sb.keybagBlocks)
		}
		off = appendEntryUUID(out, off, e.uuid, int(e.tag), e.data)
	}
	binary.LittleEndian.PutUint32(out[36:40], uint32(off-keybagEntryAreaStart))
	keybagOff := int64(sb.keybagBlock) * int64(blockSize)
	if _, err := rw.WriteAt(out, keybagOff); err != nil {
		return fmt.Errorf("apfs: write keybag: %w", err)
	}
	return nil
}

// formatPath / openPath are the file-backed helpers for FormatArgon2id /
// OpenWithPrivateKey. They mirror the structure of Format / Open.
func formatPath(path string, fn func(blockRW) (*Device, error)) (*Device, error) {
	f, err := openFile(path)
	if err != nil {
		return nil, err
	}
	dev, err := fn(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return dev, nil
}

func openPath(path string, fn func(blockRW) (*Device, error)) (*Device, error) {
	f, err := openFile(path)
	if err != nil {
		return nil, err
	}
	dev, err := fn(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return dev, nil
}

func openFile(path string) (blockRW, error) {
	return osOpenRW(path)
}

// reuseable RW open hook (also lets tests substitute if needed).
var osOpenRW = func(path string) (blockRW, error) {
	return osOpenFile(path)
}

