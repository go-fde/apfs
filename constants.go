package apfs

// APFS / CoreStorage on-disk constants.
// References:
//   - Apple File System Reference (2023-09)
//   - "Infiltrate the Vault: Security Analysis and Decryption of Lion Full Disk
//     Encryption" — Ligh, Walters et al. (PasswordsCon 2012)
//   - apfs.h from the Darwin xnu open-source tree

const (
	// nxSuperblockMagic is the 4-byte magic at offset 32 in the APFS NX
	// container superblock (block 0). Apple writes the ASCII bytes
	// 'N','X','S','B' there (little-endian uint32 = 0x4253584E). An
	// earlier version of this constant was "BSXN" — self-consistent
	// for round-tripping our own writer but incompatible with any
	// container produced by Apple's tooling, including the fully-
	// Apple-shape FormatContainerEncrypted output. Fixed during F-2 work.
	nxSuperblockMagic = "NXSB"

	// nxKeylockerOffset is the byte offset of the apfs_prange nx_keylocker
	// inside the NX SuperBlock (paddr u64 at +1296, block_count u64 at +1304).
	// This is where Apple's apfs.kext / fsck_apfs look for the container
	// keybag — earlier versions of this package incorrectly wrote at +64-72,
	// which is nx_incompatible_features.
	nxKeylockerOffset = 1296

	// mediaKeybagObjType is the apfs_obj_phys.o_type value for a media
	// keybag block: 0x6B657973 ("syek" little-endian / "keys" big-endian).
	// Stored at obj_phys offset +24 inside the keybag block.
	mediaKeybagObjType uint32 = 0x6b657973

	// keybagEntryAlignment is the boundary entries are rounded up to
	// (apfs-fuse next_entry: (size + 0xF) & ~0xF). Earlier versions used
	// 8-byte alignment, which Apple's parser tolerated only by accident.
	keybagEntryAlignment = 16

	// keybagEntryAreaStart is the byte offset within a keybag block where
	// entries start: 32 (obj_phys) + 16 (apfs_kb_locker) = 48.
	keybagEntryAreaStart = 48

	// nxBlockSize is the default APFS container block size (4096 bytes).
	// Volumes may override this but 4096 is by far the most common.
	nxBlockSize = 4096

	// sectorSize is the unit used for AES-XTS tweak numbering (512 bytes).
	sectorSize = 512

	// keybagVersion is the only supported key bag version.
	keybagVersion = 2

	// Key bag entry tag values.
	kbTagUnknown          = 0x0000
	kbTagReserved1        = 0x0001
	kbTagVolumeKey        = 0x0002 // VEK wrapped with KEK
	kbTagVolumePassphrase = 0x0003 // PBKDF2/Argon2id parameters + wrapped KEK
	kbTagWrappedKEK       = 0x0003 // alias for 0x0003 (same slot type)
	// kbTagInstitutionalKey is the keybag entry tag used by this package to
	// store an institutional recovery key (IRK) wrapping. The on-disk format
	// is package-defined: 32-byte SHA-256 fingerprint of the RSA public key
	// (DER), followed by the RSA-OAEP-SHA256 encryption of the KEK.
	kbTagInstitutionalKey = 0x0004

	// APFS volume superblock magic "BSXA" (little-endian 0x41585342).
	apfsMagic = "BSXA"
)

// nxSuperblock holds the fields from the NX Container Superblock that this
// package needs. The full structure is 1408+ bytes; only relevant fields are
// decoded.
type nxSuperblock struct {
	blockSize    uint32
	keybagBlock  uint64   // first block of the container key bag
	keybagBlocks uint64   // number of consecutive blocks occupied by the key bag
	flags        uint64   // nx_flags (offset 1264) — bit 0x4 = NX_CRYPTO_SW
	uuid         [16]byte // nx_uuid (offset 72) — container UUID, used as the
	// AES-XTS key for the container keybag at rest
}

// nxFlagCryptoSW is bit 0x4 of nx_flags. When set, apfs.kext applies
// AES-XTS at-rest decryption to the container keybag (with key
// uuid||uuid) on read; the keybag content uses the Apple ASN.1
// VEKBLOB/KEKBLOB format rather than the simpler self-consistent
// PBKDF2-locker shape this package emitted before F-2 work landed.
const nxFlagCryptoSW uint64 = 0x4

// keybagHeader is the fixed header that precedes the key-bag entries.
type keybagHeader struct {
	version    uint16
	numEntries uint16
	numBytes   uint32
}

// keybagEntry is one entry in a key bag.
type keybagEntry struct {
	uuid [16]byte
	tag  uint16
	// keylen is the length of the key-data payload that immediately follows.
	keylen uint16
	// data is the entry's payload (length = keylen).
	data []byte
}

// kbLocker holds the KDF parameters stored in a kbTagVolumePassphrase
// keybag entry. The wrapped KEK follows the locker header.
//
// PBKDF2 layout (kdfType = 0x0002):
//
//	uint16 type           (0x0002)
//	uint16 padding
//	uint32 iterations
//	uint16 saltLen
//	[salt bytes…]
//	[remaining bytes = wrapped KEK, 40 bytes for a 256-bit key]
//
// Argon2id layout (kdfType = 0x0001) — package-defined; Apple does not
// publicly document an on-disk format for Argon2id-protected APFS lockers
// so this layout is used both for writing and reading by go-fde/apfs:
//
//	uint16 type           (0x0001)
//	uint16 padding
//	uint32 timeCost       (Argon2id "t" parameter, ≥1)
//	uint32 memoryKiB      (Argon2id "m" parameter in KiB, ≥8 * threads)
//	uint16 parallelism    (Argon2id "p" parameter, ≥1)
//	uint16 saltLen
//	[salt bytes…]
//	[remaining bytes = wrapped KEK]
type kbLocker struct {
	kdfType    uint16
	salt       []byte
	wrappedKEK []byte
	// PBKDF2 parameters (kdfType = kdfTypePBKDF2).
	iterations uint32
	// Argon2id parameters (kdfType = kdfTypeArgon2id).
	timeCost    uint32
	memoryKiB   uint32
	parallelism uint16
}
