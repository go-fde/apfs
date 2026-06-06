# apfs

Pure-Go read/write support for APFS FileVault 2 full-disk encryption.

## Overview

APFS FileVault 2 protects volumes using AES-XTS block-level encryption. The key hierarchy is:

```
passphrase
    │  PBKDF2-SHA256
    ▼
  KEK (Key Encryption Key)  ─── AES-KW (RFC 3394) ──▶  wrapped KEK
                                                          stored in
                                                        Container Key Bag

  KEK ─── AES-KW (RFC 3394) ──▶  wrapped VEK
                                  stored in
                                Container Key Bag

  VEK (Volume Encryption Key)
      │  AES-XTS (per 512-byte sector)
      ▼
  plaintext blocks
```

Key bag entries are stored at the location named by the NX container
superblock's `nx_keylocker` field (offset 1296). Two on-disk shapes are
supported:

- **Apple shape** (selected when `nx_flags & NX_CRYPTO_SW`): keybag is
  encrypted at rest with AES-XTS-128 keyed on `containerUUID || containerUUID`;
  decrypted bytes follow Apple's `apfs_obj_phys` + `apfs_kb_locker`
  layout. The container keybag's tag=2 entry carries an ASN.1
  VEKBLOB; the volume keybag's tag=3 entry carries an ASN.1 KEKBLOB.
  See *Apple-shape encrypted-container support (F-2)* below.
- **Legacy self-consistent shape** (selected when the NX_CRYPTO_SW
  bit is clear): keybag is plaintext on disk; tag=3 entry encodes
  KDF parameters (PBKDF2-SHA256 or Argon2id) plus the wrapped KEK
  inline, tag=2 entry holds the raw AES-KW(KEK, VEK) ciphertext.
  Used by this package's `Format` / `FormatArgon2id` helpers and by
  the test suite. See *Argon2id format* below for that layout.

`unlockVEK` dispatches between the two shapes based on the
`nx_flags & NX_CRYPTO_SW` bit; callers go through the same
`apfs.Open` / `apfs.OpenFrom` public entry points either way.

## Supported features

| Feature | Status |
|---------|--------|
| APFS NX container superblock parsing | ✅ (nx_keylocker at +1296, nx_flags) |
| Apple-shape container keybag parsing (NX_CRYPTO_SW path) | ✅ |
| Apple-shape volume keybag parsing | ✅ |
| Legacy self-consistent keybag parsing (pre-F-2 format) | ✅ (auto-dispatched on `nx_flags & 0x4`) |
| Key derivation: PBKDF2-SHA256 | ✅ |
| Key derivation: Argon2id | ✅ (package-defined locker layout, see *Argon2id format* below) |
| AES Key Wrap / Unwrap (RFC 3394) | ✅ |
| Cipher: AES-128-XTS (`vek_size` = 32) | ✅ |
| Cipher: AES-256-XTS (`vek_size` = 64) | ✅ |
| At-rest keybag XTS encryption / decryption | ✅ (`EncryptContainerKeybag`, `EncryptVolumeKeybag`, `DecryptContainerKeybag`, `DecryptVolumeKeybag`) |
| ASN.1 VEKBLOB / KEKBLOB build + parse | ✅ (`BuildVEKBlob`, `BuildKEKBlob`, `ParseVEKBlob`, `ParseKEKBlob`) |
| Keybag block builder | ✅ (`PackKeybagBlock` — emits Apple's exact obj_phys + apfs_kb_locker shape) |
| Personal Recovery Key (PRK) | ✅ (passphrase-style locker tagged with a well-known UUID) |
| Institutional Recovery Key (IRK) | ✅ (RSA-OAEP wrapping of the KEK; private key required to unlock) |
| T2 / Secure Enclave mediated keys | ❌ (hardware access required) |
| Encrypted metadata (APFS snapshots, etc.) | ❌ (payload encryption only) |

## Apple-shape encrypted-container support (F-2)

Beyond the legacy self-consistent format produced by `Format` /
`FormatArgon2id`, this package now exposes the byte-level primitives
needed to build and parse keybags in **Apple's exact on-disk shape** —
the layout `diskutil apfs encryptVolume` produces. The recipe was
reverse-engineered byte-for-byte against two independently-encrypted
Apple reference DMGs and is locked in by:

- `TestVEKBlob_HMACAgainstAppleReference` — re-computes the HMAC over
  Apple's reference VEKBLOB using our `computeKeybagHMAC` and asserts
  byte-equality with Apple's stored value.
- `TestKeybagChain_PassphraseUnlocksVEK` — builds a complete Apple-
  shape container + volume keybag pair (using `BuildVEKBlob`,
  `BuildKEKBlob`, `PackKeybagBlock`, `EncryptContainerKeybag`,
  `EncryptVolumeKeybag`), then walks the structure end-to-end with
  only the passphrase + the two UUIDs + the two paddrs, recovering
  the VEK byte-for-byte. Same chain Apple's apfs.kext walks on mount.

The recipe (validated against Apple's reference 2026-05-09):

- **At-rest XTS**: AES-XTS-128, key = `uuid || uuid` (container UUID
  for the container keybag, volume UUID for the volume keybag),
  512-byte XTS sectors, tweak = `paddr × 8 + sector_index`.
- **Keybag block layout**: 32-byte `obj_phys` (type = `0x6b657973`
  "syek", sealed Fletcher-64 cksum) + 16-byte `apfs_kb_locker`
  (version=2, nkeys, nbytes including the 16-byte header AND the
  trailing 16-byte alignment pad) + 16-byte-aligned entries.
- **VEKBLOB / KEKBLOB**: ASN.1 DER with HMAC-SHA256 keyed by
  `SHA-256(\x01\x16\x20\x17\x15\x05 || salt)` over the [3] inner
  envelope. The [2] field is an 8-byte OCTET STRING (Apple's
  opaque `info_t`), NOT a minimal-length INTEGER. The inner [3]
  contains the AES-KW(KEK, VEK) RFC-3394 ciphertext (40 bytes for
  a 32-byte VEK).
- **`unlockVEK` dispatch**: `nx_flags & NX_CRYPTO_SW` (bit 0x4)
  selects the Apple-shape unlock walk; clear bit selects the legacy
  PBKDF2-locker path. Both work transparently through the
  `apfs.Open` / `apfs.OpenFrom` public API.

## Usage

### Open an encrypted APFS volume image

```go
import "github.com/go-fde/apfs"

// Open and unlock an APFS encrypted volume.
dev, err := apfs.Open("/dev/disk2s2", []byte("my passphrase"))
if err != nil {
    log.Fatal(err)
}
defer dev.Close()

// Read decrypted blocks. Offsets are absolute byte offsets in the device.
// Reads and writes must be aligned to 512-byte sector boundaries.
buf := make([]byte, 4096)
_, err = dev.ReadAt(buf, 0)

// Write encrypted blocks.
_, err = dev.WriteAt(buf, 0)
```

### Create a new APFS FDE container

`Format` and `FormatOn` write a minimal APFS NX superblock and key bag to an
existing file or block device, then return an open `*Device` ready for payload
I/O. Container parameters:

| Parameter | Value |
|-----------|-------|
| Block size | 4096 bytes |
| NX superblock | block 0 |
| Key bag | block 1 (referenced via `nx_keylocker` at NX SB offset 1296) |
| Payload start | block 2 (byte offset 8192) |
| VEK / KEK size | 32 bytes each (AES-256) |
| Key derivation | PBKDF2-SHA256, 1000 iterations, 16-byte salt |
| Key wrapping | AES Key Wrap (RFC 3394) |
| Cipher | AES-256-XTS, 512-byte sectors |

This is the **legacy self-consistent format**: `nx_flags & NX_CRYPTO_SW`
is clear and the keybag is plaintext on disk. Use
`pkg/go-filesystems/apfs.FormatContainerEncrypted` (or `…GPT`) for the
**Apple-shape** format, which produces output structurally identical
to `diskutil apfs encryptVolume`.

```go
// The file must exist before calling Format.
f, _ := os.Create("disk.apfs")
f.Close()

dev, err := apfs.Format("disk.apfs", []byte("passphrase"))
if err != nil { log.Fatal(err) }
defer dev.Close()

// WriteAt offset is absolute from the start of the container.
// Payload starts at block 2 = byte offset 2 × 4096 = 8192.
dev.WriteAt(myData, 2*4096)
```

`FormatOn` accepts any value satisfying the same `blockRW` interface as
`OpenFrom`, enabling container creation inside a QCOW2 virtual disk.

### Detect an APFS container

```go
ok, err := apfs.Detect("/path/to/disk.img")
if err != nil {
    log.Fatal(err)
}
if ok {
    fmt.Println("this is an APFS container")
}
```

### Layer on top of another block device (e.g. QCOW2)

`OpenFrom` accepts any value satisfying:

```go
interface {
    io.ReaderAt
    WriteAt([]byte, int64) (int, error)
    io.Closer
}
```

```go
import (
    apfsfde      "github.com/go-fde/apfs"
    image_qcow2 "github.com/go-diskimages/qcow2"
)

qdev, err := image_qcow2.OpenDevice("disk.qcow2")
if err != nil { log.Fatal(err) }

// apfsDev.Close() also closes qdev.
apfsDev, err := apfsfde.OpenFrom(qdev, []byte("passphrase"))
if err != nil {
    qdev.Close()
    log.Fatal(err)
}
defer apfsDev.Close()

buf := make([]byte, 512)
apfsDev.ReadAt(buf, 0)
```

## Block addressing

ReadAt and WriteAt use **absolute** byte offsets from the start of the
underlying device (block 0 of the APFS container). Reads and writes must be
aligned to 512-byte sector boundaries and have lengths that are multiples of
512 bytes. These constraints are imposed by AES-XTS, which operates on fixed
512-byte sectors.

The XTS tweak value for a given sector is `byteOffset / 512`, matching the
behaviour of Apple's kernel `com.apple.filesystems.apfs` kext.

## Compatibility

### Reading

`apfs.Open(path, passphrase)` opens both shapes transparently:

- **Apple-shape** containers produced by `diskutil apfs encryptVolume`
  on macOS 10.13 High Sierra and later. `unlockVEK` decrypts the
  container keybag with the container UUID, walks to the volume
  keybag, parses the ASN.1 KEKBLOB / VEKBLOB, derives the KEK from
  the passphrase via PBKDF2-SHA256, and unwraps the VEK.
- **Legacy self-consistent** containers produced by this package's
  `Format` / `FormatArgon2id` helpers (plaintext keybag, proprietary
  PBKDF2 / Argon2id locker). Used by tests and by callers that don't
  need byte-level Apple compatibility.

Both paths support AES-128-XTS (`vek_size` = 32) and AES-256-XTS
(`vek_size` = 64) at the volume layer.

### Writing

This package's `Format` produces the **legacy self-consistent**
shape. To produce an **Apple-shape** encrypted container that
matches `diskutil apfs encryptVolume` byte-for-byte, use
`pkg/go-filesystems/apfs.FormatContainerEncrypted` (or
`FormatContainerEncryptedGPT`) which sits on top of this package
and wires the additional container-level metadata (NX SB
`nx_keylocker` + `nx_flags`, checkpoint ephemerals, FQ trees,
APSB encryption flags). See [`COMPAT.md`](../../go-filesystems/apfs/COMPAT.md)
cell F-2 for the full recipe and parity test.

Note: `hdiutil create -encryption AES-256` is **DMG-envelope**
encryption (UDIF), NOT APFS FDE — different layer entirely.

## Argon2id format

Apple's APFS reference does not publicly document an on-disk layout for
Argon2id-protected lockers. This package defines and uses the following
self-consistent layout for the data field of a `kbTagVolumePassphrase`
keybag entry when `kdfType = 0x0001`:

```text
uint16 kdfType       (0x0001)
uint16 padding       (0)
uint32 timeCost      (Argon2id "t" parameter)
uint32 memoryKiB     (Argon2id "m" parameter, in KiB)
uint16 parallelism   (Argon2id "p" parameter)
uint16 saltLen
[saltLen bytes salt]
[remaining bytes = wrapped KEK]
```

Use `FormatArgon2id` / `FormatArgon2idOn` to create a container with an
Argon2id-protected locker, or `AddArgon2idPassphrase` to add an Argon2id
locker to an existing container.

## Personal Recovery Key (PRK)

A PRK is a regular passphrase locker tagged with the well-known UUID
`EBC6C064-0000-11AA-AA11-00306543ECAC` (the same UUID Apple uses for the
recovery user on HFS+ FileVault). Use `AddRecoveryKey(rw, existing, prk)` to
add one to a container; the resulting keybag entry can be unlocked by passing
the recovery key as the passphrase to `Open`/`OpenFrom`.

## Institutional Recovery Key (IRK)

An IRK is an RSA keypair held by an MDM administrator. The container's KEK is
wrapped with RSA-OAEP-SHA256 under the public key. The keybag entry uses tag
`kbTagInstitutionalKey = 0x0004` with the layout:

```text
[32 bytes  SHA-256 fingerprint of the RSA public key DER]
[N  bytes  RSA-OAEP-SHA256 ciphertext of the KEK]
```

The fingerprint lets the unlock path locate the matching entry when several
IRK keys coexist in the same keybag.

```go
priv, _ := rsa.GenerateKey(rand.Reader, 2048)
apfs.AddInstitutionalKey(rw, []byte("primary passphrase"), &priv.PublicKey)

// later, with the private key only:
dev, err := apfs.OpenWithPrivateKey("disk.apfs", priv)
```

## On-disk format references

- *Apple File System Reference* (developer.apple.com/support/downloads)
- *"Infiltrate the Vault: Security Analysis and Decryption of Lion Full Disk
  Encryption"* — Ligh, Walters et al. (PasswordsCon 2012)
- `apfs.h` and `IOKit/storage/APFS/APFSConstants.h` from the Darwin xnu
  open-source tree
- RFC 3394 — Advanced Encryption Standard (AES) Key Wrap Algorithm
