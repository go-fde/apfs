package apfs

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// appleShapeImage is a 4-block container in the shape FormatContainerEncrypted
// (go-filesystems/apfs) and diskutil write: NX_CRYPTO_SW set, the container
// keybag at block 2 encrypted with uuid||uuid, pointing at a volume keybag at
// block 3 whose KEKBLOB is unwrapped by passphrase.
func appleShapeImage(t testing.TB, passphrase []byte, iterations uint32) (img, vek []byte, volUUID [16]byte) {
	t.Helper()
	var nxUUID [16]byte
	copy(nxUUID[:], mustRand(16))
	copy(volUUID[:], mustRand(16))
	vek = mustRand(32)
	kek := mustRand(32)
	salt := mustRand(16)
	derived := pbkdf2.Key(passphrase, salt, int(iterations), 32, sha256.New)
	wKEK, err := aesKeyWrap(derived, kek)
	if err != nil {
		t.Fatal(err)
	}
	wVEK, err := aesKeyWrap(kek, vek)
	if err != nil {
		t.Fatal(err)
	}
	kekBlob, err := BuildKEKBlob(volUUID, 0, wKEK, iterations, salt, mustRand(8))
	if err != nil {
		t.Fatal(err)
	}
	vekBlob, err := BuildVEKBlob(volUUID, 0, wVEK, mustRand(8))
	if err != nil {
		t.Fatal(err)
	}
	const cKB, vKB = 2, 3
	prange := make([]byte, 16)
	binary.LittleEndian.PutUint64(prange[:8], vKB)
	binary.LittleEndian.PutUint64(prange[8:], 1)
	cPlain := PackKeybagBlock([]KeybagEntry{
		{UUID: volUUID, Tag: KBTagVolumeUnlockRecords, Data: prange},
		{UUID: volUUID, Tag: KBTagVolumeKey, Data: vekBlob},
	})
	vPlain := PackKeybagBlock([]KeybagEntry{{UUID: volUUID, Tag: KBTagVolumePassphrase, Data: kekBlob}})
	cCipher, err := EncryptContainerKeybag(cPlain, nxUUID, cKB)
	if err != nil {
		t.Fatal(err)
	}
	vCipher, err := EncryptVolumeKeybag(vPlain, volUUID, vKB)
	if err != nil {
		t.Fatal(err)
	}
	img = make([]byte, 4*nxBlockSize)
	copy(img, buildNXSuperblock(nxBlockSize, cKB, 1))
	copy(img[72:88], nxUUID[:])
	binary.LittleEndian.PutUint64(img[1264:1272], nxFlagCryptoSW)
	copy(img[cKB*nxBlockSize:], cCipher)
	copy(img[vKB*nxBlockSize:], vCipher)
	return img, vek, volUUID
}

func TestUnlockVolumeKeyAppleShape(t *testing.T) {
	img, vek, volUUID := appleShapeImage(t, []byte("s3cret"), 1000)
	vk, err := UnlockVolumeKey(bytes.NewReader(img), []byte("s3cret"), DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(vk.VEK, vek) || vk.VolumeUUID != volUUID {
		t.Fatalf("got VEK %x uuid %x, want %x %x", vk.VEK, vk.VolumeUUID, vek, volUUID)
	}

	_, err = UnlockVolumeKey(bytes.NewReader(img), []byte("wrong"), DefaultLimits)
	if !errors.Is(err, ErrWrongPassphrase) || errors.Is(err, ErrLimit) {
		t.Fatalf("wrong passphrase: err = %v, want ErrWrongPassphrase only", err)
	}
	_, err = UnlockVolumeKey(bytes.NewReader(img), []byte("s3cret"), Limits{MaxPBKDF2Iterations: 999})
	if !errors.Is(err, ErrLimit) || errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("1000 iterations under 999: err = %v, want ErrLimit only", err)
	}
}

func TestUnlockVolumeKeyLegacyShape(t *testing.T) {
	img := buildAPFSImage(t, []byte("pass"), []byte("payload"))
	vk, err := UnlockVolumeKey(bytes.NewReader(img), []byte("pass"), DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if vk.VolumeUUID != ([16]byte{}) {
		t.Fatalf("legacy keybag names no volume, got %x", vk.VolumeUUID)
	}
	// The key must be the one Device uses: decrypt block 2 both ways.
	sc, err := NewSectorCipher(vk.VEK)
	if err != nil {
		t.Fatal(err)
	}
	blk := append([]byte(nil), img[2*nxBlockSize:3*nxBlockSize]...)
	if err := sc.Decrypt(blk, 2*nxBlockSize/SectorSize); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(blk, []byte("payload")) {
		t.Fatalf("SectorCipher with the unlocked key read %q", blk[:7])
	}
	dev, err := OpenFrom(&memRW{buf: img}, []byte("pass"))
	if err != nil {
		t.Fatal(err)
	}
	viaDev := make([]byte, nxBlockSize)
	if _, err := dev.ReadAt(viaDev, 2*nxBlockSize); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(viaDev, blk) {
		t.Fatal("SectorCipher and Device disagree on the same block")
	}
	if _, err := UnlockVolumeKey(bytes.NewReader(img), []byte("nope"), DefaultLimits); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("legacy wrong passphrase: err = %v, want ErrWrongPassphrase", err)
	}
}

func TestSectorCipher(t *testing.T) {
	if _, err := NewSectorCipher(make([]byte, 16)); err == nil {
		t.Fatal("a 16-byte VEK was accepted")
	}
	for _, n := range []int{32, 64} {
		sc, err := NewSectorCipher(mustRand(n))
		if err != nil {
			t.Fatal(err)
		}
		plain := mustRand(4 * SectorSize)
		buf := append([]byte(nil), plain...)
		if err := sc.Encrypt(buf, math.MaxUint64-1); err != nil { // wraps past 2^64
			t.Fatal(err)
		}
		if bytes.Equal(buf, plain) {
			t.Fatal("Encrypt left the data as it was")
		}
		// Unit k decrypts on its own with tweak first+k: units are independent.
		unit := append([]byte(nil), buf[2*SectorSize:3*SectorSize]...)
		if err := sc.Decrypt(unit, 0); err != nil { // (MaxUint64-1)+2 wraps to 0
			t.Fatal(err)
		}
		if !bytes.Equal(unit, plain[2*SectorSize:3*SectorSize]) {
			t.Fatal("data unit 2 did not decrypt with the wrapped tweak 0")
		}
		if err := sc.Decrypt(buf, math.MaxUint64-1); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf, plain) {
			t.Fatal("round trip changed the data")
		}
		if err := sc.Decrypt(make([]byte, 100), 0); err == nil {
			t.Fatal("a partial data unit was accepted")
		}
	}
}

// The superblock fields that size allocations or offsets are untrusted.
func TestHostileGeometry(t *testing.T) {
	for _, c := range []struct {
		name            string
		blockSize       uint32
		kbBlock, kbSize uint64
	}{
		{"block size 1 MiB", 1 << 20, 1, 1},
		{"block size 4 GiB-1", math.MaxUint32, 1, 1},
		{"block size not a power of two", 6144, 1, 1},
		{"block size below the minimum", 512, 1, 1},
		{"keybag of 2^40 blocks", 4096, 1, 1 << 40},
		{"keybag past int64", 4096, math.MaxUint64 / 2, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := newMemRW(4 * nxBlockSize)
			copy(m.buf, buildNXSuperblock(c.blockSize, c.kbBlock, c.kbSize))
			_, err := UnlockVolumeKey(m, []byte("p"), DefaultLimits)
			if err == nil || errors.Is(err, ErrWrongPassphrase) {
				t.Fatalf("err = %v, want a structural refusal", err)
			}
		})
	}
	// A volume keybag paddr past int64 in an Apple-shape container keybag.
	img, _, volUUID := appleShapeImage(t, []byte("p"), 1000)
	prange := make([]byte, 16)
	binary.LittleEndian.PutUint64(prange[:8], math.MaxUint64/2)
	binary.LittleEndian.PutUint64(prange[8:], 1)
	cPlain := PackKeybagBlock([]KeybagEntry{
		{UUID: volUUID, Tag: KBTagVolumeUnlockRecords, Data: prange},
		{UUID: volUUID, Tag: KBTagVolumeKey, Data: []byte{0x30, 0}},
	})
	var nxUUID [16]byte
	copy(nxUUID[:], img[72:88])
	cCipher, err := EncryptContainerKeybag(cPlain, nxUUID, 2)
	if err != nil {
		t.Fatal(err)
	}
	copy(img[2*nxBlockSize:], cCipher)
	if _, err := UnlockVolumeKey(bytes.NewReader(img), []byte("p"), DefaultLimits); err == nil {
		t.Fatal("a volume keybag past int64 was read")
	}
}

// FuzzUnlockVolumeKey feeds arbitrary bytes as the superblock and both
// keybag blocks of an Apple-shape container (the keybags are fuzzed as
// plaintext, then encrypted in place, so the parser behind the XTS layer is
// reached). It must never panic, and the KDF stays within tight limits.
func FuzzUnlockVolumeKey(f *testing.F) {
	img, _, volUUID := appleShapeImage(f, []byte("p"), 1000)
	var nxUUID [16]byte
	copy(nxUUID[:], img[72:88])
	cPlain, _ := DecryptContainerKeybag(img[2*nxBlockSize:3*nxBlockSize], nxUUID, 2)
	vPlain, _ := DecryptVolumeKeybag(img[3*nxBlockSize:4*nxBlockSize], volUUID, 3)
	f.Add(img[:nxBlockSize], cPlain, vPlain)
	f.Add(img[:64], []byte{}, []byte{})
	lim := Limits{MaxPBKDF2Iterations: 2000, MaxArgon2Time: 1, MaxArgon2MemoryKiB: 64}
	f.Fuzz(func(t *testing.T, sb, ckb, vkb []byte) {
		m := make([]byte, 4*nxBlockSize)
		copy(m, img)
		copy(m[:nxBlockSize], sb)
		copy(m[72:88], nxUUID[:]) // keep the key the container keybag is under
		if len(ckb) > 0 {
			blk := make([]byte, nxBlockSize)
			copy(blk, ckb)
			if c, err := EncryptContainerKeybag(blk, nxUUID, 2); err == nil {
				copy(m[2*nxBlockSize:], c)
			}
		}
		if len(vkb) > 0 {
			blk := make([]byte, nxBlockSize)
			copy(blk, vkb)
			if c, err := EncryptVolumeKeybag(blk, volUUID, 3); err == nil {
				copy(m[3*nxBlockSize:], c)
			}
		}
		_, _ = UnlockVolumeKey(bytes.NewReader(m), []byte("p"), lim)
	})
}

// FuzzParseBlobs: the DER blobs of a keybag are image bytes; the parsers
// must refuse, never panic, whatever they are given.
func FuzzParseBlobs(f *testing.F) {
	var u [16]byte
	k, _ := BuildKEKBlob(u, 0, make([]byte, 40), 200000, make([]byte, 16), make([]byte, 8))
	v, _ := BuildVEKBlob(u, 0, make([]byte, 40), make([]byte, 8))
	f.Add(k)
	f.Add(v)
	f.Add([]byte{0x30, 0x02, 0x80, 0xff})
	f.Add([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, der []byte) {
		_, _ = ParseKEKBlob(der)
		_, _ = ParseVEKBlob(der)
	})
}

// The old parser indexed past the end on these; the new one must refuse.
func TestParseBlobsTruncated(t *testing.T) {
	var u [16]byte
	k, err := BuildKEKBlob(u, 0, make([]byte, 40), 200000, make([]byte, 16), make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}
	for _, der := range [][]byte{
		{0x30, 0x02, 0x80, 0xff},
		{0x30, 0x84, 0xff, 0xff, 0xff, 0xff},
		{0x30},
		{},
	} {
		if _, err := ParseKEKBlob(der); err == nil {
			t.Fatalf("ParseKEKBlob(%x) accepted", der)
		}
		if _, err := ParseVEKBlob(der); err == nil {
			t.Fatalf("ParseVEKBlob(%x) accepted", der)
		}
	}
	for n := range len(k) {
		_, _ = ParseKEKBlob(k[:n]) // every prefix: no panic
		_, _ = ParseVEKBlob(k[:n])
	}
}
