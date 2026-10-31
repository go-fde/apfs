package apfs

import (
	"bytes"
	"crypto/aes"
	"testing"

	"github.com/go-encryptions/xts"
)

// The keybag's XTS data units follow the container's block size: the first
// unit of the block at paddr is paddr × blockSize/512 (apfs-fuse KeyMgmt.cpp,
// cs_factor = GetBlocksize() / 0x200). Checked against xts itself, keyed
// uuid || uuid, with that formula written out -- not against this package.
func TestKeybagUnitsFollowTheBlockSize(t *testing.T) {
	var uuid [16]byte
	for i := range uuid {
		uuid[i] = byte(i * 13)
	}
	const paddr = 7
	for _, bs := range []uint32{4096, 8192, 16384, 65536} {
		plain := make([]byte, 2*bs) // two blocks: the second continues the units
		for i := range plain {
			plain[i] = byte(i)
		}
		got, err := EncryptKeybagBlocks(plain, uuid, paddr, bs)
		if err != nil {
			t.Fatalf("%d: %v", bs, err)
		}
		c, err := xts.NewCipher(aes.NewCipher, append(uuid[:], uuid[:]...))
		if err != nil {
			t.Fatal(err)
		}
		want := bytes.Clone(plain)
		unit := uint64(paddr) * uint64(bs/512)
		for i := 0; i < len(want); i += 512 {
			c.Encrypt(want[i:i+512], want[i:i+512], unit)
			unit++
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("block size %d: not paddr × %d", bs, bs/512)
		}
		back, err := DecryptKeybagBlocks(got, uuid, paddr, bs)
		if err != nil || !bytes.Equal(back, plain) {
			t.Fatalf("block size %d: round trip: %v", bs, err)
		}
		vb, err := DecryptVolumeBlocks(got, append(uuid[:], uuid[:]...), paddr, bs)
		if err != nil || !bytes.Equal(vb, plain) {
			t.Fatalf("block size %d: the volume-block path differs: %v", bs, err)
		}
	}
}

// The functions without a block size are the 4096-byte case, unchanged.
func TestFourKiBFunctionsUnchanged(t *testing.T) {
	var uuid [16]byte
	uuid[0] = 1
	plain := bytes.Repeat([]byte{0x5a}, 4096)
	a, err := EncryptContainerKeybag(plain, uuid, 3)
	if err != nil {
		t.Fatal(err)
	}
	b, err := EncryptKeybagBlocks(plain, uuid, 3, 4096)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatalf("EncryptContainerKeybag differs from the 4096 case: %v", err)
	}
	if v, err := EncryptVolumeKeybag(plain, uuid, 3); err != nil || !bytes.Equal(v, b) {
		t.Fatalf("EncryptVolumeKeybag differs: %v", err)
	}
}

func TestBlockSizeRefused(t *testing.T) {
	var uuid [16]byte
	for _, bs := range []uint32{0, 512, 2048, 4095, 6144, 131072} {
		if _, err := DecryptKeybagBlocks(make([]byte, 8192), uuid, 0, bs); err == nil {
			t.Errorf("block size %d accepted", bs)
		}
	}
	if _, err := DecryptKeybagBlocks(make([]byte, 4096), uuid, 0, 8192); err == nil {
		t.Error("a length that is not a whole block accepted")
	}
}
