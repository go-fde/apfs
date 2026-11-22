package apfs

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// hostileLegacyImage builds a legacy-shape container whose keybag holds the
// given entries, over nblocks keybag blocks.
func hostileLegacyImage(t *testing.T, nblocks int, entries []rawEntry) *memRW {
	t.Helper()
	rw := newMemRW(1 << 20)
	sb := nxSuperblockBytes()
	binary.LittleEndian.PutUint64(sb[nxKeylockerOffset+8:], uint64(nblocks))
	copy(rw.buf, sb)
	kb := make([]byte, nblocks*nxBlockSize)
	binary.LittleEndian.PutUint32(kb[24:28], mediaKeybagObjType)
	binary.LittleEndian.PutUint16(kb[32:34], keybagVersion)
	binary.LittleEndian.PutUint16(kb[34:36], uint16(len(entries)))
	off := keybagEntryAreaStart
	for _, e := range entries {
		off = appendEntryUUID(kb, off, e.uuid, int(e.tag), e.data)
	}
	copy(rw.buf[nxBlockSize:], kb)
	return rw
}

// legacyImageWithVEK wraps vek under a PBKDF2 locker for pass.
func legacyImageWithVEK(t *testing.T, pass, vek []byte) *memRW {
	t.Helper()
	salt := []byte("0123456789abcdef")
	kek := bytes.Repeat([]byte{0x11}, 32)
	derived := pbkdf2.Key(pass, salt, 1000, 32, sha256.New)
	wKEK, err := aesKeyWrap(derived, kek)
	if err != nil {
		t.Fatal(err)
	}
	wVEK, err := aesKeyWrap(kek, vek)
	if err != nil {
		t.Fatal(err)
	}
	return hostileLegacyImage(t, 1, []rawEntry{
		{tag: kbTagVolumePassphrase, data: encodePBKDF2Locker(1000, salt, wKEK)},
		{tag: kbTagVolumeKey, data: wVEK},
	})
}

// A keybag wrapping a 16-byte volume key used to open with a nil cipher, and
// the first ReadAt was a nil dereference (issue #36).
func TestOpenRefusesAShortVEK(t *testing.T) {
	pass := []byte("known")
	for _, n := range []int{16, 24, 40, 48, 72} {
		rw := legacyImageWithVEK(t, pass, bytes.Repeat([]byte{0x22}, n))
		dev, err := OpenFrom(rw, pass)
		if err == nil {
			t.Fatalf("OpenFrom accepted a %d-byte VEK (dev=%v)", n, dev)
		}
	}
	for _, n := range []int{32, 64} {
		rw := legacyImageWithVEK(t, pass, bytes.Repeat([]byte{0x22}, n))
		dev, err := OpenFrom(rw, pass)
		if err != nil {
			t.Fatalf("a %d-byte VEK refused: %v", n, err)
		}
		if _, err := dev.ReadAt(make([]byte, 512), 0); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUnwrapVEKRefusesAShortVEK(t *testing.T) {
	kek := bytes.Repeat([]byte{0x11}, 32)
	w, err := aesKeyWrap(kek, bytes.Repeat([]byte{0x22}, 16))
	if err != nil {
		t.Fatal(err)
	}
	v, err := unwrapVEK([]keybagEntry{{data: w}}, kek)
	if err == nil {
		t.Fatalf("unwrapVEK returned a %d-byte key", len(v))
	}
	if !strings.Contains(err.Error(), "16 bytes") {
		t.Fatalf("the error does not name the size: %v", err)
	}
	// A KEK that cannot unwrap at all is a different error.
	if _, err := unwrapVEK([]keybagEntry{{data: w}}, bytes.Repeat([]byte{0x99}, 32)); err == nil || strings.Contains(err.Error(), "bytes, want") {
		t.Fatalf("a wrong KEK must not read as a size error: %v", err)
	}
	// A good entry after a short one is still found.
	good, err := aesKeyWrap(kek, bytes.Repeat([]byte{0x33}, 32))
	if err != nil {
		t.Fatal(err)
	}
	v, err = unwrapVEK([]keybagEntry{{data: w}, {data: good}}, kek)
	if err != nil || len(v) != 32 {
		t.Fatalf("unwrapVEK = %d bytes, %v", len(v), err)
	}
}

func TestAppleShapeRefusesAShortVEK(t *testing.T) {
	pass := []byte("known")
	img, _, _ := appleShapeImageVEK(t, pass, 1000, 16)
	if vk, err := UnlockVolumeKey(bytes.NewReader(img), pass, DefaultLimits); err == nil {
		t.Fatalf("UnlockVolumeKey returned a %d-byte VEK", len(vk.VEK))
	}
	if dev, err := OpenFrom(&memRW{buf: img}, pass); err == nil {
		t.Fatalf("OpenFrom accepted a 16-byte VEK (dev=%v)", dev)
	}
}

func TestNewDeviceRefusesAKeyXTSCannotTake(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 65} {
		if dev, err := newDevice(newMemRW(512), make([]byte, n)); err == nil || dev != nil {
			t.Fatalf("newDevice accepted a %d-byte key: %v, %v", n, dev, err)
		}
	}
	if dev, err := newDevice(newMemRW(512), make([]byte, 64)); err != nil || dev.enc == nil {
		t.Fatalf("newDevice refused a 64-byte key: %v", err)
	}
}
