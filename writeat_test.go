package apfs

import (
	"bytes"
	"testing"
)

// A write whose length is not a sector multiple used to reach the device as
// plaintext with err == nil (issue #34).
func TestWriteAtUnalignedLengthRefused(t *testing.T) {
	rw := newMemRW(1 << 20)
	dev, err := FormatOn(rw, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte("TOP-SECRET-"), 10) // 110 bytes
	const off = 64 * 1024
	n, err := dev.WriteAt(secret, off)
	if err == nil {
		t.Fatalf("WriteAt of a non-sector length accepted (n=%d)", n)
	}
	if n != 0 {
		t.Fatalf("n = %d, want 0", n)
	}
	if bytes.Contains(rw.buf, []byte("TOP-SECRET-")) {
		t.Fatal("the plaintext reached the device")
	}
}

func TestWriteAtUnalignedOffsetRefused(t *testing.T) {
	rw := newMemRW(1 << 20)
	dev, err := FormatOn(rw, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dev.WriteAt(make([]byte, 512), 64*1024+7); err == nil {
		t.Fatal("WriteAt at offset 65543 accepted")
	}
	if _, err := dev.WriteAt(make([]byte, 512), -512); err == nil {
		t.Fatal("WriteAt at a negative offset accepted")
	}
	if _, err := dev.ReadAt(make([]byte, 512), -512); err == nil {
		t.Fatal("ReadAt at a negative offset accepted")
	}
}

func TestWriteAtReadAtAlignedRoundTrip(t *testing.T) {
	rw := newMemRW(1 << 20)
	dev, err := FormatOn(rw, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	p := bytes.Repeat([]byte("abcdefgh"), 128) // 1024 bytes
	if n, err := dev.WriteAt(p, 64*1024); err != nil || n != len(p) {
		t.Fatalf("WriteAt = %d, %v", n, err)
	}
	got := make([]byte, len(p))
	if _, err := dev.ReadAt(got, 64*1024); err != nil || !bytes.Equal(got, p) {
		t.Fatalf("round trip failed: %v", err)
	}
	if bytes.Equal(rw.buf[64*1024:64*1024+len(p)], p) {
		t.Fatal("device holds plaintext")
	}
}
