package apfs

import (
	"encoding/binary"
	"testing"

	"github.com/go-simd/adler32/fletcher64"
)

// naiveFletcher64 is the kernel this package carried before it moved to
// github.com/go-simd/adler32/fletcher64; it is the oracle for the move.
func naiveFletcher64(buf []byte) uint64 {
	const mod = (uint64(1) << 32) - 1
	var s1, s2 uint64
	for i := 0; i+4 <= len(buf); i += 4 {
		w := uint64(binary.LittleEndian.Uint32(buf[i : i+4]))
		s1 = (s1 + w) % mod
		s2 = (s2 + s1) % mod
	}
	c1 := mod - ((s1 + s2) % mod)
	c2 := mod - ((s1 + c1) % mod)
	return (c2 << 32) | c1
}

// TestSharedFletcher64MatchesPreviousKernel pins the shared kernel to the
// removed local one, with a known-answer value.
func TestSharedFletcher64MatchesPreviousKernel(t *testing.T) {
	buf := make([]byte, 4088)
	for i := range buf {
		buf[i] = byte(i*7 + 3)
	}
	got := fletcher64.Sum(buf)
	if want := naiveFletcher64(buf); got != want {
		t.Fatalf("shared kernel = %#x, previous kernel = %#x", got, want)
	}
	const kat = uint64(0x1c193445c3b48774)
	if got != kat {
		t.Fatalf("shared kernel = %#x, KAT %#x", got, kat)
	}
}
