package xts

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"math/rand"
	"testing"

	xref "golang.org/x/crypto/xts"
)

// mustHex decodes a hex string or fails the test.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// IEEE P1619 / NIST XTS-AES known-answer vectors.
// Source: IEEE Std 1619-2007 Annex B and the NIST XTSGen KAT set.
var katVectors = []struct {
	name      string
	key       string // full XTS key (k1||k2)
	sectorNum uint64
	plain     string
	cipher    string
}{
	{
		// IEEE 1619 vector 1: AES-128-XTS, all-zero key, sector 0.
		name:      "ieee-aes128-1",
		key:       "0000000000000000000000000000000000000000000000000000000000000000",
		sectorNum: 0,
		plain:     "0000000000000000000000000000000000000000000000000000000000000000",
		cipher:    "917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e",
	},
	{
		// IEEE 1619 vector 2: AES-128-XTS, key 11..,22.., sector 0x3333333333.
		name:      "ieee-aes128-2",
		key:       "1111111111111111111111111111111122222222222222222222222222222222",
		sectorNum: 0x3333333333,
		plain:     "4444444444444444444444444444444444444444444444444444444444444444",
		cipher:    "c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0",
	},
	{
		// IEEE 1619 vector 4 (partial): AES-128-XTS over 512 bytes of the
		// 00..ff repeating plaintext, sector 0.
		name:      "ieee-aes128-4-head",
		key:       "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
		sectorNum: 0,
		plain:     "000102030405060708090a0b0c0d0e0f",
		cipher:    "44a3766603723de69ef3b65c1633afea",
	},
	{
		// AES-256-XTS, IEEE 1619 vector 10 head block.
		name:      "ieee-aes256-10-head",
		key:       "2718281828459045235360287471352662497757247093699959574966967627" + "3141592653589793238462643383279502884197169399375105820974944592",
		sectorNum: 0xff,
		plain:     "000102030405060708090a0b0c0d0e0f",
		cipher:    "1c3b3a102f770386e4836c99e370cf9b",
	},
}

func TestKnownAnswerVectors(t *testing.T) {
	for _, v := range katVectors {
		t.Run(v.name, func(t *testing.T) {
			key := mustHex(t, v.key)
			pt := mustHex(t, v.plain)
			want := mustHex(t, v.cipher)
			c, err := NewCipher(aes.NewCipher, key)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(pt))
			c.Encrypt(got, pt, v.sectorNum)
			if !bytes.Equal(got, want) {
				t.Fatalf("encrypt mismatch\n got %x\nwant %x", got, want)
			}
			// Round-trip.
			back := make([]byte, len(want))
			c.Decrypt(back, got, v.sectorNum)
			if !bytes.Equal(back, pt) {
				t.Fatalf("decrypt round-trip mismatch\n got %x\nwant %x", back, pt)
			}
		})
	}
}

// TestMatchesReference proves byte-identical output with x/crypto/xts across
// key sizes, sector sizes, sector numbers and the accelerated vs portable path.
func TestMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, keyLen := range []int{32, 64} {
		key := make([]byte, keyLen)
		rng.Read(key)
		ours, err := NewCipher(aes.NewCipher, key)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := xref.NewCipher(aes.NewCipher, key)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range []int{16, 32, 48, 64, 80, 128, 496, 512, 4096} {
			pt := make([]byte, n)
			rng.Read(pt)
			for _, sec := range []uint64{0, 1, 2, 7, 255, 1 << 20, 0x123456789a} {
				want := make([]byte, n)
				ref.Encrypt(want, pt, sec)
				got := make([]byte, n)
				ours.Encrypt(got, pt, sec)
				if !bytes.Equal(got, want) {
					t.Fatalf("ENC keyLen=%d n=%d sec=%d\n got %x\nwant %x", keyLen, n, sec, got, want)
				}
				// decrypt both ways
				back := make([]byte, n)
				ours.Decrypt(back, got, sec)
				if !bytes.Equal(back, pt) {
					t.Fatalf("DEC keyLen=%d n=%d sec=%d roundtrip failed", keyLen, n, sec)
				}
				refBack := make([]byte, n)
				ref.Decrypt(refBack, want, sec)
				if !bytes.Equal(refBack, back) {
					t.Fatalf("DEC keyLen=%d n=%d sec=%d differs from reference", keyLen, n, sec)
				}
			}
		}
	}
}

// TestInPlace verifies that dst==src (in-place) works for both directions.
func TestInPlace(t *testing.T) {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i)
	}
	c, err := NewCipher(aes.NewCipher, key)
	if err != nil {
		t.Fatal(err)
	}
	orig := make([]byte, 512)
	for i := range orig {
		orig[i] = byte(i * 7)
	}
	buf := make([]byte, 512)
	copy(buf, orig)
	c.Encrypt(buf, buf, 99)
	if bytes.Equal(buf, orig) {
		t.Fatal("in-place encrypt did nothing")
	}
	c.Decrypt(buf, buf, 99)
	if !bytes.Equal(buf, orig) {
		t.Fatal("in-place round-trip failed")
	}
}

// fakeBlock is a non-AES 16-byte block cipher (a trivial XOR cipher) used to
// exercise the portable fallback path on accelerated architectures.
type fakeBlock struct{ k []byte }

func (f fakeBlock) BlockSize() int { return 16 }
func (f fakeBlock) Encrypt(dst, src []byte) {
	for i := 0; i < 16; i++ {
		dst[i] = src[i] ^ f.k[i%len(f.k)]
	}
}
func (f fakeBlock) Decrypt(dst, src []byte) { f.Encrypt(dst, src) }

func newFake(key []byte) (cipher.Block, error) { return fakeBlock{k: key}, nil }

// TestPortableFallback drives a non-AES cipher so the portable per-block path
// is taken (c.accelerated == false) and confirms it matches x/crypto/xts, which
// uses the same algorithm.
func TestPortableFallback(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	ours, err := NewCipher(newFake, key)
	if err != nil {
		t.Fatal(err)
	}
	if ours.accelerated {
		t.Fatal("non-AES cipher must not use the accelerated path")
	}
	ref, err := xref.NewCipher(newFake, key)
	if err != nil {
		t.Fatal(err)
	}
	pt := make([]byte, 512)
	for i := range pt {
		pt[i] = byte(i)
	}
	for _, sec := range []uint64{0, 5, 1 << 30} {
		want := make([]byte, len(pt))
		ref.Encrypt(want, pt, sec)
		got := make([]byte, len(pt))
		ours.Encrypt(got, pt, sec)
		if !bytes.Equal(got, want) {
			t.Fatalf("portable ENC sec=%d mismatch", sec)
		}
		back := make([]byte, len(pt))
		ours.Decrypt(back, got, sec)
		if !bytes.Equal(back, pt) {
			t.Fatalf("portable DEC sec=%d roundtrip failed", sec)
		}
	}
}

// TestForcePortableAES exercises the portable AES path even on accelerated
// architectures, guaranteeing the fallback code stays covered and correct.
func TestForcePortableAES(t *testing.T) {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(255 - i)
	}
	c, err := NewCipher(aes.NewCipher, key)
	if err != nil {
		t.Fatal(err)
	}
	// Force the portable path regardless of architecture.
	c.accelerated = false
	ref, _ := xref.NewCipher(aes.NewCipher, key)
	pt := make([]byte, 512)
	for i := range pt {
		pt[i] = byte(i * 3)
	}
	want := make([]byte, len(pt))
	ref.Encrypt(want, pt, 12345)
	got := make([]byte, len(pt))
	c.Encrypt(got, pt, 12345)
	if !bytes.Equal(got, want) {
		t.Fatal("forced-portable AES encrypt mismatch")
	}
	back := make([]byte, len(pt))
	c.Decrypt(back, got, 12345)
	if !bytes.Equal(back, pt) {
		t.Fatal("forced-portable AES decrypt mismatch")
	}
}

func TestNewCipherErrors(t *testing.T) {
	// Wrong key length for AES surfaces from cipherFunc.
	if _, err := NewCipher(aes.NewCipher, make([]byte, 30)); err == nil {
		t.Fatal("expected error for invalid AES key length")
	}
	// A cipher with a non-16 block size must be rejected.
	if _, err := NewCipher(func(k []byte) (cipher.Block, error) {
		return des8{}, nil
	}, make([]byte, 16)); err == nil {
		t.Fatal("expected error for 8-byte block size")
	}
	// cipherFunc failing on the second (k2) key half.
	calls := 0
	_, err := NewCipher(func(k []byte) (cipher.Block, error) {
		calls++
		if calls == 2 {
			return nil, errFake
		}
		return fakeBlock{k: k}, nil
	}, make([]byte, 32))
	if err == nil {
		t.Fatal("expected error from k2 cipherFunc")
	}
}

// TestIsAESCipherProbeError covers the branch in isAESCipher where the probe
// call to cipherFunc fails. We build a cipherFunc that succeeds for the real
// 16-byte key halves but rejects the all-zero probe isAESCipher uses, so the
// accelerated path is declined and the portable path is taken.
func TestIsAESCipherProbeError(t *testing.T) {
	allZero := func(b []byte) bool {
		for _, x := range b {
			if x != 0 {
				return false
			}
		}
		return true
	}
	cf := func(k []byte) (cipher.Block, error) {
		if allZero(k) {
			return nil, errFake // reject the isAESCipher probe
		}
		return fakeBlock{k: k}, nil
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	c, err := NewCipher(cf, key)
	if err != nil {
		t.Fatal(err)
	}
	if c.accelerated {
		t.Fatal("probe error must decline acceleration")
	}
}

type des8 struct{}

func (des8) BlockSize() int          { return 8 }
func (des8) Encrypt(dst, src []byte) {}
func (des8) Decrypt(dst, src []byte) {}

var errFake = bytesError("boom")

type bytesError string

func (e bytesError) Error() string { return string(e) }

func TestPanics(t *testing.T) {
	key := make([]byte, 64)
	c, _ := NewCipher(aes.NewCipher, key)
	mustPanic(t, "short ct", func() { c.Encrypt(make([]byte, 8), make([]byte, 16), 0) })
	mustPanic(t, "non-block pt", func() { c.Encrypt(make([]byte, 16), make([]byte, 8), 0) })
	mustPanic(t, "short pt dec", func() { c.Decrypt(make([]byte, 8), make([]byte, 16), 0) })
	mustPanic(t, "non-block ct dec", func() { c.Decrypt(make([]byte, 16), make([]byte, 8), 0) })
}

func mustPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatalf("%s: expected panic", name)
		}
	}()
	fn()
}
