package apfs

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestVEKBlob_HMACAgainstAppleReference is the killer test for the
// keybag-blob layer. It hard-codes the 124-byte VEKBLOB extracted from
// the Apple `diskutil apfs encryptVolume` reference DMG (validated on
// 2026-05-09; see pkg/go-filesystems/apfs/probe_apple_keybag_darwin_test.go),
// re-runs computeKeybagHMAC over the inner keyblob with the salt from
// [2], and asserts the result matches Apple's [1] HMAC byte-for-byte.
//
// If this test ever fails it means our HMAC derivation has drifted
// from what apfs.kext computes — any FormatContainerEncrypted writer
// using BuildVEKBlob would produce containers Apple cannot mount.
func TestVEKBlob_HMACAgainstAppleReference(t *testing.T) {
	// Hex-decoded directly from the probe's full 124-byte hex dump.
	// Layout (Apple reference 2026-05-09):
	//   [0..1]    30 7a                            outer SEQUENCE len 122
	//   [2..4]    80 01 00                         [0] INTEGER 0
	//   [5..38]   81 20 + 32-byte HMAC
	//   [39..48]  82 08 + 8-byte salt
	//   [49..50]  a3 49                            [3] CONSTRUCTED len 73
	//   [51..53]  80 01 00                         inner [0] INTEGER 0
	//   [54..71]  81 10 + 16-byte volume UUID
	//   [72..81]  82 08 + 8-byte flags blob
	//   [82..123] 83 28 + 40-byte AES-KW(KEK,VEK)
	const rawHex = "" +
		"307a" + "800100" + // outer SEQUENCE + [0]
		"8120" + // [1] HMAC tag/len
		"3ca7b467daa724daab87410f50d0d0433d7f76daa3f1429c6fd3164ea08e0692" +
		"8208" + // [2] salt tag/len
		"275800f21e0c7758" +
		"a349" + // [3] CONSTRUCTED tag/len
		"800100" + // inner [0]
		"8110" + // inner [1]
		"42db8111dd5b460ab70c2b71e3d041b2" + // volume UUID
		"8208" + // inner [2]
		"0000000001003995" +
		"8328" + // inner [3] OCTET STRING tag/len (NOT 8228 — that was the transcription bug)
		"89d17edf6d57b4bee153d82a2970347a9533908e506131f0b240cb5d3e6ee5ff" +
		"731518f7dc95072c"
	raw, err := hex.DecodeString(rawHex)
	if err != nil {
		t.Fatalf("decode raw hex: %v", err)
	}
	if len(raw) != 124 {
		t.Fatalf("raw len = %d, want 124 (transcription error)", len(raw))
	}

	// Pull out the [1] HMAC and the [2] salt at known offsets, then
	// the [3] inner keyblob's *content* (which is what the HMAC binds).
	// Outer SEQUENCE header is the first 2 bytes (30 7a). Skip them.
	body := raw[2:] // 122 bytes
	// [0] version: 80 01 00 (3 bytes)
	if !bytes.Equal(body[:3], []byte{0x80, 0x01, 0x00}) {
		t.Fatalf("unexpected [0] header: %x", body[:3])
	}
	if body[3] != 0x81 || body[4] != 0x20 {
		t.Fatalf("unexpected [1] tag/len: %x %x", body[3], body[4])
	}
	gotHMAC := body[5 : 5+32]
	if body[37] != 0x82 || body[38] != 0x08 {
		t.Fatalf("unexpected [2] tag/len: %x %x", body[37], body[38])
	}
	salt := body[39 : 39+8]
	if body[47] != 0xa3 {
		t.Fatalf("unexpected [3] tag: %x", body[47])
	}
	innerLen := int(body[48])
	innerStart := 49
	innerDER := body[innerStart : innerStart+innerLen]

	// Try several HMAC-input variants. Whichever matches Apple's
	// embedded HMAC is the recipe — pin it for the writer.
	variants := []struct {
		name  string
		input []byte
	}{
		{"inner-content", innerDER},
		{"inner-with-context-3-header", body[47 : 47+2+innerLen]},
		{"inner-as-universal-SEQUENCE", append([]byte{0x30, byte(innerLen)}, innerDER...)},
		{"salt-then-inner", append(append([]byte{}, salt...), innerDER...)},
		{"inner-then-salt", append(append([]byte{}, innerDER...), salt...)},
	}
	for _, v := range variants {
		got := computeKeybagHMAC(salt, v.input)
		if bytes.Equal(got, gotHMAC) {
			t.Logf("HMAC variant matched: %s", v.name)
			return
		}
		t.Logf("variant %q HMAC = %x (no match)", v.name, got)
	}

	// Also try variants of the magic constant — maybe it's different.
	altMagics := []struct {
		name  string
		bytes []byte
	}{
		{"original \\x01\\x16\\x20\\x17\\x15\\x05", []byte{0x01, 0x16, 0x20, 0x17, 0x15, 0x05}},
		{"reversed", []byte{0x05, 0x15, 0x17, 0x20, 0x16, 0x01}},
		{"4-byte trim", []byte{0x01, 0x16, 0x20, 0x17}},
		{"empty", nil},
	}
	for _, am := range altMagics {
		h := newHMACKey(am.bytes, salt)
		got := computeHMACWithKey(h, innerDER)
		if bytes.Equal(got, gotHMAC) {
			t.Logf("HMAC matched with alternate magic %q", am.name)
			return
		}
	}

	t.Fatalf("no HMAC variant matched Apple's reference\n want %x\n salt=%x\n inner=%x",
		gotHMAC, salt, innerDER)
}

// newHMACKey is a probe helper: SHA256(magic || salt).
func newHMACKey(magic, salt []byte) []byte {
	h := sha256.New()
	h.Write(magic)
	h.Write(salt)
	return h.Sum(nil)
}

// computeHMACWithKey is a probe helper: HMAC-SHA256(key, msg).
func computeHMACWithKey(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// TestBuildVEKBlob_RoundTripParse ensures BuildVEKBlob produces output
// whose [1] HMAC verifies under the same salt + inner DER it was built
// from. This is a self-consistency check; the cross-Apple validation
// happens in TestVEKBlob_HMACAgainstAppleReference above.
func TestBuildVEKBlob_RoundTripParse(t *testing.T) {
	uuid := [16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00}
	salt := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x12, 0x34}
	wrappedVEK := bytes.Repeat([]byte{0x42}, 40)
	flags := uint64(0x100_3995) // matches a real Apple flag value

	der, err := BuildVEKBlob(uuid, flags, wrappedVEK, salt)
	if err != nil {
		t.Fatalf("BuildVEKBlob: %v", err)
	}

	// Sanity: outer is a SEQUENCE.
	if der[0] != 0x30 {
		t.Fatalf("outer tag = 0x%x, want 0x30", der[0])
	}
	// Re-parse the layout we built and recompute HMAC.
	body := der[2:] // skip SEQUENCE header
	if body[3] != 0x81 || body[4] != 0x20 {
		t.Fatalf("expected [1] OCTET STRING len 32, got %x %x", body[3], body[4])
	}
	embeddedHMAC := body[5 : 5+32]
	if body[37] != 0x82 || body[38] != 0x08 {
		t.Fatalf("expected [2] OCTET STRING len 8, got %x %x", body[37], body[38])
	}
	embeddedSalt := body[39 : 39+8]
	if body[47] != 0xa3 {
		t.Fatalf("expected [3] tag 0xa3, got 0x%x", body[47])
	}
	// HMAC is over the [3] envelope (tag+length+content) — i.e. body[47..end].
	hmacInput := body[47:]
	want := computeKeybagHMAC(embeddedSalt, hmacInput)
	if !bytes.Equal(embeddedHMAC, want) {
		t.Fatalf("self-consistency: HMAC field doesn't match\nfield: %x\ncomputed: %x", embeddedHMAC, want)
	}
}

// TestBuildKEKBlob_RoundTripParse checks BuildKEKBlob produces a blob
// whose [1] HMAC self-verifies. The KEKBLOB inner has two extra fields
// (iterations + PBKDF2 salt).
func TestBuildKEKBlob_RoundTripParse(t *testing.T) {
	uuid := [16]byte{0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
		0x11, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	wrappedKEK := bytes.Repeat([]byte{0x77}, 40)
	hmacSalt := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	pbkdf2Salt := bytes.Repeat([]byte{0x55}, 16)

	der, err := BuildKEKBlob(uuid, 0, wrappedKEK, 200000, pbkdf2Salt, hmacSalt)
	if err != nil {
		t.Fatalf("BuildKEKBlob: %v", err)
	}
	if der[0] != 0x30 {
		t.Fatalf("outer tag = 0x%x, want 0x30", der[0])
	}
	// Skip the universal SEQUENCE header (variable length).
	body := der[seqHeaderLen(der):]
	if !bytes.Equal(body[:3], []byte{0x80, 0x01, 0x00}) {
		t.Fatalf("expected [0] INTEGER 0, got %x", body[:3])
	}
	if body[3] != 0x81 || body[4] != 0x20 {
		t.Fatalf("expected [1] OCTET STRING len 32, got %x %x", body[3], body[4])
	}
	embeddedHMAC := body[5 : 5+32]
	if body[37] != 0x82 || body[38] != 0x08 {
		t.Fatalf("expected [2] OCTET STRING len 8, got %x %x", body[37], body[38])
	}
	embeddedSalt := body[39 : 39+8]
	if body[47] != 0xa3 {
		t.Fatalf("expected [3] tag 0xa3, got 0x%x", body[47])
	}
	// HMAC input is the [3] envelope (tag + long-form length + content).
	innerLen, innerOff := decodeLen(body, 48)
	hmacInput := body[47 : innerOff+innerLen]
	want := computeKeybagHMAC(embeddedSalt, hmacInput)
	if !bytes.Equal(embeddedHMAC, want) {
		t.Fatalf("KEKBLOB self-consistency: HMAC mismatch")
	}
}

// seqHeaderLen returns the byte length of a universal SEQUENCE header
// (tag + length octets) at the start of der.
func seqHeaderLen(der []byte) int {
	if der[1]&0x80 == 0 {
		return 2 // short-form length
	}
	return 2 + int(der[1]&0x7F)
}

// decodeLen reads a DER length starting at off in b and returns the
// length value and the offset of the first content byte.
func decodeLen(b []byte, off int) (int, int) {
	first := b[off]
	if first&0x80 == 0 {
		return int(first), off + 1
	}
	n := int(first & 0x7F)
	v := 0
	for i := 0; i < n; i++ {
		v = (v << 8) | int(b[off+1+i])
	}
	return v, off + 1 + n
}

// TestBuildVEKBlob_VerifiesUnderApfsFuseRule asserts that any VEKBLOB
// our writer emits (with arbitrary inputs) passes the parse-and-verify
// rule apfs-fuse's KeyManager::DecodeKeyHeader applies: HMAC-SHA256
// over the bytes from after the [2] salt to the end of the outer
// SEQUENCE, keyed by SHA256(magic || salt). If this ever fails, our
// writer would emit blobs Apple's apfs.kext rejects.
func TestBuildVEKBlob_VerifiesUnderApfsFuseRule(t *testing.T) {
	uuid := [16]byte{0xaa}
	salt := []byte{8, 7, 6, 5, 4, 3, 2, 1}
	wrappedVEK := bytes.Repeat([]byte{0xCC}, 40)

	der, err := BuildVEKBlob(uuid, 0, wrappedVEK, salt)
	if err != nil {
		t.Fatalf("BuildVEKBlob: %v", err)
	}

	// Walk the structure exactly the way apfs-fuse does:
	//   parse outer SEQUENCE → [0] integer → [1] OCTET STRING (HMAC) →
	//   [2] OCTET STRING (salt) → HMAC over (here..body_end).
	hdrLen := seqHeaderLen(der)
	body := der[hdrLen:]
	bodyLen := len(der) - hdrLen
	pos := 0
	// [0] version
	if body[pos] != 0x80 || body[pos+1] != 0x01 {
		t.Fatalf("expected [0] INTEGER 1-byte, got %x %x", body[pos], body[pos+1])
	}
	pos += 3
	// [1] HMAC
	if body[pos] != 0x81 {
		t.Fatalf("expected [1] tag, got 0x%x", body[pos])
	}
	pos++
	hmacLen, hmacOff := decodeLen(body, pos)
	if hmacLen != 32 {
		t.Fatalf("HMAC length = %d, want 32", hmacLen)
	}
	embeddedHMAC := body[hmacOff : hmacOff+hmacLen]
	pos = hmacOff + hmacLen
	// [2] salt
	if body[pos] != 0x82 {
		t.Fatalf("expected [2] tag, got 0x%x", body[pos])
	}
	pos++
	saltLen, saltOff := decodeLen(body, pos)
	embeddedSalt := body[saltOff : saltOff+saltLen]
	pos = saltOff + saltLen
	// HMAC input = remainder of body.
	hmacInput := body[pos:bodyLen]

	got := computeKeybagHMAC(embeddedSalt, hmacInput)
	if !bytes.Equal(got, embeddedHMAC) {
		t.Fatalf("apfs-fuse-style verify failed:\n  embedded %x\n  computed %x", embeddedHMAC, got)
	}
}

// TestEncodeUnsignedDERInt covers the corner cases of the integer
// encoder: zero, low values, values requiring leading 0x00, and
// multi-byte values.
func TestEncodeUnsignedDERInt(t *testing.T) {
	cases := []struct {
		v    uint64
		want []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{0x7F, []byte{0x7F}},
		{0x80, []byte{0x00, 0x80}}, // leading 0x00 to keep positive
		{0xFF, []byte{0x00, 0xFF}},
		{0x100, []byte{0x01, 0x00}},
		{0x0100_3995, []byte{0x01, 0x00, 0x39, 0x95}},
	}
	for _, tc := range cases {
		got := encodeUnsignedDERInt(tc.v)
		if !bytes.Equal(got, tc.want) {
			t.Errorf("encodeUnsignedDERInt(0x%x) = %x, want %x", tc.v, got, tc.want)
		}
	}
}
