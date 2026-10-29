package apfs

// keybag_blob.go implements Apple's ASN.1 DER-encoded VEKBLOB / KEKBLOB
// payloads carried inside KB_TAG_VOLUME_KEY (container keybag) and
// KB_TAG_VOLUME_PASSPHRASE (volume keybag) entries.
//
// The structures are documented at
// https://jtsylve.blog/post/2022/12/22/APFS-Wrapped-Keys and validated
// empirically against an Apple `diskutil apfs encryptVolume` reference
// DMG (see pkg/go-filesystems/apfs/probe_apple_keybag_darwin_test.go).
//
//	VEKBLOB ::= SEQUENCE {
//	    [0] INTEGER       version (0)
//	    [1] OCTET STRING  hmac    (32 bytes; HMAC-SHA256 of the keyblob DER)
//	    [2] OCTET STRING  salt    (8 bytes; per-instance, also feeds the
//	                               HMAC-key derivation)
//	    [3] SEQUENCE {
//	        [0] INTEGER       version (0)
//	        [1] OCTET STRING  uuid   (volume UUID, 16 bytes)
//	        [2] INTEGER       flags  (8-byte LE in Apple's encoding)
//	        [3] OCTET STRING  AES-KW(KEK, VEK)  (40 bytes for a 32-byte VEK)
//	    }
//	}
//
//	KEKBLOB extends VEKBLOB's inner keyblob with PBKDF2 parameters:
//
//	    [4] INTEGER       iterations (PBKDF2 round count)
//	    [5] OCTET STRING  salt2      (PBKDF2 salt, 16 bytes typically)
//
// HMAC key derivation (kbhmacKey below) is:
//
//	hmac_key = SHA-256(keybagHMACMagic || salt)
//
// where keybagHMACMagic is the 6-byte constant Apple ships in apfs.kext
// (`\x01\x16\x20\x17\x15\x05`). The salt is the [2] OCTET STRING from
// the same blob.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// keybagHMACMagic is the 6-byte constant Apple's apfs.kext concatenates
// with the per-blob salt before SHA-256-ing it down to the HMAC key.
// Source: https://jtsylve.blog/post/2022/12/22/APFS-Wrapped-Keys
var keybagHMACMagic = [6]byte{0x01, 0x16, 0x20, 0x17, 0x15, 0x05}

// kbhmacKey returns the HMAC-SHA256 key used to sign a keybag blob's
// inner keyblob: SHA-256(magic || salt).
func kbhmacKey(salt []byte) []byte {
	h := sha256.New()
	h.Write(keybagHMACMagic[:])
	h.Write(salt)
	return h.Sum(nil)
}

// computeKeybagHMAC returns the HMAC-SHA256 of innerDER under the key
// derived from salt via kbhmacKey.
func computeKeybagHMAC(salt, innerDER []byte) []byte {
	mac := hmac.New(sha256.New, kbhmacKey(salt))
	mac.Write(innerDER)
	return mac.Sum(nil)
}

// derWriter is a minimal DER serialiser for the precise subset we need:
// context-tagged INTEGERs and OCTET STRINGs, plus IMPLICIT-tagged
// CONSTRUCTED SEQUENCEs. Universal SEQUENCE is supported as the outer
// envelope.
type derWriter struct {
	buf bytes.Buffer
}

func (w *derWriter) writeTag(class, tag byte, constructed bool) {
	t := class << 6
	if constructed {
		t |= 0x20
	}
	t |= tag & 0x1F
	w.buf.WriteByte(t)
}

// writeLen writes a DER length per X.690 §8.1.3. Short form (≤127) uses
// one byte; long form encodes the length on the smallest number of
// octets prefixed by 0x80|count.
func (w *derWriter) writeLen(n int) {
	if n < 0x80 {
		w.buf.WriteByte(byte(n))
		return
	}
	tmp := make([]byte, 0, 4)
	for v := n; v > 0; v >>= 8 {
		tmp = append(tmp, byte(v&0xFF))
	}
	// reverse
	for i, j := 0, len(tmp)-1; i < j; i, j = i+1, j-1 {
		tmp[i], tmp[j] = tmp[j], tmp[i]
	}
	w.buf.WriteByte(0x80 | byte(len(tmp)))
	w.buf.Write(tmp)
}

// writeContextOctets writes a context-specific [N] OCTET STRING with
// the given payload.
func (w *derWriter) writeContextOctets(tag byte, b []byte) {
	w.writeTag(2, tag, false) // class 2 = context, primitive
	w.writeLen(len(b))
	w.buf.Write(b)
}

// writeContextInteger writes a context-specific [N] INTEGER. The integer
// is encoded big-endian on the smallest number of octets that preserves
// the sign bit (per DER). v is treated as unsigned.
func (w *derWriter) writeContextInteger(tag byte, v uint64) {
	w.writeTag(2, tag, false) // primitive INTEGER
	enc := encodeUnsignedDERInt(v)
	w.writeLen(len(enc))
	w.buf.Write(enc)
}

// writeContextSequence writes a context-specific [N] CONSTRUCTED with
// the given pre-serialised inner content.
func (w *derWriter) writeContextSequence(tag byte, inner []byte) {
	w.writeTag(2, tag, true)
	w.writeLen(len(inner))
	w.buf.Write(inner)
}

// writeUniversalSequence wraps inner in a universal SEQUENCE (tag 0x30).
func (w *derWriter) writeUniversalSequence(inner []byte) {
	w.buf.WriteByte(0x30)
	w.writeLen(len(inner))
	w.buf.Write(inner)
}

func (w *derWriter) bytes() []byte { return w.buf.Bytes() }

// encodeUnsignedDERInt encodes v as a DER INTEGER. DER requires the
// minimum number of octets that represents the value, with a leading
// 0x00 prepended when the high bit of the first non-zero octet is set
// (so positive integers don't get reinterpreted as negative).
func encodeUnsignedDERInt(v uint64) []byte {
	if v == 0 {
		return []byte{0x00}
	}
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], v)
	// Strip leading zeros.
	i := 0
	for i < 7 && raw[i] == 0x00 {
		i++
	}
	out := raw[i:]
	if out[0]&0x80 != 0 {
		// Prepend a zero byte to keep the integer positive.
		return append([]byte{0x00}, out...)
	}
	cp := make([]byte, len(out))
	copy(cp, out)
	return cp
}

// buildVEKBlobInnerDER returns the DER-encoded inner keyblob:
//
//	SEQUENCE {
//	    [0] INTEGER       0
//	    [1] OCTET STRING  uuid
//	    [2] OCTET STRING  flags  (8 bytes, treated as opaque info_t per
//	                              apfs-fuse — NOT a minimal-encoding
//	                              INTEGER, even when the value is 0)
//	    [3] OCTET STRING  wrappedKey
//	}
//
// The bytes returned are the *content* of the [3] CONSTRUCTED tag in
// the outer VEKBLOB — i.e. they include the inner SEQUENCE's content
// only, without an outer SEQUENCE/CONSTRUCTED header. Caller wraps
// them with writeContextSequence.
func buildVEKBlobInnerDER(uuid [16]byte, flags uint64, wrappedKey []byte) []byte {
	var w derWriter
	w.writeContextInteger(0, 0)
	w.writeContextOctets(1, uuid[:])
	w.writeContextOctets(2, encodeFlagsOctets(flags))
	w.writeContextOctets(3, wrappedKey)
	return w.bytes()
}

// encodeFlagsOctets returns a fixed-8-byte LE encoding of v. Apple's
// VEKBLOB / KEKBLOB store the [2] field as an 8-byte OCTET STRING
// (apfs-fuse's `hdr.info`), not as a minimal-length INTEGER — using a
// short encoding here makes the resulting keybag entry shorter than
// Apple's by 7 bytes, which fsck rejects.
func encodeFlagsOctets(v uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return b[:]
}

// BuildVEKBlob returns the 124-byte (typical) DER-encoded VEKBLOB Apple
// stores in the container keybag's KB_TAG_VOLUME_KEY entry. It computes
// the HMAC-SHA256 over the inner keyblob (including the [3] CONSTRUCTED
// tag/length prefix) automatically.
//
// salt must be 8 bytes (Apple's convention). wrappedKey is the
// AES-KW(KEK, VEK) RFC-3394 ciphertext (8-byte IV + ciphertext = 40
// bytes for a 32-byte VEK).
func BuildVEKBlob(volumeUUID [16]byte, flags uint64, wrappedVEK []byte, salt []byte) ([]byte, error) {
	if len(salt) != 8 {
		return nil, fmt.Errorf("apfs: VEKBLOB salt must be 8 bytes, got %d", len(salt))
	}
	if len(wrappedVEK) < 24 || len(wrappedVEK)%8 != 0 {
		return nil, fmt.Errorf("apfs: VEKBLOB wrappedVEK length %d is not a valid AES-KW ciphertext", len(wrappedVEK))
	}
	innerDER := buildVEKBlobInnerDER(volumeUUID, flags, wrappedVEK)

	// Apple's apfs.kext computes the HMAC over the bytes from the [3]
	// CONSTRUCTED tag through the end of the outer SEQUENCE body. Since
	// nothing follows [3] in our writer, that's just the [3] tag+length
	// prefix concatenated with innerDER.
	innerWithHeader := wrapContextConstructedDER(3, innerDER)
	mac := computeKeybagHMAC(salt, innerWithHeader)

	var outer derWriter
	outer.writeContextInteger(0, 0)         // version
	outer.writeContextOctets(1, mac)        // HMAC-SHA256
	outer.writeContextOctets(2, salt)       // salt
	outer.writeContextSequence(3, innerDER) // inner keyblob

	var envelope derWriter
	envelope.writeUniversalSequence(outer.bytes())
	return envelope.bytes(), nil
}

// wrapContextConstructedDER returns the bytes of a context-tagged
// CONSTRUCTED structure: tag (0xA0|num) + length octets + content.
// Used to compute the HMAC input that includes the [3] header — Apple's
// apfs.kext HMACs over the whole [3] envelope, not just its content.
func wrapContextConstructedDER(tag byte, content []byte) []byte {
	var w derWriter
	w.writeTag(2, tag, true) // class=context, constructed
	w.writeLen(len(content))
	w.buf.Write(content)
	return w.bytes()
}

// buildKEKBlobInnerDER mirrors buildVEKBlobInnerDER but appends the
// PBKDF2 iteration count and salt that Apple stores for KEK-protecting
// passphrase lockers.
func buildKEKBlobInnerDER(uuid [16]byte, flags uint64, wrappedKEK []byte, iterations uint32, pbkdf2Salt []byte) []byte {
	var w derWriter
	w.writeContextInteger(0, 0)
	w.writeContextOctets(1, uuid[:])
	w.writeContextOctets(2, encodeFlagsOctets(flags))
	w.writeContextOctets(3, wrappedKEK)
	w.writeContextInteger(4, uint64(iterations))
	w.writeContextOctets(5, pbkdf2Salt)
	return w.bytes()
}

// vekBlobParse holds the fields ParseVEKBlob extracts from a VEKBLOB.
type vekBlobParse struct {
	UUID       [16]byte
	WrappedKey []byte // AES-KW(KEK, VEK) — typically 40 bytes for a 32-byte VEK
}

// kekBlobParse holds the fields ParseKEKBlob extracts from a KEKBLOB.
type kekBlobParse struct {
	UUID       [16]byte
	WrappedKey []byte // AES-KW(derivedKey, KEK)
	Iterations uint32 // PBKDF2 iteration count
	PBKDF2Salt []byte // PBKDF2 salt
}

// ParseVEKBlob decodes a VEKBLOB (the data field of a container
// keybag's KB_TAG_VOLUME_KEY entry) and returns the inner volume UUID
// and AES-KW(KEK, VEK) ciphertext. The HMAC field is not verified here
// — apfs.kext checks it and we trust that path; if a corrupt blob ever
// makes it to AESKeyUnwrap the unwrap will fail.
func ParseVEKBlob(der []byte) (vekBlobParse, error) {
	var out vekBlobParse
	f, err := blobInnerFields(der, 3, "VEKBLOB")
	if err != nil {
		return out, err
	}
	// [1] uuid, [2] flags (skipped), [3] wrapped key
	if len(f[0]) != 16 {
		return out, fmt.Errorf("apfs: VEKBLOB inner uuid length %d, want 16", len(f[0]))
	}
	copy(out.UUID[:], f[0])
	out.WrappedKey = append([]byte{}, f[2]...)
	return out, nil
}

// ParseKEKBlob decodes a KEKBLOB (the data field of a volume keybag's
// KB_TAG_VOLUME_PASSPHRASE entry) and returns the inner UUID, the
// AES-KW(derivedKey, KEK) ciphertext, and the PBKDF2 iteration count
// and salt needed to derive the unwrap key from a passphrase.
func ParseKEKBlob(der []byte) (kekBlobParse, error) {
	var out kekBlobParse
	f, err := blobInnerFields(der, 5, "KEKBLOB")
	if err != nil {
		return out, err
	}
	// [1] uuid, [2] flags (skipped), [3] wrapped KEK, [4] iterations, [5] salt
	if len(f[0]) != 16 {
		return out, fmt.Errorf("apfs: KEKBLOB inner uuid length %d, want 16", len(f[0]))
	}
	copy(out.UUID[:], f[0])
	out.WrappedKey = append([]byte{}, f[2]...)
	// [4] is an unsigned INTEGER: up to 4 value bytes, plus a leading 0x00
	// when the top bit is set (encodeUnsignedDERInt).
	it := f[3]
	if len(it) == 5 && it[0] == 0 {
		it = it[1:]
	}
	if len(it) == 0 || len(it) > 4 {
		return out, fmt.Errorf("apfs: KEKBLOB iteration count of %d bytes", len(f[3]))
	}
	for _, b := range it {
		out.Iterations = out.Iterations<<8 | uint32(b)
	}
	out.PBKDF2Salt = append([]byte{}, f[4]...)
	return out, nil
}

// blobInnerFields walks a keybag blob -- SEQUENCE { [0] version?, [1] HMAC,
// [2] salt, [3] { [0] version?, field1 ... fieldN } } -- and returns the
// contents of the first n fields of the [3] envelope. Every length is checked
// against what is left: the blob comes from an image.
func blobInnerFields(der []byte, n int, what string) ([][]byte, error) {
	tag, body, _, err := derTLV(der, 0)
	if err != nil || tag != 0x30 {
		return nil, fmt.Errorf("apfs: %s outer not a SEQUENCE", what)
	}
	pos := skipDERVersion(body)
	for range 2 { // [1] HMAC, [2] outer salt
		if _, _, pos, err = derTLV(body, pos); err != nil {
			return nil, fmt.Errorf("apfs: %s: %w", what, err)
		}
	}
	tag, inner, _, err := derTLV(body, pos)
	if err != nil {
		return nil, fmt.Errorf("apfs: %s: %w", what, err)
	}
	if tag != 0xa3 {
		return nil, fmt.Errorf("apfs: %s [3] tag = 0x%x, want 0xa3", what, tag)
	}
	ipos := skipDERVersion(inner)
	out := make([][]byte, n)
	for i := range out {
		if _, out[i], ipos, err = derTLV(inner, ipos); err != nil {
			return nil, fmt.Errorf("apfs: %s inner field %d: %w", what, i+1, err)
		}
	}
	return out, nil
}

// derTLV reads one DER tag-length-value at off: its tag, its contents and the
// offset just past it. Long-form lengths of up to 3 octets are accepted (a
// blob lives in a keybag block, at most 64 KiB); a length past the end of b
// is an error, never a panic.
func derTLV(b []byte, off int) (tag byte, content []byte, next int, err error) {
	if off < 0 || off > len(b)-2 {
		return 0, nil, 0, fmt.Errorf("DER field at %d past the end (%d bytes)", off, len(b))
	}
	tag = b[off]
	l, p := int(b[off+1]), off+2
	if l&0x80 != 0 {
		nb := l & 0x7f
		if nb == 0 || nb > 3 || nb > len(b)-p {
			return 0, nil, 0, fmt.Errorf("DER length of %d octets at %d", nb, off)
		}
		l = 0
		for _, c := range b[p : p+nb] {
			l = l<<8 | int(c)
		}
		p += nb
	}
	if l > len(b)-p {
		return 0, nil, 0, fmt.Errorf("DER field at %d: length %d, %d bytes left", off, l, len(b)-p)
	}
	return tag, b[p : p+l], p + l, nil
}

// skipDERVersion returns the offset just past a leading [0] INTEGER version
// field (typically `80 01 00`), or 0 when there is none or it is malformed.
func skipDERVersion(b []byte) int {
	if len(b) == 0 || b[0] != 0x80 {
		return 0
	}
	if _, _, next, err := derTLV(b, 0); err == nil {
		return next
	}
	return 0
}

// BuildKEKBlob returns the DER-encoded KEKBLOB Apple stores in the
// volume keybag's KB_TAG_VOLUME_PASSPHRASE entry. wrappedKEK must be
// the AES-KW ciphertext of the KEK under the PBKDF2-derived key.
//
// hmacSalt is the 8-byte salt that feeds the outer HMAC key derivation
// (kbhmacKey). pbkdf2Salt is the salt PBKDF2 was called with — typically
// 16 bytes per Apple's reference. The two salts are independent.
func BuildKEKBlob(userUUID [16]byte, flags uint64, wrappedKEK []byte, iterations uint32, pbkdf2Salt []byte, hmacSalt []byte) ([]byte, error) {
	if len(hmacSalt) != 8 {
		return nil, fmt.Errorf("apfs: KEKBLOB outer salt must be 8 bytes, got %d", len(hmacSalt))
	}
	if len(wrappedKEK) < 24 || len(wrappedKEK)%8 != 0 {
		return nil, fmt.Errorf("apfs: KEKBLOB wrappedKEK length %d is not a valid AES-KW ciphertext", len(wrappedKEK))
	}
	innerDER := buildKEKBlobInnerDER(userUUID, flags, wrappedKEK, iterations, pbkdf2Salt)
	mac := computeKeybagHMAC(hmacSalt, wrapContextConstructedDER(3, innerDER))

	var outer derWriter
	outer.writeContextInteger(0, 0)
	outer.writeContextOctets(1, mac)
	outer.writeContextOctets(2, hmacSalt)
	outer.writeContextSequence(3, innerDER)

	var envelope derWriter
	envelope.writeUniversalSequence(outer.bytes())
	return envelope.bytes(), nil
}
