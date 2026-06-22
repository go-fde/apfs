//go:build arm64

package xts

// accelAvailable reports that a fused assembly AES-XTS kernel exists for arm64
// (ARMv8 AES + NEON). All current arm64 hardware that Go targets implements the
// AES crypto extension; the Go runtime requires it, so no feature probe is
// needed.
const accelAvailable = true

// xtsEncSectorAsm encrypts p in place (len a non-zero multiple of 16) using
// AES-XTS. enc is the flat encryption round-key schedule, rounds the AES round
// count (10 for AES-128, 14 for AES-256), and tweak the pre-encrypted initial
// tweak T0; on return *tweak holds the tweak following the last block.
//
//go:noescape
func xtsEncSectorAsm(p []byte, enc *byte, rounds int, tweak *byte)

// xtsDecSectorAsm decrypts p in place using AES-XTS. dec is the AESD-ready
// decryption schedule (InvMixColumns folded into the inner round keys).
//
//go:noescape
func xtsDecSectorAsm(p []byte, dec *byte, rounds int, tweak *byte)
