//go:build !arm64 && !amd64

package xts

// accelAvailable is false on architectures without a fused assembly AES-XTS
// kernel (riscv64, loong64, ppc64le, s390x). Encrypt/Decrypt use the portable
// per-block path, which is byte-for-byte identical to golang.org/x/crypto/xts.
const accelAvailable = false

// xtsEncSectorAsm and xtsDecSectorAsm are never called on these architectures
// (accelAvailable is false, so c.accelerated is always false). They exist only
// so the architecture-independent code in xts.go compiles. If they were ever
// reached it would indicate a logic error, so they panic.
func xtsEncSectorAsm(p []byte, enc *byte, rounds int, tweak *byte) {
	panic("xts: assembly kernel called on an unsupported architecture")
}

func xtsDecSectorAsm(p []byte, dec *byte, rounds int, tweak *byte) {
	panic("xts: assembly kernel called on an unsupported architecture")
}
