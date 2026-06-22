//go:build amd64

package xts

import "golang.org/x/sys/cpu"

// accelAvailable reports whether the fused assembly AES-XTS kernel can be used
// on this amd64 CPU. Unlike arm64, AES-NI is optional on amd64, so we gate on
// the CPUID feature bits. Without AES-NI (and the SSE3/PCLMUL the kernel uses)
// we fall back to the portable per-block path.
var accelAvailable = cpu.X86.HasAES && cpu.X86.HasSSE3

// xtsEncSectorAsm encrypts p in place using AES-XTS (AES-NI), pipelined 4
// blocks wide. See accel_arm64.go for the parameter contract.
//
//go:noescape
func xtsEncSectorAsm(p []byte, enc *byte, rounds int, tweak *byte)

// xtsDecSectorAsm decrypts p in place using AES-XTS (AES-NI). dec is the
// AESDEC-ready schedule built by expandDec.
//
//go:noescape
func xtsDecSectorAsm(p []byte, dec *byte, rounds int, tweak *byte)
