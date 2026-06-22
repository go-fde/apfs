//go:build arm64

#include "textflag.h"

// gf_double doubles the XTS tweak held in NEON register V (16 bytes, stored in
// little-endian order: V.D[0] is the low 64 bits, V.D[1] the high 64 bits).
// It computes V = (V << 1) in GF(2^128) with the XTS reduction polynomial
// x^128 + x^7 + x^2 + x + 1 (constant 0x87). Tmp1/Tmp2 are scratch GPRs.
//
//   lo' = (lo << 1)
//   hi' = (hi << 1) | (lo >> 63)
//   if (hi >> 63) != 0 { lo' ^= 0x87 }
//
// Implemented with general-purpose registers for clarity and correctness; the
// AES rounds dominate, so this is not on the hot path.
#define gf_double(V) \
	VMOV	V.D[0], R14;   \
	VMOV	V.D[1], R15;   \
	LSR	$63, R15, R11; \
	LSR	$63, R14, R12; \
	LSL	$1, R14, R14;  \
	LSL	$1, R15, R15;  \
	ORR	R12, R15, R15; \
	MOVD	$0x87, R13;    \
	MUL	R11, R13, R13; \
	EOR	R13, R14, R14; \
	VMOV	R14, V.D[0];   \
	VMOV	R15, V.D[1]

// func xtsEncSectorAsm(p []byte, enc *byte, rounds int, tweak *byte)
//
// Encrypts p (a multiple of 16 bytes, typically a 512-byte sector) in place
// using AES-XTS. The initial tweak T0 is read from *tweak; on return *tweak
// holds the tweak that follows the last processed block (so the same sector
// buffer can be processed in chunks). enc points to the flat encryption round
// key schedule (16*(rounds+1) bytes, big-endian word layout matching the
// FIPS-197 schedule, directly usable by AESE).
//
// Blocks are pipelined 4-wide to keep the AESE/AESMC units busy; a tail loop
// handles the final 1-3 blocks.
TEXT ·xtsEncSectorAsm(SB), NOSPLIT, $0-48
	MOVD	p_base+0(FP), R0	// data pointer
	MOVD	p_len+8(FP), R1		// data length
	MOVD	enc+24(FP), R2		// round-key pointer
	MOVD	rounds+32(FP), R3	// round count
	MOVD	tweak+40(FP), R4	// tweak pointer

	VLD1	(R4), [V8.B16]		// V8 = current tweak T

	// number of full 4-block groups
	LSR	$6, R1, R5		// R5 = len / 64
	AND	$63, R1, R6		// R6 = len % 64 (remaining bytes)

	CBZ	R5, enc_tail

enc_group_loop:
	// Compute tweaks T0..T3 for the 4 blocks into V8,V9,V10,V11.
	VMOV	V8.B16, V9.B16
	gf_double(V9)	// V9 = T1 = T0<<1
	VMOV	V9.B16, V10.B16
	gf_double(V10)	// V10 = T2
	VMOV	V10.B16, V11.B16
	gf_double(V11)	// V11 = T3

	// Load 4 plaintext blocks.
	VLD1	(R0), [V0.B16, V1.B16, V2.B16, V3.B16]
	// PP = P xor T
	VEOR	V0.B16, V8.B16, V0.B16
	VEOR	V1.B16, V9.B16, V1.B16
	VEOR	V2.B16, V10.B16, V2.B16
	VEOR	V3.B16, V11.B16, V3.B16

	// AES encrypt 4 blocks. Round keys streamed from R2; restore R2 after.
	MOVD	R2, R8			// rk cursor
	SUB	$1, R3, R9		// number of AESE+AESMC rounds (rounds-1)
enc_round_loop:
	VLD1.P	16(R8), [V14.B16]
	AESE	V14.B16, V0.B16
	AESMC	V0.B16, V0.B16
	AESE	V14.B16, V1.B16
	AESMC	V1.B16, V1.B16
	AESE	V14.B16, V2.B16
	AESMC	V2.B16, V2.B16
	AESE	V14.B16, V3.B16
	AESMC	V3.B16, V3.B16
	SUBS	$1, R9
	BNE	enc_round_loop
	// Penultimate round key: AESE only (no MixColumns).
	VLD1.P	16(R8), [V14.B16]
	AESE	V14.B16, V0.B16
	AESE	V14.B16, V1.B16
	AESE	V14.B16, V2.B16
	AESE	V14.B16, V3.B16
	// Final round key: XOR.
	VLD1	(R8), [V14.B16]
	VEOR	V0.B16, V14.B16, V0.B16
	VEOR	V1.B16, V14.B16, V1.B16
	VEOR	V2.B16, V14.B16, V2.B16
	VEOR	V3.B16, V14.B16, V3.B16

	// CC = C xor T
	VEOR	V0.B16, V8.B16, V0.B16
	VEOR	V1.B16, V9.B16, V1.B16
	VEOR	V2.B16, V10.B16, V2.B16
	VEOR	V3.B16, V11.B16, V3.B16
	VST1	[V0.B16, V1.B16, V2.B16, V3.B16], (R0)

	ADD	$64, R0
	// Advance tweak: T <- T3 doubled once more.
	VMOV	V11.B16, V8.B16
	gf_double(V8)
	SUBS	$1, R5
	BNE	enc_group_loop

enc_tail:
	// Handle remaining whole blocks (R6 bytes, each 16).
	LSR	$4, R6, R5		// number of tail blocks
	CBZ	R5, enc_done
enc_tail_loop:
	VLD1	(R0), [V0.B16]
	VEOR	V0.B16, V8.B16, V0.B16
	MOVD	R2, R8
	SUB	$1, R3, R9
enc_tail_round:
	VLD1.P	16(R8), [V14.B16]
	AESE	V14.B16, V0.B16
	AESMC	V0.B16, V0.B16
	SUBS	$1, R9
	BNE	enc_tail_round
	VLD1.P	16(R8), [V14.B16]
	AESE	V14.B16, V0.B16
	VLD1	(R8), [V14.B16]
	VEOR	V0.B16, V14.B16, V0.B16
	VEOR	V0.B16, V8.B16, V0.B16
	VST1	[V0.B16], (R0)
	ADD	$16, R0
	gf_double(V8)
	SUBS	$1, R5
	BNE	enc_tail_loop

enc_done:
	VST1	[V8.B16], (R4)		// store updated tweak
	RET

// func xtsDecSectorAsm(p []byte, dec *byte, rounds int, tweak *byte)
// dec points to the decryption round-key schedule with AESIMC pre-applied to
// the inner round keys (so AESD/AESIMC consume them directly). Layout: the keys
// are in forward order [rk0 .. rkN]; decryption consumes them in reverse.
TEXT ·xtsDecSectorAsm(SB), NOSPLIT, $0-48
	MOVD	p_base+0(FP), R0
	MOVD	p_len+8(FP), R1
	MOVD	dec+24(FP), R2
	MOVD	rounds+32(FP), R3
	MOVD	tweak+40(FP), R4

	VLD1	(R4), [V8.B16]

	LSR	$6, R1, R5
	AND	$63, R1, R6
	CBZ	R5, dec_tail

dec_group_loop:
	VMOV	V8.B16, V9.B16
	gf_double(V9)
	VMOV	V9.B16, V10.B16
	gf_double(V10)
	VMOV	V10.B16, V11.B16
	gf_double(V11)

	VLD1	(R0), [V0.B16, V1.B16, V2.B16, V3.B16]
	VEOR	V0.B16, V8.B16, V0.B16
	VEOR	V1.B16, V9.B16, V1.B16
	VEOR	V2.B16, V10.B16, V2.B16
	VEOR	V3.B16, V11.B16, V3.B16

	MOVD	R2, R8
	SUB	$1, R3, R9
dec_round_loop:
	VLD1.P	16(R8), [V14.B16]
	AESD	V14.B16, V0.B16
	AESIMC	V0.B16, V0.B16
	AESD	V14.B16, V1.B16
	AESIMC	V1.B16, V1.B16
	AESD	V14.B16, V2.B16
	AESIMC	V2.B16, V2.B16
	AESD	V14.B16, V3.B16
	AESIMC	V3.B16, V3.B16
	SUBS	$1, R9
	BNE	dec_round_loop
	VLD1.P	16(R8), [V14.B16]
	AESD	V14.B16, V0.B16
	AESD	V14.B16, V1.B16
	AESD	V14.B16, V2.B16
	AESD	V14.B16, V3.B16
	VLD1	(R8), [V14.B16]
	VEOR	V0.B16, V14.B16, V0.B16
	VEOR	V1.B16, V14.B16, V1.B16
	VEOR	V2.B16, V14.B16, V2.B16
	VEOR	V3.B16, V14.B16, V3.B16

	VEOR	V0.B16, V8.B16, V0.B16
	VEOR	V1.B16, V9.B16, V1.B16
	VEOR	V2.B16, V10.B16, V2.B16
	VEOR	V3.B16, V11.B16, V3.B16
	VST1	[V0.B16, V1.B16, V2.B16, V3.B16], (R0)

	ADD	$64, R0
	VMOV	V11.B16, V8.B16
	gf_double(V8)
	SUBS	$1, R5
	BNE	dec_group_loop

dec_tail:
	LSR	$4, R6, R5
	CBZ	R5, dec_done
dec_tail_loop:
	VLD1	(R0), [V0.B16]
	VEOR	V0.B16, V8.B16, V0.B16
	MOVD	R2, R8
	SUB	$1, R3, R9
dec_tail_round:
	VLD1.P	16(R8), [V14.B16]
	AESD	V14.B16, V0.B16
	AESIMC	V0.B16, V0.B16
	SUBS	$1, R9
	BNE	dec_tail_round
	VLD1.P	16(R8), [V14.B16]
	AESD	V14.B16, V0.B16
	VLD1	(R8), [V14.B16]
	VEOR	V0.B16, V14.B16, V0.B16
	VEOR	V0.B16, V8.B16, V0.B16
	VST1	[V0.B16], (R0)
	ADD	$16, R0
	gf_double(V8)
	SUBS	$1, R5
	BNE	dec_tail_loop

dec_done:
	VST1	[V8.B16], (R4)
	RET
