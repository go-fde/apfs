//go:build amd64

#include "textflag.h"

// gfd doubles the XTS tweak held in SSE register Vt (16 bytes, little-endian:
// low 64 bits in lane 0, high 64 bits in lane 1) in GF(2^128) with the XTS
// reduction polynomial (constant 0x87). Uses GPRs R8..R11 as scratch and Vtmp
// is unused (kept for symmetry). The AES rounds dominate, so the GPR round-trip
// here is not on the hot path.
//
//   lo' = (lo << 1) ^ (hi>>63 ? 0x87 : 0)
//   hi' = (hi << 1) | (lo >> 63)
#define gfd(Vt) \
	MOVQ	Vt, R8;      \
	PEXTRQ	$1, Vt, R9;  \
	MOVQ	R9, R10;     \
	SHRQ	$63, R10;    \
	MOVQ	R8, R11;     \
	SHRQ	$63, R11;    \
	SHLQ	$1, R8;      \
	SHLQ	$1, R9;      \
	ORQ	R11, R9;     \
	IMULQ	$0x87, R10;  \
	XORQ	R10, R8;     \
	MOVQ	R8, Vt;      \
	PINSRQ	$1, R9, Vt

// func xtsEncSectorAsm(p []byte, enc *byte, rounds int, tweak *byte)
TEXT ·xtsEncSectorAsm(SB), NOSPLIT, $0-48
	MOVQ	p_base+0(FP), SI
	MOVQ	p_len+8(FP), DX
	MOVQ	enc+24(FP), BX
	MOVQ	rounds+32(FP), CX
	MOVQ	tweak+40(FP), DI

	MOVUPS	(DI), X4          // X4 = current tweak T0

	MOVQ	DX, AX
	SHRQ	$6, AX            // AX = number of 4-block groups (len/64)
	MOVQ	DX, R12
	ANDQ	$63, R12          // R12 = tail bytes
	TESTQ	AX, AX
	JZ	enc_tail

enc_group:
	// Derive tweaks T1..T3 from T0.
	MOVO	X4, X5
	gfd(X5)
	MOVO	X5, X6
	gfd(X6)
	MOVO	X6, X7
	gfd(X7)

	MOVUPS	0(SI), X0
	MOVUPS	16(SI), X1
	MOVUPS	32(SI), X2
	MOVUPS	48(SI), X3
	PXOR	X4, X0
	PXOR	X5, X1
	PXOR	X6, X2
	PXOR	X7, X3

	MOVQ	BX, R13           // round-key cursor
	// First round key: PXOR.
	MOVUPS	(R13), X8
	PXOR	X8, X0
	PXOR	X8, X1
	PXOR	X8, X2
	PXOR	X8, X3
	ADDQ	$16, R13
	MOVQ	CX, R14
	SUBQ	$1, R14           // rounds-1 AESENC rounds
enc_round:
	MOVUPS	(R13), X8
	AESENC	X8, X0
	AESENC	X8, X1
	AESENC	X8, X2
	AESENC	X8, X3
	ADDQ	$16, R13
	SUBQ	$1, R14
	JNZ	enc_round
	// Last round key: AESENCLAST.
	MOVUPS	(R13), X8
	AESENCLAST	X8, X0
	AESENCLAST	X8, X1
	AESENCLAST	X8, X2
	AESENCLAST	X8, X3

	PXOR	X4, X0
	PXOR	X5, X1
	PXOR	X6, X2
	PXOR	X7, X3
	MOVUPS	X0, 0(SI)
	MOVUPS	X1, 16(SI)
	MOVUPS	X2, 32(SI)
	MOVUPS	X3, 48(SI)

	ADDQ	$64, SI
	MOVO	X7, X4
	gfd(X4)
	SUBQ	$1, AX
	JNZ	enc_group

enc_tail:
	MOVQ	R12, AX
	SHRQ	$4, AX            // tail blocks
	TESTQ	AX, AX
	JZ	enc_done
enc_tail_loop:
	MOVUPS	(SI), X0
	PXOR	X4, X0
	MOVQ	BX, R13
	MOVUPS	(R13), X8
	PXOR	X8, X0
	ADDQ	$16, R13
	MOVQ	CX, R14
	SUBQ	$1, R14
enc_tail_round:
	MOVUPS	(R13), X8
	AESENC	X8, X0
	ADDQ	$16, R13
	SUBQ	$1, R14
	JNZ	enc_tail_round
	MOVUPS	(R13), X8
	AESENCLAST	X8, X0
	PXOR	X4, X0
	MOVUPS	X0, (SI)
	ADDQ	$16, SI
	gfd(X4)
	SUBQ	$1, AX
	JNZ	enc_tail_loop

enc_done:
	MOVUPS	X4, (DI)
	RET

// func xtsDecSectorAsm(p []byte, dec *byte, rounds int, tweak *byte)
TEXT ·xtsDecSectorAsm(SB), NOSPLIT, $0-48
	MOVQ	p_base+0(FP), SI
	MOVQ	p_len+8(FP), DX
	MOVQ	dec+24(FP), BX
	MOVQ	rounds+32(FP), CX
	MOVQ	tweak+40(FP), DI

	MOVUPS	(DI), X4

	MOVQ	DX, AX
	SHRQ	$6, AX
	MOVQ	DX, R12
	ANDQ	$63, R12
	TESTQ	AX, AX
	JZ	dec_tail

dec_group:
	MOVO	X4, X5
	gfd(X5)
	MOVO	X5, X6
	gfd(X6)
	MOVO	X6, X7
	gfd(X7)

	MOVUPS	0(SI), X0
	MOVUPS	16(SI), X1
	MOVUPS	32(SI), X2
	MOVUPS	48(SI), X3
	PXOR	X4, X0
	PXOR	X5, X1
	PXOR	X6, X2
	PXOR	X7, X3

	MOVQ	BX, R13
	MOVUPS	(R13), X8
	PXOR	X8, X0
	PXOR	X8, X1
	PXOR	X8, X2
	PXOR	X8, X3
	ADDQ	$16, R13
	MOVQ	CX, R14
	SUBQ	$1, R14
dec_round:
	MOVUPS	(R13), X8
	AESDEC	X8, X0
	AESDEC	X8, X1
	AESDEC	X8, X2
	AESDEC	X8, X3
	ADDQ	$16, R13
	SUBQ	$1, R14
	JNZ	dec_round
	MOVUPS	(R13), X8
	AESDECLAST	X8, X0
	AESDECLAST	X8, X1
	AESDECLAST	X8, X2
	AESDECLAST	X8, X3

	PXOR	X4, X0
	PXOR	X5, X1
	PXOR	X6, X2
	PXOR	X7, X3
	MOVUPS	X0, 0(SI)
	MOVUPS	X1, 16(SI)
	MOVUPS	X2, 32(SI)
	MOVUPS	X3, 48(SI)

	ADDQ	$64, SI
	MOVO	X7, X4
	gfd(X4)
	SUBQ	$1, AX
	JNZ	dec_group

dec_tail:
	MOVQ	R12, AX
	SHRQ	$4, AX
	TESTQ	AX, AX
	JZ	dec_done
dec_tail_loop:
	MOVUPS	(SI), X0
	PXOR	X4, X0
	MOVQ	BX, R13
	MOVUPS	(R13), X8
	PXOR	X8, X0
	ADDQ	$16, R13
	MOVQ	CX, R14
	SUBQ	$1, R14
dec_tail_round:
	MOVUPS	(R13), X8
	AESDEC	X8, X0
	ADDQ	$16, R13
	SUBQ	$1, R14
	JNZ	dec_tail_round
	MOVUPS	(R13), X8
	AESDECLAST	X8, X0
	PXOR	X4, X0
	MOVUPS	X0, (SI)
	ADDQ	$16, SI
	gfd(X4)
	SUBQ	$1, AX
	JNZ	dec_tail_loop

dec_done:
	MOVUPS	X4, (DI)
	RET
