# Performance parity — go-fde/apfs vs OpenSSL / dm-crypt  (2026-06-22)

Parity benchmark of the hot crypto paths of the APFS (FileVault-style) backend:
**bulk AES-XTS sector crypto** and the **PBKDF2 / Argon2id** key-unwrap KDFs.

APFS FileVault uses AES-XTS over 512-byte sectors, the same primitive cryptsetup
uses, so OpenSSL and the kernel dm-crypt `xts-aes-ce` driver are the natural
reference points (Apple's CoreCrypto on-device numbers are not reproducible in a
Linux VM). The `go-fde/clear` passthrough gives the no-encryption upper bound.

## Methodology

- **Ours (host):** Apple M4 Max, macOS 26.5, Go 1.26.4 `darwin/arm64`,
  ARMv8 AES present. Cipher: `golang.org/x/crypto/xts` v0.50.0 over `crypto/aes`
  (the exact `xtscipher` in `cipher.go`); KDFs: `golang.org/x/crypto`. Single
  core, MB/s over 1 MiB in 512-byte sectors, best of `-count=2 -benchtime=3s`.
- **Reference (Linux):** `debian` Tart VM, aarch64 (same M4 Max silicon, ARMv8
  AES), OpenSSL 3.5.6 (`OPENSSL_armcap=0x8fd`), `cryptsetup 2.7.5`
  (`aes-xts-plain64`), real dm-crypt loop device with `dd oflag=direct`.

## Correctness

AES-256-XTS ciphertext (key `00..3f`, sector 0) is **byte-identical** to
OpenSSL/libcrypto — verified via the shared `go-fde/luks` check (same
`x/crypto/xts` + `crypto/aes` path). The XTS bulk cipher is provably correct.

## Bulk AES-XTS (single core, MB/s — higher is better)

| op | algo | ours | OpenSSL (1 KiB / 16 KiB) | cryptsetup / dm-crypt | ratio vs OpenSSL@1KiB | verdict |
|---|---|---:|---:|---:|---:|---|
| encrypt | AES-256-XTS | **588 MB/s** | 10 536 / 11 881 MB/s | 4364 (mem) / 3700 (disk) MB/s | 0.056× (18× slower) | ❌ far behind |
| decrypt | AES-256-XTS | **592 MB/s** | 10 536 / 11 881 MB/s | 4429 / 4700 MB/s | 0.056× (18× slower) | ❌ far behind |
| encrypt | AES-128-XTS | **604 MB/s** | 13 538 / 15 798 MB/s | 4537 MB/s | 0.045× | ❌ far behind |
| passthrough (`go-fde/clear`) | none (memcpy) | 80 118 MB/s | — | — | — | upper bound |

## KDF — key unwrap (ms/derivation, lower is better)

| op | params | ours | reference | ratio | verdict |
|---|---|---:|---:|---:|---|
| PBKDF2-SHA256 | 100 000 iters | **9.5 ms** | OpenSSL/cryptsetup ≈ 9.5–10.5 ms | ~1.0× | ✅ at parity |
| Argon2id | t=4, m=256 MiB, p=1 | **551 ms** | same `x/crypto` primitive | n/a | ✅ same primitive |

## Summary, root cause, action items

**Bulk AES-XTS is ~18× slower than OpenSSL and ~7.5× slower than cryptsetup, per
core.** This is **not** software-AES vs hardware-AES: `crypto/aes` uses the
ARMv8 AES instructions here (raw AES-CTR = 10 GB/s). The bottleneck is
`golang.org/x/crypto/xts`, which runs AES one 16-byte block at a time through the
`cipher.Block` interface and does the XTS tweak GF(2¹²⁸) multiply in scalar Go —
no fused/vectorised XTS path. OpenSSL and the kernel `xts-aes-ce` driver fuse
the tweak multiply (`PMULL`) with pipelined AES rounds in assembly.

**Action items:**
1. Replace `x/crypto/xts` with a **fused, go-asmgen AES-XTS kernel** (PMULL/
   VPCLMUL tweak multiply + ≥4-block AES pipeline) across all 6 targets;
   target ≥ 4 GB/s/core.
2. Add a whole-sector bulk API to `xtscipher` to amortise interface dispatch.
3. Parallelise independent XTS sectors for large transfers.

KDF is already at parity. Reproduce with [`benchmarks/`](benchmarks/)
(`./benchmarks/run.sh`).
