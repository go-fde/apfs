# go-fde/apfs benchmarks

Reproducible performance-parity harness for the hot crypto paths of
`go-fde/apfs` (bulk AES-XTS sector crypto + the PBKDF2/Argon2 unwrap KDFs),
compared against `cryptsetup`/dm-crypt and OpenSSL.

This is a **standalone Go module** (`gofde-apfs-benchmarks`), intentionally not a
submodule of `github.com/go-fde/apfs`, so the repo's `go test ./...` and the CI
coverage gate never descend into it.

## Run

```sh
./run.sh            # benchtime=3s, count=2
./run.sh 1s 1       # quicker
```

The harness reproduces the exact constructions `go-fde/apfs` uses:
`golang.org/x/crypto/xts` over `crypto/aes` (hardware AES on arm64/amd64), and
`golang.org/x/crypto/{pbkdf2,argon2}`. The in-package `../bench_test.go` file
benchmarks the repo's own `sectorCipher` directly.

## Reference numbers (cryptsetup / OpenSSL)

Generated in the `debian` Tart VM (aarch64, ARMv8 AES):

```sh
sudo cryptsetup benchmark
openssl speed -elapsed -evp aes-256-xts
# dm-crypt real device:
cryptsetup luksFormat --type luks2 --cipher aes-xts-plain64 --key-size 512 img
cryptsetup open img m -; dd if=/dev/zero of=/dev/mapper/m bs=1M count=256 oflag=direct
```

See [`../BENCHMARKS.md`](../BENCHMARKS.md) for the full parity tables, the
honest hardware-vs-software-XTS gap, root cause, and action items.
