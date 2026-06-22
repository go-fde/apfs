// Isolated benchmark module.
//
// Standalone module (not a submodule of github.com/go-fde/apfs) so the repo's
// `go test ./...` / `go build ./...` and the CI coverage gate never descend
// into it. It reproduces the exact crypto construction used by go-fde/apfs
// (golang.org/x/crypto/xts over crypto/aes, plus pbkdf2/argon2).
module gofde-apfs-benchmarks

go 1.25.0

require golang.org/x/crypto v0.50.0

require golang.org/x/sys v0.43.0 // indirect
