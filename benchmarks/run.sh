#!/usr/bin/env bash
# Reproducible benchmark runner for go-fde/apfs.
#
# Runs the isolated bulk-XTS + KDF benchmarks (this module) and, when run from a
# checkout of the main package, the in-package sectorCipher benchmarks too. The
# isolated module is deliberately separate from github.com/go-fde/apfs so the
# coverage gate never sees it.
#
# Usage: ./run.sh [benchtime] [count]
set -euo pipefail
BT="${1:-3s}"
COUNT="${2:-2}"
cd "$(dirname "$0")"

echo "== environment =="
go version
uname -srm
echo

echo "== isolated bulk-crypto + KDF harness =="
GOWORK=off go test -run '^$' -bench . -benchtime="$BT" -count="$COUNT" ./...
echo

# In-package benchmarks (exercise the repo's own sectorCipher).
if [ -f ../bench_test.go ]; then
  echo "== in-package go-fde/apfs sectorCipher benchmarks =="
  ( cd .. && GOWORK=off go test -run '^$' \
      -bench 'XTS|CBC|PBKDF2|Argon2id_t4_m256' \
      -benchtime="$BT" -count="$COUNT" . )
fi
