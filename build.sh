#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Shaun Murphy
#
# build.sh - Build script for fv-ssh-unlock
#
# Builds the fv-ssh-unlock CLI (and, optionally, the mock test server) into the
# dist/ directory. By default it produces a pure-Go binary with runtime and
# externally managed file credential providers. Pass --keyring to also build
# with OS keyring support.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
status()  { echo -e "${BLUE}[build]${NC} $1"; }
success() { echo -e "${GREEN}[ok]${NC} $1"; }
error()   { echo -e "${RED}[error]${NC} $1" >&2; }

TAGS=""
BUILD_CLI=true
BUILD_MOCK=false
CLEAN=false

usage() {
    cat <<'USAGE'
Usage: ./build.sh [OPTIONS]

Options:
  --keyring   Build with OS keyring credential support (adds go-keyring)
  --mock      Also build the mock FileVault SSH test server
  --clean     Remove the dist/ directory before building
  --help      Show this help

With no options, builds dist/fv-ssh-unlock with runtime and file providers.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --keyring) TAGS="keyring"; shift ;;
        --mock)    BUILD_MOCK=true; shift ;;
        --clean)   CLEAN=true; shift ;;
        --help)    usage; exit 0 ;;
        *) error "unknown option: $1"; usage; exit 1 ;;
    esac
done

command -v go >/dev/null 2>&1 || { error "Go is not installed or not in PATH"; exit 1; }

# Require a patched Go release. Go 1.26.0-1.26.5 contain a reachable
# encoding/asn1 stack-exhaustion vulnerability in the SSH handshake path.
GO_VER="$(go env GOVERSION 2>/dev/null | sed 's/^go//')"
GO_BASE="${GO_VER%%[-+]*}"
IFS=. read -r cur_major cur_minor cur_patch <<<"${GO_BASE}"
req_major=1; req_minor=26; req_patch=7
if (( cur_major < req_major ||
      (cur_major == req_major && cur_minor < req_minor) ||
      (cur_major == req_major && cur_minor == req_minor && cur_patch < req_patch) )); then
    error "Go ${req_major}.${req_minor}.${req_patch}+ required; found ${GO_VER}"; exit 1
fi
status "Using Go ${GO_VER}"

VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
LDFLAGS="-s -w -X main.version=${VERSION}"

$CLEAN && { status "cleaning dist/"; rm -rf dist; }
mkdir -p dist

EXT=""
case "${OSTYPE:-}" in msys*|win32*|cygwin*) EXT=".exe" ;; esac

if $BUILD_CLI; then
    out="dist/fv-ssh-unlock${EXT}"
    if [[ -n "$TAGS" ]]; then
        status "building ${out} (tags: ${TAGS}, version ${VERSION})"
        go build -tags="$TAGS" -ldflags "$LDFLAGS" -o "$out" ./cmd/fv-ssh-unlock
    else
        status "building ${out} (version ${VERSION})"
        go build -ldflags "$LDFLAGS" -o "$out" ./cmd/fv-ssh-unlock
    fi
    success "built ${out}"
fi

if $BUILD_MOCK; then
    out="dist/mock-fv-ssh-server${EXT}"
    status "building ${out}"
    ( cd tools/mock-fv-ssh-server && go build -o "../../${out}" . )
    success "built ${out}"
fi

success "done. Binaries in dist/"
