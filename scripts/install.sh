#!/bin/sh
# MIT License
#
# Copyright (c) 2024 CrowdStrike
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


# install.sh downloads a falcon-installer release for Linux or macOS, verifies
# its SHA-256 checksum, and installs the binary.
#
#   curl -fsSL https://raw.githubusercontent.com/CrowdStrike/falcon-installer/main/scripts/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/CrowdStrike/falcon-installer/main/scripts/install.sh | sh -s -- --version v0.27.0
#
# Everything runs from main, which is called on the last line, so a truncated
# download executes nothing.

set -eu

BINARY_NAME="falcon-installer"
REPO_URL="https://github.com/CrowdStrike/falcon-installer"
RELEASES_URL="${REPO_URL}/releases"

VERSION="${FALCON_INSTALLER_VERSION:-}"
INSTALL_DIR="${FALCON_INSTALLER_DIR:-.}"
USE_SUDO="${FALCON_INSTALLER_USE_SUDO:-true}"
DEBUG="${FALCON_INSTALLER_DEBUG:-false}"
FORCE="false"

TMP_DIR=""
STAGED=""
SUDO=""

usage() {
  cat <<EOF
Install ${BINARY_NAME} on Linux or macOS.

Usage: install.sh [options]

Options:
  -v, --version <tag>      Release to install, e.g. v0.27.0 (default: latest)
  -d, --install-dir <dir>  Directory to save the binary in (default: current directory)
      --no-sudo            Never use sudo, even if the directory is not writable
      --force              Reinstall even if the requested version is installed
      --debug              Print each command as it runs
  -h, --help               Show this help

Environment variables:
  FALCON_INSTALLER_VERSION    Same as --version
  FALCON_INSTALLER_DIR        Same as --install-dir
  FALCON_INSTALLER_USE_SUDO   Set to false for the same effect as --no-sudo
  FALCON_INSTALLER_DEBUG      Set to true for the same effect as --debug

Releases: ${RELEASES_URL}
EOF
}

log() {
  printf '%s\n' "$*"
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

usage_error() {
  printf 'ERROR: %s\n\n' "$*" >&2
  usage >&2
  exit 2
}

has() {
  command -v "$1" >/dev/null 2>&1
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -v | --version)
        [ $# -ge 2 ] || usage_error "$1 requires a value, e.g. $1 v0.27.0"
        VERSION="$2"
        shift 2
        ;;
      --version=*)
        VERSION="${1#*=}"
        shift
        ;;
      -d | --install-dir)
        [ $# -ge 2 ] || usage_error "$1 requires a directory"
        INSTALL_DIR="$2"
        shift 2
        ;;
      --install-dir=*)
        INSTALL_DIR="${1#*=}"
        shift
        ;;
      --no-sudo)
        USE_SUDO="false"
        shift
        ;;
      --force)
        FORCE="true"
        shift
        ;;
      --debug)
        DEBUG="true"
        shift
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      *)
        usage_error "unknown option: $1"
        ;;
    esac
  done
}

# detect_platform maps uname output to the OS and arch names used in release
# asset names, e.g. falcon-installer-0.27.0-macos-arm64.tar.gz.
detect_platform() {
  uname_s=$(uname -s)
  case "$uname_s" in
    Linux) OS="linux" ;;
    Darwin) OS="macos" ;;
    MINGW* | MSYS* | CYGWIN*) fail "on Windows, use install.ps1 instead: ${REPO_URL}#windows" ;;
    *) fail "unsupported operating system: ${uname_s}. See ${RELEASES_URL}" ;;
  esac

  uname_m=$(uname -m)
  case "$uname_m" in
    x86_64 | amd64) ARCH="x86_64" ;;
    aarch64 | arm64) ARCH="arm64" ;;
    *) ARCH="$uname_m" ;;
  esac

  # A shell running under Rosetta 2 reports x86_64; install the native build.
  if [ "$OS" = "macos" ] && [ "$ARCH" = "x86_64" ] &&
    [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || true)" = "1" ]; then
    ARCH="arm64"
  fi

  case "${OS}-${ARCH}" in
    linux-x86_64 | linux-arm64 | linux-s390x | macos-x86_64 | macos-arm64) ;;
    *) fail "no prebuilt ${BINARY_NAME} for ${OS}-${ARCH}. See ${RELEASES_URL}" ;;
  esac
}

detect_tools() {
  if has curl; then
    DOWNLOADER="curl"
  elif has wget; then
    DOWNLOADER="wget"
    # BusyBox wget supports neither option, and reads no config file.
    wget_help=$(wget --help 2>&1 || true)
    case "$wget_help" in
      *--https-only*) WGET_HTTPS_ONLY="true" ;;
      *) WGET_HTTPS_ONLY="false" ;;
    esac
    case "$wget_help" in
      *--no-config*) WGET_NO_CONFIG="true" ;;
      *) WGET_NO_CONFIG="false" ;;
    esac
  else
    fail "curl or wget is required"
  fi

  if has sha256sum; then
    HASHER="sha256sum"
  elif has shasum; then
    HASHER="shasum"
  elif has openssl; then
    HASHER="openssl"
  else
    fail "sha256sum, shasum, or openssl is required to verify the download"
  fi

  has tar || fail "tar is required to extract the download"
}

# http_get ignores ~/.curlrc and ~/.wgetrc, which could turn off certificate
# checks. Proxies still work through the https_proxy environment variable.
http_get() {
  case "$DOWNLOADER" in
    curl)
      # -q only takes effect as the first argument.
      curl -q --proto '=https' --tlsv1.2 -fsSL -o "$2" "$1"
      ;;
    wget)
      url="$1"
      set -- -q -O "$2"
      if [ "$WGET_HTTPS_ONLY" = "true" ]; then
        set -- --https-only "$@"
      fi
      if [ "$WGET_NO_CONFIG" = "true" ]; then
        set -- --no-config "$@"
      fi
      wget "$@" "$url"
      ;;
  esac
}

sha256() {
  case "$HASHER" in
    sha256sum) sha256sum "$1" | awk '{ print tolower($1) }' ;;
    shasum) shasum -a 256 "$1" | awk '{ print tolower($1) }' ;;
    openssl) openssl dgst -sha256 "$1" | awk '{ print tolower($NF) }' ;;
  esac
}

# expected_hash prints the checksum listed for the named asset. checksums.txt
# lists both raw binaries and archives, so the name must match exactly.
expected_hash() {
  awk -v f="$1" '$2 == f { print tolower($1) }' "$CHECKSUMS"
}

# normalize_version turns a pinned version such as 0.27.0 into the v0.27.0 tag.
normalize_version() {
  [ -n "$VERSION" ] || return 0
  if ! printf '%s\n' "$VERSION" | grep -Eq '^v?[0-9]+\.[0-9]+\.[0-9]+$'; then
    fail "invalid version '${VERSION}': expected a release tag such as v0.27.0"
  fi
  case "$VERSION" in
    v*) ;;
    *) VERSION="v${VERSION}" ;;
  esac
}

# fetch_checksums downloads checksums.txt for the pinned release. Otherwise it
# fetches the latest release's copy through the /releases/latest/download
# redirect and reads the version from the asset names it lists, which avoids
# the GitHub API and its rate limit for unauthenticated clients.
fetch_checksums() {
  CHECKSUMS="${TMP_DIR}/checksums.txt"
  if [ -n "$VERSION" ]; then
    http_get "${RELEASES_URL}/download/${VERSION}/checksums.txt" "$CHECKSUMS" ||
      fail "release ${VERSION} not found. See ${RELEASES_URL} for available versions"
  else
    http_get "${RELEASES_URL}/latest/download/checksums.txt" "$CHECKSUMS" ||
      fail "could not download checksums.txt for the latest release. Pin a release with --version (see ${RELEASES_URL})"
    latest=$(awk '{ print $2 }' "$CHECKSUMS" |
      sed -n "s/^${BINARY_NAME}-\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)-.*/\1/p" | head -n 1)
    [ -n "$latest" ] || fail "could not determine the latest version from its checksums.txt. Pin a release with --version"
    VERSION="v${latest}"
  fi
  VERSION_NUMBER="${VERSION#v}"
}

# check_installed skips the download when the target already holds this
# release's binary and nobody else can change it. It compares the file's hash
# with the release's raw binary rather than running it, because the file may
# not be ours.
check_installed() {
  target="${INSTALL_DIR}/${BINARY_NAME}"
  if [ -d "$target" ]; then
    fail "${target} is a directory. Run from another directory or pass --install-dir"
  fi
  if [ ! -e "$target" ] && [ ! -L "$target" ]; then
    return 0
  fi

  expected=$(expected_hash "${BINARY_NAME}-${VERSION_NUMBER}-${OS}-${ARCH}")
  if [ "$FORCE" != "true" ] && [ -n "$expected" ] && private_file "$target" &&
    [ "$(sha256 "$target" 2>/dev/null)" = "$expected" ]; then
    log "${BINARY_NAME} ${VERSION} is already installed at ${target}. Use --force to reinstall."
    exit 0
  fi
  log "Replacing ${target}"
}

download() {
  ASSET="${BINARY_NAME}-${VERSION_NUMBER}-${OS}-${ARCH}.tar.gz"
  log "Downloading ${BINARY_NAME} ${VERSION} for ${OS}-${ARCH}"
  http_get "${RELEASES_URL}/download/${VERSION}/${ASSET}" "${TMP_DIR}/${ASSET}" ||
    fail "release ${VERSION} has no ${ASSET}. See ${RELEASES_URL}/tag/${VERSION}"
}

verify_checksum() {
  expected=$(expected_hash "$ASSET")
  [ -n "$expected" ] || fail "checksums.txt for ${VERSION} has no entry for ${ASSET}"

  actual=$(sha256 "${TMP_DIR}/${ASSET}")
  if [ "$actual" != "$expected" ]; then
    fail "checksum mismatch for ${ASSET}: expected ${expected}, got ${actual}. Nothing was installed"
  fi
  log "Verified SHA-256 checksum"
}

# writable reports whether dir, or its nearest existing parent when dir does
# not exist yet, is writable by the current user.
writable() {
  dir="$1"
  while [ ! -d "$dir" ]; do
    dir=$(dirname "$dir")
  done
  [ -w "$dir" ]
}

dir_label() {
  if [ "$INSTALL_DIR" = "." ]; then
    printf 'the current directory (%s)' "$(pwd)"
  else
    printf '%s' "$INSTALL_DIR"
  fi
}

# check_dir_safe refuses directories that other users can write to, unless the
# sticky bit is set, as it is on /tmp. Without it, they could replace the
# binary after the script finishes and before it is run with sudo. A directory
# group-writable by the user's own primary group is allowed, since that group
# usually holds only the user.
check_dir_safe() {
  [ -d "$INSTALL_DIR" ] || return 0
  shared=$(find "$INSTALL_DIR" -prune ! -perm -1000 \( -perm -0002 -o \( -perm -0020 ! -group "$(id -g)" \) \) -print)
  if [ -n "$shared" ]; then
    fail "$(dir_label) is writable by other users and lacks the sticky bit, so they could replace ${BINARY_NAME} before it runs as root. Run from another directory, such as your home directory or /tmp, or pass --install-dir"
  fi
}

# private_file reports whether path is a regular file, not a symlink, owned by
# the current user or root, that nobody else can write to.
private_file() {
  [ -f "$1" ] && [ ! -L "$1" ] &&
    [ -n "$(find "$1" -prune \( -user "$(id -u)" -o -user 0 \) ! -perm -0020 ! -perm -0002 -print)" ]
}

# check_writable decides before downloading whether installing needs sudo.
check_writable() {
  if [ "$(id -u)" -eq 0 ] || writable "$INSTALL_DIR"; then
    return 0
  fi
  if [ "$USE_SUDO" = "true" ] && has sudo; then
    SUDO="sudo"
    log "$(dir_label) is not writable; using sudo"
  else
    fail "$(dir_label) is not writable. Run from a writable directory, pass --install-dir, or allow sudo"
  fi
}

as_root() {
  if [ -n "$SUDO" ]; then
    sudo "$@"
  else
    "$@"
  fi
}

install_binary() {
  tar -xzf "${TMP_DIR}/${ASSET}" -C "$TMP_DIR" "$BINARY_NAME"
  target="${INSTALL_DIR}/${BINARY_NAME}"

  # Copy to a new file beside the target, then rename it into place. The rename
  # replaces an existing file or symlink rather than writing through it, and
  # in a sticky directory such as /tmp it fails rather than replacing a file
  # another user owns.
  as_root mkdir -p -m 0755 "$INSTALL_DIR"
  STAGED=$(as_root mktemp "${INSTALL_DIR}/.${BINARY_NAME}.XXXXXX") ||
    fail "could not create a file in $(dir_label)"
  as_root cp "${TMP_DIR}/${BINARY_NAME}" "$STAGED"
  as_root chmod 0755 "$STAGED"
  as_root mv -f "$STAGED" "$target" ||
    fail "could not replace ${target}, which may belong to another user. Remove it or pass --install-dir"
  STAGED=""
}

post_check() {
  target="${INSTALL_DIR}/${BINARY_NAME}"
  # Check the result is still the file just written before suggesting sudo.
  if ! private_file "$target" ||
    [ "$(sha256 "$target")" != "$(sha256 "${TMP_DIR}/${BINARY_NAME}")" ]; then
    fail "${target} is not the file this script installed. Remove it and try again, or pass --install-dir"
  fi
  "$target" --version >/dev/null 2>&1 || fail "installed ${target}, but it failed to run"
  log "Installed ${BINARY_NAME} ${VERSION} to ${target}"
  log "Next: sudo ${target} --help"
}

cleanup() {
  if [ -n "$STAGED" ]; then
    as_root rm -f "$STAGED" || true
  fi
  if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
  fi
}

main() {
  parse_args "$@"
  if [ "$DEBUG" = "true" ]; then
    set -x
  fi
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  detect_platform
  detect_tools
  normalize_version
  check_dir_safe
  TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/${BINARY_NAME}.XXXXXX")
  fetch_checksums
  check_installed
  check_writable
  download
  verify_checksum
  install_binary
  post_check
}

main "$@"
