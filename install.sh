#!/bin/sh
# Fida installer — downloads a prebuilt `fida` binary for your platform
# from GitHub Releases and installs it to a bin directory on your PATH.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/ajipurn/fida/main/install.sh | sh
#
# Environment overrides:
#   FIDA_VERSION      release tag to install (default: latest for piped install,
#                       local source when run from a checkout; use "source" to
#                       force building the current checkout)
#   FIDA_INSTALL_DIR  install location (default: $HOME/.local/bin)
#   FIDA_REPO         owner/repo to download from (default: ajipurn/fida)
#
# POSIX sh; no bashisms. Fails loudly rather than leaving a partial install.

set -eu

REPO="${FIDA_REPO:-ajipurn/fida}"
REQUESTED_VERSION="${FIDA_VERSION:-}"
VERSION="${REQUESTED_VERSION:-latest}"
INSTALL_DIR="${FIDA_INSTALL_DIR:-$HOME/.local/bin}"
BIN_NAME="fida"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  BOLD="$(printf '\033[1m')"
  DIM="$(printf '\033[2m')"
  GREEN="$(printf '\033[1;32m')"
  RED="$(printf '\033[1;31m')"
  RESET="$(printf '\033[0m')"
else
  BOLD=""
  DIM=""
  GREEN=""
  RED=""
  RESET=""
fi

have() { command -v "$1" >/dev/null 2>&1; }
err()  { printf '%serror:%s %s\n' "$RED" "$RESET" "$1" >&2; exit 1; }

# True only when fida is not already on disk at the install location, so the
# guided setup runs on a fresh install but stays out of the way on upgrades.
is_fresh_install() { [ ! -e "$INSTALL_DIR/$BIN_NAME" ]; }

script_dir() {
  case "$0" in
    */*) dir=${0%/*} ;;
    *) dir=. ;;
  esac
  (CDPATH= cd "$dir" 2>/dev/null && pwd)
}

header() {
  # No ASCII art here: `fida init` renders its own TUI/logo right after, and
  # two banners back-to-back is noise. Keep the installer to one quiet line.
  # printf '\n%sfida%s %s· secret leak prevention for AI coding agents%s\n\n' \
  #   "$BOLD" "$RESET" "$DIM" "$RESET"
  :
}

show_failure_log() {
  log="$1"
  [ -s "$log" ] || return 0
  printf '\n%sinstaller log%s\n' "$DIM" "$RESET" >&2
  if have tail; then
    tail -n 40 "$log" >&2 || true
  else
    sed -n '1,120p' "$log" >&2 || true
  fi
}

run_installing() {
  log="$tmp/install.log"
  : >"$log"

  if [ -t 1 ]; then
    "$@" >"$log" 2>&1 &
    pid=$!
    i=0
    while kill -0 "$pid" 2>/dev/null; do
      case "$i" in
        0) frame="-" ;;
        1) frame="\\" ;;
        2) frame="|" ;;
        *) frame="/" ;;
      esac
      printf '\rinstalling %s' "$frame"
      i=$((i + 1))
      [ "$i" -gt 3 ] && i=0
      sleep 0.1
    done
    set +e
    wait "$pid"
    status=$?
    set -e
    printf '\r             \r'
  else
    printf 'installing...\n'
    set +e
    "$@" >"$log" 2>&1
    status=$?
    set -e
  fi

  if [ "$status" -ne 0 ]; then
    printf 'failed\n' >&2
    show_failure_log "$log"
    exit "$status"
  fi
}

post_install() {
  installed="$INSTALL_DIR/$BIN_NAME"
  version="${1:-}"

  printf '%sdone%s\n' "$GREEN" "$RESET"
  printf 'installed  %s\n' "$installed"
  [ -n "$version" ] && printf 'version    %s\n' "$version"

  case ":$PATH:" in
    *":$INSTALL_DIR:"*)
      printf 'run        %s --help\n' "$BIN_NAME"
      ;;
    *)
      printf 'run        %s --help\n' "$installed"
      ;;
  esac
}

# Hand straight off into the guided setup on a fresh install so there's no
# separate "now run fida init" step. Upgrades skip it (the user already chose
# their integrations). `fida init` is unchanged and can be re-run any time.
#
# A piped install (`curl ... | sh`) leaves stdin as the pipe, so reconnect the
# controlling terminal via /dev/tty to drive the interactive TUI; without a tty
# we skip rather than emit a degraded non-interactive run.
run_init() {
  [ "$FRESH_INSTALL" = "1" ] || return 0
  installed="$INSTALL_DIR/$BIN_NAME"
  [ -x "$installed" ] || return 0

  printf '\n'
  if [ -r /dev/tty ] && [ -t 1 ]; then
    "$installed" init </dev/tty || true
  elif [ -t 0 ] && [ -t 1 ]; then
    "$installed" init || true
  fi
}

SCRIPT_DIR="$(script_dir 2>/dev/null || pwd)"
SOURCE_DIR=""
if [ -f "$SCRIPT_DIR/Cargo.toml" ] && [ -f "$SCRIPT_DIR/crates/fida-cli/Cargo.toml" ]; then
  SOURCE_DIR="$SCRIPT_DIR"
fi

tmp="$(mktemp -d 2>/dev/null || mktemp -d -t fida)"
cargo_root=""
trap 'rm -rf "$tmp" "$cargo_root"' EXIT INT TERM

install_from_source() {
  [ -n "$SOURCE_DIR" ] || {
    echo "FIDA_VERSION=source requires running install.sh from a Fida source checkout" >&2
    return 1
  }
  have cargo || {
    echo "need cargo installed to build from source. Install Rust from https://rustup.rs/ or use a published release." >&2
    return 1
  }

  cargo_root="$(mktemp -d 2>/dev/null || mktemp -d -t fida-cargo)"
  PATH="$cargo_root/bin:$PATH" cargo install --quiet --locked --path "$SOURCE_DIR/crates/fida-cli" --root "$cargo_root"

  mkdir -p "$INSTALL_DIR"
  chmod +x "$cargo_root/bin/$BIN_NAME"
  mv "$cargo_root/bin/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"
}

install_from_release() {
  if have curl; then
    DL="curl -fsSL"
    DL_OUT="curl -fsSL -o"
  elif have wget; then
    DL="wget -qO-"
    DL_OUT="wget -qO"
  else
    echo "need either curl or wget installed" >&2
    return 1
  fi

  have tar || {
    echo "need tar installed" >&2
    return 1
  }

  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Linux)  os_part="unknown-linux-gnu" ;;
    Darwin) os_part="apple-darwin" ;;
    *)
      echo "unsupported OS '$os'. Build from source: https://github.com/$REPO" >&2
      return 1
      ;;
  esac

  case "$arch" in
    x86_64|amd64)  arch_part="x86_64" ;;
    arm64|aarch64) arch_part="aarch64" ;;
    *)
      echo "unsupported architecture '$arch'. Build from source: https://github.com/$REPO" >&2
      return 1
      ;;
  esac

  if [ "$os_part" = "unknown-linux-gnu" ] && [ "$arch_part" = "aarch64" ]; then
    echo "no prebuilt binary for linux/aarch64 yet. Build from source: cargo install --git https://github.com/$REPO fida-cli" >&2
    return 1
  fi

  target="${arch_part}-${os_part}"
  version="$VERSION"

  if [ "$version" = "latest" ]; then
    version="$(
      $DL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
        | sed -nE 's/.*"tag_name" *: *"([^"]+)".*/\1/p' \
        | head -n1 || true
    )"
    if [ -z "$version" ]; then
      if [ -n "$SOURCE_DIR" ]; then
        install_from_source
        printf 'from source\n' >"$tmp/version"
        return 0
      fi
      echo "could not determine the latest release tag for $REPO" >&2
      return 1
    fi
  fi

  asset="${BIN_NAME}-${target}.tar.gz"
  url="https://github.com/$REPO/releases/download/$version/$asset"

  $DL_OUT "$tmp/$asset" "$url"

  # Verify the release checksum. Our release workflow always publishes a
  # `<asset>.sha256` sidecar, so a present sidecar is authoritative: fail
  # closed on a mismatch, an empty checksum file, or when no hashing tool is
  # available to check it (the old code silently skipped the last two).
  # ponytail: a *missing* sidecar is warned about, not a hard error — a
  # transient fetch failure or an old tag without one shouldn't brick installs.
  # Upgrade path: drop this warn-and-continue branch (require the sidecar) once
  # every supported release ships one, or pin expected hashes in the installer.
  if $DL_OUT "$tmp/$asset.sha256" "$url.sha256" 2>/dev/null; then
    expected="$(awk '{print $1}' "$tmp/$asset.sha256")"
    if have sha256sum; then
      actual="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
    elif have shasum; then
      actual="$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')"
    else
      echo "cannot verify download: need 'sha256sum' or 'shasum' to check the published checksum" >&2
      return 1
    fi
    if [ -z "$expected" ]; then
      echo "cannot verify download: checksum file for $asset was empty" >&2
      return 1
    fi
    if [ "$expected" != "$actual" ]; then
      echo "checksum mismatch" >&2
      echo "expected: $expected" >&2
      echo "actual:   $actual" >&2
      return 1
    fi
  else
    printf '%swarning:%s could not download the checksum for %s; skipping integrity check\n' \
      "$BOLD" "$RESET" "$asset" >&2
  fi

  tar -xzf "$tmp/$asset" -C "$tmp"

  if [ -f "$tmp/$BIN_NAME" ]; then
    src="$tmp/$BIN_NAME"
  elif [ -f "$tmp/$target/$BIN_NAME" ]; then
    src="$tmp/$target/$BIN_NAME"
  else
    src="$(find "$tmp" -type f -name "$BIN_NAME" -perm -u+x 2>/dev/null | head -n1 || true)"
    [ -n "$src" ] || src="$(find "$tmp" -type f -name "$BIN_NAME" 2>/dev/null | head -n1 || true)"
    [ -n "$src" ] || {
      echo "could not find '$BIN_NAME' inside the downloaded archive" >&2
      return 1
    }
  fi

  mkdir -p "$INSTALL_DIR"
  chmod +x "$src"
  mv "$src" "$INSTALL_DIR/$BIN_NAME"
  printf '%s\n' "$version" >"$tmp/version"
}

# Capture this before we write the binary: distinguishes a first-time install
# (run the guided setup) from an upgrade (leave the user's setup alone).
if is_fresh_install; then
  FRESH_INSTALL=1
else
  FRESH_INSTALL=0
fi

# Let tests source this file for its helpers without running the install.
[ "${FIDA_INSTALL_LIB:-}" = "1" ] && return 0 2>/dev/null

header

if [ "$VERSION" = "source" ]; then
  run_installing install_from_source
  post_install "from source"
  run_init
  exit 0
fi

if [ -n "$SOURCE_DIR" ] && [ -z "$REQUESTED_VERSION" ]; then
  run_installing install_from_source
  post_install "from source"
  run_init
  exit 0
fi

run_installing install_from_release
installed_version="$(sed -n '1p' "$tmp/version" 2>/dev/null || printf '%s\n' "$VERSION")"
post_install "$installed_version"
run_init
