#!/usr/bin/env sh
set -eu

REPO="${MCAIFEE_REPO:-turinglabsorg/mcaifee}"
VERSION="${MCAIFEE_VERSION:-latest}"
INSTALL_DIR="${MCAIFEE_INSTALL_DIR:-$HOME/.local/bin}"
SOURCE="${MCAIFEE_INSTALL_SOURCE:-}"
DRY_RUN=0
INSTALL_SHELL_INIT=0
REMOVE_SHELL_INIT=0
SHELL_KIND="${MCAIFEE_SHELL:-posix}"

usage() {
  cat <<'USAGE'
Install Mcaifee from GitHub Releases.

Usage:
  ./install.sh [options]

Options:
  --version <tag>       Install a specific tag, for example v0.3.0.
  --install-dir <dir>   Install directory. Default: $HOME/.local/bin.
  --source <path|url>   Install from a local file or direct URL instead of GitHub release auto-detection.
  --shell-init [shell]  Install package-manager wrappers into the shell startup file. Shell: posix, bash, zsh, fish.
  --shell-disable [shell]
                        Remove package-manager wrappers from the shell startup file.
  --dry-run             Print actions without writing files.
  -h, --help            Show this help.

Environment:
  MCAIFEE_VERSION        Same as --version.
  MCAIFEE_INSTALL_DIR    Same as --install-dir.
  MCAIFEE_INSTALL_SOURCE Same as --source.
  MCAIFEE_SHELL          Shell used by --shell-init and --shell-disable.
  MCAIFEE_REPO           GitHub repo, default turinglabsorg/mcaifee.
USAGE
}

fail() {
  printf 'mcaifee install: %s\n' "$1" >&2
  exit 1
}

need_arg() {
  [ "$#" -gt 1 ] || fail "$1 requires a value"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      need_arg "$@"
      VERSION="$2"
      shift 2
      ;;
    --install-dir)
      need_arg "$@"
      INSTALL_DIR="$2"
      shift 2
      ;;
    --source)
      need_arg "$@"
      SOURCE="$2"
      shift 2
      ;;
    --shell-init)
      INSTALL_SHELL_INIT=1
      if [ "$#" -gt 1 ] && [ "${2#-}" = "$2" ]; then
        SHELL_KIND="$2"
        shift 2
      else
        shift
      fi
      ;;
    --shell-disable)
      REMOVE_SHELL_INIT=1
      if [ "$#" -gt 1 ] && [ "${2#-}" = "$2" ]; then
        SHELL_KIND="$2"
        shift 2
      else
        shift
      fi
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1"
      ;;
  esac
done

detect_asset() {
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os:$arch" in
    Linux:x86_64|Linux:amd64)
      printf 'mcaifee-linux-x86_64'
      ;;
    Darwin:x86_64|Darwin:amd64)
      printf 'mcaifee-macos-x86_64'
      ;;
    Darwin:arm64|Darwin:aarch64)
      printf 'mcaifee-macos-aarch64'
      ;;
    *)
      fail "unsupported platform: $os $arch"
      ;;
  esac
}

download() {
  source="$1"
  destination="$2"
  case "$source" in
    http://*|https://*)
      if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$source" -o "$destination"
      elif command -v wget >/dev/null 2>&1; then
        wget -qO "$destination" "$source"
      else
        fail "curl or wget is required to download $source"
      fi
      ;;
    *)
      [ -f "$source" ] || fail "source file does not exist: $source"
      cp "$source" "$destination"
      ;;
  esac
}

shell_profile_path() {
  case "$1" in
    posix)
      printf '%s/.profile' "$HOME"
      ;;
    bash)
      printf '%s/.bashrc' "$HOME"
      ;;
    zsh)
      printf '%s/.zshrc' "$HOME"
      ;;
    fish)
      printf '%s/.config/fish/conf.d/mcaifee.fish' "$HOME"
      ;;
    *)
      fail "unsupported shell: $1"
      ;;
  esac
}

shell_integration_block() {
  shell="$1"
  binary="$2"
  install_dir="$3"
  case "$shell" in
    fish)
      cat <<EOF
# >>> mcaifee shell integration >>>
set -gx PATH "$install_dir" \$PATH
"$binary" shell-init --shell fish | source
# <<< mcaifee shell integration <<<
EOF
      ;;
    posix|bash|zsh)
      cat <<EOF
# >>> mcaifee shell integration >>>
export PATH="$install_dir:\$PATH"
eval "\$("$binary" shell-init --shell $shell)"
# <<< mcaifee shell integration <<<
EOF
      ;;
    *)
      fail "unsupported shell: $shell"
      ;;
  esac
}

strip_shell_integration_block() {
  awk '
    /^# >>> mcaifee shell integration >>>/ { skip = 1; next }
    /^# <<< mcaifee shell integration <<</ { skip = 0; next }
    skip != 1 { print }
  ' "$1" > "$2"
}

install_shell_integration() {
  [ -n "${HOME:-}" ] || fail "HOME is required for --shell-init"
  shell="$1"
  binary="$2"
  install_dir="$3"
  profile="$(shell_profile_path "$shell")"
  profile_dir="$(dirname "$profile")"

  printf 'shell profile: %s\n' "$profile"

  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'dry-run: would install shell integration:\n'
    shell_integration_block "$shell" "$binary" "$install_dir"
    return
  fi

  mkdir -p "$profile_dir"
  tmp_profile="$(mktemp "${TMPDIR:-/tmp}/mcaifee-profile.XXXXXX")"
  if [ -f "$profile" ]; then
    strip_shell_integration_block "$profile" "$tmp_profile"
  else
    : > "$tmp_profile"
  fi
  if [ -s "$tmp_profile" ]; then
    printf '\n' >> "$tmp_profile"
  fi
  shell_integration_block "$shell" "$binary" "$install_dir" >> "$tmp_profile"
  mv "$tmp_profile" "$profile"
  printf 'shell integration installed: %s\n' "$profile"
  printf 'restart the shell, or run: eval "$(%s shell-init --shell %s)"\n' "$binary" "$shell"
}

remove_shell_integration() {
  [ -n "${HOME:-}" ] || fail "HOME is required for --shell-disable"
  shell="$1"
  profile="$(shell_profile_path "$shell")"

  printf 'shell profile: %s\n' "$profile"

  if [ ! -f "$profile" ]; then
    printf 'shell integration not found\n'
    return
  fi

  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'dry-run: would remove mcaifee shell integration block\n'
    return
  fi

  tmp_profile="$(mktemp "${TMPDIR:-/tmp}/mcaifee-profile.XXXXXX")"
  strip_shell_integration_block "$profile" "$tmp_profile"
  mv "$tmp_profile" "$profile"
  printf 'shell integration removed: %s\n' "$profile"
}

if [ "$REMOVE_SHELL_INIT" -eq 1 ]; then
  remove_shell_integration "$SHELL_KIND"
  exit 0
fi

asset="$(detect_asset)"
if [ -z "$SOURCE" ]; then
  if [ "$VERSION" = "latest" ]; then
    SOURCE="https://github.com/$REPO/releases/latest/download/$asset"
  else
    SOURCE="https://github.com/$REPO/releases/download/$VERSION/$asset"
  fi
fi

target="$INSTALL_DIR/mcaifee"

printf 'mcaifee install\n'
printf 'source: %s\n' "$SOURCE"
printf 'target: %s\n' "$target"

if [ "$DRY_RUN" -eq 0 ]; then
  mkdir -p "$INSTALL_DIR"
  tmp="$(mktemp "${TMPDIR:-/tmp}/mcaifee.XXXXXX")"
  trap 'rm -f "$tmp"' EXIT INT TERM
  download "$SOURCE" "$tmp"
  chmod +x "$tmp"
  mv "$tmp" "$target"
  "$target" --help >/dev/null
  printf 'installed: %s\n' "$target"
else
  printf 'dry-run: no files written\n'
fi

if [ "$INSTALL_SHELL_INIT" -eq 1 ]; then
  printf '\n'
  install_shell_integration "$SHELL_KIND" "$target" "$INSTALL_DIR"
fi
