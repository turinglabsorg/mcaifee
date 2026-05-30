#!/usr/bin/env sh
set -eu

REPO="${MCAIFEE_REPO:-turinglabsorg/mcaifee}"
VERSION="${MCAIFEE_VERSION:-latest}"
INSTALL_DIR="${MCAIFEE_INSTALL_DIR:-$HOME/.local/bin}"
SOURCE="${MCAIFEE_INSTALL_SOURCE:-}"
DRY_RUN=0
VERIFY_DOWNLOAD="${MCAIFEE_INSTALL_VERIFY:-1}"
COSIGN_VERIFY="${MCAIFEE_INSTALL_COSIGN:-auto}"
INSTALL_SHELL_INIT=0
REMOVE_SHELL_INIT=0
SHELL_KIND="${MCAIFEE_SHELL:-posix}"
INSTALL_AGENT_SKILL=0
AGENT_SKILL_DIR="${MCAIFEE_AGENT_SKILL_DIR:-$HOME/.agents/skills/mcaifee}"
INSTALL_PATH_LINK=0
PATH_LINK_DIR="${MCAIFEE_PATH_LINK_DIR:-/usr/local/bin}"

usage() {
  cat <<'USAGE'
Install Mcaifee from GitHub Releases.

Usage:
  ./install.sh [options]

Options:
  --version <tag>       Install a specific tag, for example v0.5.1.
  --install-dir <dir>   Install directory. Default: $HOME/.local/bin.
  --source <path|url>   Install from a local file or direct URL instead of GitHub release auto-detection.
  --shell-init [shell]  Install package-manager wrappers into the shell startup file. Shell: posix, bash, zsh, fish.
  --shell-disable [shell]
                        Remove package-manager wrappers from the shell startup file.
  --agent-skill [dir]   Install the Codex/Grog-style skill. Default: $HOME/.agents/skills/mcaifee.
  --codex-skill [dir]   Alias for --agent-skill.
  --path-link [dir]     Symlink mcaifee into a PATH-visible directory. Default: /usr/local/bin.
  --no-verify           Skip SHA-256 verification for downloaded binaries.
  --cosign              Require cosign signature/certificate verification.
  --no-cosign           Skip optional cosign verification.
  --dry-run             Print actions without writing files.
  -h, --help            Show this help.

Environment:
  MCAIFEE_VERSION        Same as --version.
  MCAIFEE_INSTALL_DIR    Same as --install-dir.
  MCAIFEE_INSTALL_SOURCE Same as --source.
  MCAIFEE_SHELL          Shell used by --shell-init and --shell-disable.
  MCAIFEE_REPO           GitHub repo, default turinglabsorg/mcaifee.
  MCAIFEE_AGENT_SKILL_DIR
                         Same as --agent-skill.
  MCAIFEE_PATH_LINK_DIR  Same as --path-link.
  MCAIFEE_INSTALL_VERIFY Set to 0 to skip SHA-256 verification.
  MCAIFEE_INSTALL_COSIGN Set to 1, 0, or auto. Default: auto.
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
    --agent-skill|--codex-skill)
      INSTALL_AGENT_SKILL=1
      if [ "$#" -gt 1 ] && [ "${2#-}" = "$2" ]; then
        AGENT_SKILL_DIR="$2"
        shift 2
      else
        shift
      fi
      ;;
    --path-link)
      INSTALL_PATH_LINK=1
      if [ "$#" -gt 1 ] && [ "${2#-}" = "$2" ]; then
        PATH_LINK_DIR="$2"
        shift 2
      else
        shift
      fi
      ;;
    --no-verify)
      VERIFY_DOWNLOAD=0
      shift
      ;;
    --verify)
      VERIFY_DOWNLOAD=1
      shift
      ;;
    --cosign)
      COSIGN_VERIFY=1
      shift
      ;;
    --no-cosign)
      COSIGN_VERIFY=0
      shift
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

is_url() {
  case "$1" in
    http://*|https://*) return 0 ;;
    *) return 1 ;;
  esac
}

sha256_of_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    fail "sha256sum or shasum is required to verify downloads"
  fi
}

verify_sha256() {
  binary="$1"
  source_url="$2"
  checksum_file="$3"
  expected="$(awk 'NF {print $1; exit}' "$checksum_file")"
  [ -n "$expected" ] || fail "checksum file is empty: $source_url.sha256"
  actual="$(sha256_of_file "$binary")"
  if [ "$actual" != "$expected" ]; then
    fail "checksum mismatch for $source_url"
  fi
  printf 'verified sha256: %s\n' "$expected"
}

verify_cosign_blob() {
  binary="$1"
  source_url="$2"
  sig_file="$3"
  cert_file="$4"
  command -v cosign >/dev/null 2>&1 || fail "cosign is required by --cosign"
  identity_regexp="https://github.com/$REPO/.github/workflows/release.yml@refs/tags/v.*"
  cosign verify-blob \
    --certificate "$cert_file" \
    --signature "$sig_file" \
    --certificate-identity-regexp "$identity_regexp" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "$binary" >/dev/null
  printf 'verified cosign signature: %s\n' "$source_url"
}

verify_downloaded_binary() {
  binary="$1"
  source_url="$2"
  [ "$VERIFY_DOWNLOAD" = "0" ] && return
  if ! is_url "$source_url"; then
    printf 'verification skipped: local source\n'
    return
  fi
  checksum_file="$(mktemp "${TMPDIR:-/tmp}/mcaifee.sha256.XXXXXX")"
  download "$source_url.sha256" "$checksum_file"
  verify_sha256 "$binary" "$source_url" "$checksum_file"
  rm -f "$checksum_file"

  if [ "$COSIGN_VERIFY" = "0" ]; then
    return
  fi
  if [ "$COSIGN_VERIFY" = "auto" ] && ! command -v cosign >/dev/null 2>&1; then
    printf 'cosign verification skipped: cosign not found\n'
    return
  fi
  sig_file="$(mktemp "${TMPDIR:-/tmp}/mcaifee.sig.XXXXXX")"
  cert_file="$(mktemp "${TMPDIR:-/tmp}/mcaifee.pem.XXXXXX")"
  download "$source_url.sig" "$sig_file"
  download "$source_url.pem" "$cert_file"
  verify_cosign_blob "$binary" "$source_url" "$sig_file" "$cert_file"
  rm -f "$sig_file" "$cert_file"
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

raw_ref() {
  if [ "$VERSION" = "latest" ]; then
    printf 'main'
  else
    printf '%s' "$VERSION"
  fi
}

install_skill_file() {
  source_path="$1"
  destination="$2"
  if [ -f "$source_path" ]; then
    cp "$source_path" "$destination"
  else
    ref="$(raw_ref)"
    download "https://raw.githubusercontent.com/$REPO/$ref/$source_path" "$destination"
  fi
}

install_agent_skill() {
  skill_dir="$1"
  printf 'agent skill: %s\n' "$skill_dir"

  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'dry-run: would install agent skill files\n'
    return
  fi

  mkdir -p "$skill_dir/references"
  install_skill_file "SKILL.md" "$skill_dir/SKILL.md"
  install_skill_file "README.md" "$skill_dir/README.md"
  install_skill_file "Dockerfile.malicious-test" "$skill_dir/Dockerfile.malicious-test"
  install_skill_file "references/npm-security-sources.md" "$skill_dir/references/npm-security-sources.md"
  install_skill_file "references/npm-threat-model.md" "$skill_dir/references/npm-threat-model.md"
  install_skill_file "references/source-integration-plan.md" "$skill_dir/references/source-integration-plan.md"
  printf 'agent skill installed: %s\n' "$skill_dir"
}

install_path_link() {
  binary="$1"
  link_dir="$2"
  link_path="$link_dir/mcaifee"

  printf 'path link: %s -> %s\n' "$link_path" "$binary"

  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'dry-run: would create PATH link\n'
    return
  fi

  mkdir -p "$link_dir"
  ln -sf "$binary" "$link_path"
  printf 'path link installed: %s\n' "$link_path"
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
  verify_downloaded_binary "$tmp" "$SOURCE"
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

if [ "$INSTALL_AGENT_SKILL" -eq 1 ]; then
  printf '\n'
  install_agent_skill "$AGENT_SKILL_DIR"
fi

if [ "$INSTALL_PATH_LINK" -eq 1 ]; then
  printf '\n'
  install_path_link "$target" "$PATH_LINK_DIR"
fi
