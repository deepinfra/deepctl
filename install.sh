#!/bin/sh
# Based on Deno installer. Copyright 2019 the Deno authors. All rights reserved. MIT license.
# TODO(everyone): Keep this script simple and easily auditable.

set -e

if [ "$OS" = "Windows_NT" ]; then
  target="windows"
  echo "Windows is not supported at the moment, sorry" >&2
  exit 1
else
  case $(uname -sm) in
    "Darwin x86_64")
      target="macos"
      ;;
    "Darwin arm64")
      target="macos"
      ;;
    *)
      target="linux"
      ;;
  esac
fi

if [ $# -eq 0 ]; then
  SOURCE_URI="https://github.com/deepinfra/deepctl/releases/latest/download/deepctl-${target}"
else
  SOURCE_URI="https://github.com/deepinfra/deepctl/releases/download/${1}/deepctl-${target}"
fi

EXE_NAME="${DEEPCTL_EXE_NAME:-deepctl}"
DEEPCTL_INSTALL="${DEEPCTL_INSTALL:-/usr/local/bin}"
EXE_TARGET="$DEEPCTL_INSTALL/$EXE_NAME"

if [ "${DEEPCTL_INSTALL#$HOME}" != "$DEEPCTL_INSTALL" ]; then
    # assume subdirs of $HOME are writable without sudo
    MAYSUDO="env --"
else
    # assume everything outside $HOME requires sudo
    echo -e "\nYou may be prompted for sudo password to write $EXE_TARGET" >&2
    echo -e "To change the install folder you can set \$DEEPCTL_INSTALL:\n" >&2
    echo -e "  curl https://deepinfra.com/get.sh | DEEPCTL_INSTALL=another/dir bash\n" >&2
    MAYSUDO="sudo"
fi

if [ ! -d "$DEEPCTL_INSTALL" ]; then
    $MAYSUDO mkdir -p "$DEEPCTL_INSTALL"
fi

$MAYSUDO curl --fail --location --progress-bar --output "$EXE_TARGET" "$SOURCE_URI"
$MAYSUDO chmod +x "$EXE_TARGET"

echo "deepctl was installed successfully to $EXE_TARGET"
if ! command -v "$EXE_NAME" >/dev/null; then
  case $SHELL in
    /bin/zsh) shell_profile=".zshrc" ;;
    *) shell_profile=".bashrc" ;;
  esac
  echo "Manually add the directory to your \$HOME/$shell_profile (or similar)"
  echo "  echo 'export PATH=\"$DEEPCTL_INSTALL:\$PATH\"' >> \$HOME/$shell_profile"
  echo "  export PATH=\"$DEEPCTL_INSTALL:\$PATH\""
fi
echo "Run '$EXE_NAME --help' to get started"
