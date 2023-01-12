#!/usr/bin/bash

set -e
set -o pipefail

update_version() {
    file="$1"
    lines="$(grep -n '^name = "deepctl"$' $file)"
    if [ "$(echo $lines | wc -l)" != 1 ]; then
        echo "Can't find the right line to update" >&2
        exit 1
    fi

    line_no="${lines%%:*}"
    sed -i "$((line_no+1)) c version = \"$VERSION\"" $file
}

if [ $# -ne 1 ]; then
    echo "$0 X.Y.Z" >&2
    exit 1
fi

VERSION="$1"

if [ ! -z "$(git status --porcelain)" -o "$(git branch --show)" != "main" ]; then
    echo "Please cleanup your working directory, and switch to \"main\" branch" >&2
    exit 1
fi

update_version Cargo.toml
update_version Cargo.lock

git diff | cat

echo -n "Does this look ok?[y/N] " >&2
read res

if [ "$res" != 'y' -a "$res" != 'Y' ]; then
    echo "Oh, well. Suit yourself!" >&2
    exit 1
fi

echo -e "\nCommitting, tagging and pushing . . ." >&2
sleep 2

git commit -a -m "Bump version to $VERSION"
git tag "v${VERSION}"
git push origin main --tags
