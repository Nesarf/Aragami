#!/bin/sh
# Put a self-contained Node binary at the given path, for packaging forms that must carry
# their own runtime.
#
#   fetch-node.sh /path/to/node
#
# Why not copy the node that is already installed: it was, and the AppImage it produced
# reported "libnode.so.127: cannot open shared object file" on any machine without that
# library. Distribution builds of nodejs link against a shared libnode and resolve some
# builtins through absolute host paths, so copying one into a bundle produces a runtime that
# only works on the machine that built it. The official Node build is self-contained and needs
# nothing beyond the host's libc.
#
# The version and digest live here rather than in each caller, because there are two callers
# -- the AppImage step and the snap's node part -- and a version written down twice is a
# version that will disagree with itself.
set -eu

DEST="$1"
VERSION=22.23.2
SHA256=d60acfe00a2932254bb0ad20e01b0d74397a0875595de719654b214f4b03f307
URL="https://nodejs.org/dist/v${VERSION}/node-v${VERSION}-linux-x64.tar.xz"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

curl -fsSL -o "$TMP/node.tar.xz" "$URL"
# The digest is checked rather than trusted: this is a binary that ends up inside the
# artifact people install, and it is fetched from the network during a build.
printf '%s  %s\n' "$SHA256" "$TMP/node.tar.xz" | sha256sum -c - >/dev/null

tar -xJf "$TMP/node.tar.xz" -C "$TMP"
install -d "$(dirname "$DEST")"
install -m 755 "$TMP/node-v${VERSION}-linux-x64/bin/node" "$DEST"

printf '  node %s -> %s\n' "$VERSION" "$DEST"
