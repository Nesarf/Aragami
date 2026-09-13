#!/bin/sh
# Build the per-target .rpm packages.
#
# rpmbuild has no Windows equivalent, so unlike the .deb this is not assembled by a
# PowerShell script: it runs under Linux (WSL locally, ubuntu-latest in CI). The spec is
# generated per target from aragami.spec.in rather than duplicated three times, because
# the only things that differ are the package name and the conflicts it declares -- and a
# spec that has been copied three times is a spec that will drift.
#
#   build-rpm.sh <version> <sources-dir> <out-dir>
#
# <sources-dir> must contain dist/ (dist/cli.cjs, dist/mcp.cjs), README.md, LICENSE and Aragami.
set -eu

VERSION="$1"
SOURCES="$2"
OUT="$3"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

for f in dist/cli.cjs dist/mcp.cjs README.md LICENSE Aragami; do
  [ -f "$SOURCES/$f" ] || { echo "missing $SOURCES/$f" >&2; exit 2; }
done

TOP=$(mktemp -d)
trap 'rm -rf "$TOP"' EXIT
mkdir -p "$TOP/BUILD" "$TOP/RPMS" "$TOP/SOURCES" "$TOP/SPECS" "$TOP/SRPMS" "$OUT"
cp -R "$SOURCES/dist" "$SOURCES/README.md" "$SOURCES/LICENSE" "$SOURCES/Aragami" "$TOP/SOURCES/"

for T in all tor firefox; do
  if [ "$T" = all ]; then
    NAME=aragami
    CONFLICTS=""
  else
    NAME="aragami-$T"
    # Every variant owns the same /usr/bin wrappers and the same /usr/share payload, so
    # they have to declare each other. Without this rpm would install a second copy over
    # the first and leave a mixture of the two on disk.
    CONFLICTS="Conflicts: aragami, aragami-tor, aragami-firefox"
  fi

  sed -e "s/@VERSION@/$VERSION/" \
      -e "s/@PACKAGE@/$NAME/" \
      -e "s|@CONFLICTS@|$CONFLICTS|" \
      "$HERE/rpm/aragami.spec.in" > "$TOP/SPECS/$NAME.spec"

  rpmbuild --define "_topdir $TOP" -bb "$TOP/SPECS/$NAME.spec" >/dev/null
  found=$(find "$TOP/RPMS" -name "$NAME-$VERSION-*.rpm" | head -1)
  [ -n "$found" ] || { echo "rpmbuild produced nothing for $NAME" >&2; exit 1; }
  cp "$found" "$OUT/"
  echo "  [ok] $(basename "$found")"
done
