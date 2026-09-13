#!/bin/sh
# Aragami installer for the tarball distribution.
#
# Deliberately a shell script rather than a package manager call: this is the fallback for
# systems where no native package exists yet, so it must assume nothing beyond a POSIX shell
# and Node.js. It installs per-user by default, which needs no privileges and keeps the
# system tree clean; pass --system to install under /usr/local instead.
#
#   ./install.sh              install to ~/.local
#   ./install.sh --system     install to /usr/local   (needs root)
#   ./install.sh --uninstall  remove what this installed
#
set -eu

PREFIX="${HOME}/.local"
SYSTEM=0
UNINSTALL=0

for arg in "$@"; do
  case "$arg" in
    --system)    PREFIX="/usr/local"; SYSTEM=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help)
      sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LIBDIR="${PREFIX}/lib/aragami"
BINDIR="${PREFIX}/bin"

if [ "$UNINSTALL" -eq 1 ]; then
  echo "Removing Aragami from ${PREFIX}"
  rm -rf "$LIBDIR"
  for n in aragami aragami-mcp aragami-tor aragami-tor-mcp aragami-firefox aragami-firefox-mcp; do
    rm -f "${BINDIR}/${n}"
  done
  echo "Done. User data, profiles and browser installs were not touched."
  exit 0
fi

# Node is the one hard requirement; say so plainly rather than failing halfway.
if ! command -v node >/dev/null 2>&1; then
  echo "Node.js is required but was not found on PATH (>= 18)." >&2
  echo "The single-file executable distribution needs no Node, if that is easier." >&2
  exit 1
fi

NODE_MAJOR=$(node -p 'process.versions.node.split(".")[0]')
if [ "$NODE_MAJOR" -lt 18 ]; then
  echo "Node.js ${NODE_MAJOR} found; 18 or newer is required." >&2
  exit 1
fi

if [ "$SYSTEM" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
  echo "--system requires root (try: sudo ./install.sh --system)" >&2
  exit 1
fi

echo "Installing Aragami to ${LIBDIR}"
mkdir -p "$LIBDIR" "$BINDIR"
cp -R "${HERE}/dist" "$LIBDIR/"
cp "${HERE}/README.md" "$LIBDIR/" 2>/dev/null || true
cp "${HERE}/LICENSE" "$LIBDIR/" 2>/dev/null || true
# The seal, under its bare name. Tolerated rather than required for the same reason as the two
# above: an installation from a tree that has no emblem still installs and reports its absence.
cp "${HERE}/Aragami" "$LIBDIR/" 2>/dev/null || true

# Wrappers rather than copies of the launchers, so the target pinning lives in one place and
# the installed command follows an upgrade of the library directory.
write_wrapper() {
  name="$1"; mode="$2"; pinned="$3"
  entry="cli.cjs"; [ "$mode" = "mcp" ] && entry="mcp.cjs"
  {
    echo '#!/bin/sh'
    [ -n "$pinned" ] && echo "ARAGAMI_TARGET=${pinned}; export ARAGAMI_TARGET"
    echo "exec node \"${LIBDIR}/dist/${entry}\" \"\$@\""
  } > "${BINDIR}/${name}"
  chmod 755 "${BINDIR}/${name}"
}

write_wrapper aragami          cli ""
write_wrapper aragami-mcp      mcp ""
write_wrapper aragami-tor      cli tor
write_wrapper aragami-tor-mcp  mcp tor
write_wrapper aragami-firefox     cli firefox
write_wrapper aragami-firefox-mcp mcp firefox

case ":${PATH}:" in
  *":${BINDIR}:"*) ;;
  *) echo
     echo "Note: ${BINDIR} is not on PATH. Add it with:"
     echo "  export PATH=\"${BINDIR}:\$PATH\"" ;;
esac

echo
echo "Installed. Try:"
echo "  aragami --help"
echo "  aragami-tor aragami_audit --human"
echo "  aragami-firefox aragami_audit --human"
echo
echo "This is an auditor, not a hardening tool: it reads files and reports static residue."
echo "A clean audit is not proof of safety."
