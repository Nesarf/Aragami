#!/usr/bin/env python3
"""Build a tar.gz with explicitly stated Unix metadata.

Why this exists rather than a call to tar: the Linux packages are assembled on Windows, where
the filesystem has no execute bit and ownership cannot be set. bsdtar therefore wrote every
member as 0666 and every directory as 0777 -- which produced a .deb whose /usr/bin wrappers
installed without an execute bit, and a tarball whose install.sh could not be run. The modes
have to be *stated*, not inherited, and tarfile lets them be stated per member.

That defect was fixed in the .deb first and left in the tarball, because the fix went into the
.deb's own builder. This is the one builder both use, so the next form added cannot repeat it.

    mktar.py <source-dir> <output.tar.gz> [--prefix NAME]
    mktar.py --check <archive>

Without --prefix the members are ./relative, which is what dpkg expects. With one they are
NAME/relative, which is what a release tarball expects so that it unpacks into a directory.

Modes: directories 0755; anything named install.sh, anything AppImage runs, and anything under
usr/bin is a program and gets 0755; everything else is data and gets 0644. Ownership is forced
to root:root because a package built on Windows has no such account to inherit, and an archive
whose files unpack owned by a nonexistent uid is a real defect even though it is a quiet one.
"""

import os
import sys
import tarfile

# Programs, by rule rather than by a list of paths that has to be kept in step with the tree.
EXEC_NAMES = {"install.sh", "AppRun"}


def mode_for(rel: str, is_dir: bool) -> int:
    if is_dir:
        return 0o755
    parts = rel.split("/")
    if parts[-1] in EXEC_NAMES:
        return 0o755
    if len(parts) >= 2 and "/".join(parts[:-1]) == "usr/bin":
        return 0o755
    return 0o644


def build(src: str, out: str, prefix: str) -> int:
    if not os.path.isdir(src):
        print(f"not a directory: {src}", file=sys.stderr)
        return 2
    # "./" for dpkg's convention, "NAME/" for a tarball that should unpack into a directory.
    lead = "./" if prefix == "./" else prefix.rstrip("/") + "/"

    with tarfile.open(out, "w:gz", format=tarfile.GNU_FORMAT) as tf:
        root = tarfile.TarInfo(lead)
        root.type = tarfile.DIRTYPE
        root.mode = 0o755
        root.uid = root.gid = 0
        root.uname = root.gname = "root"
        tf.addfile(root)

        count = 0
        for cur, dirs, files in os.walk(src):
            dirs.sort()
            for name in sorted(dirs):
                path = os.path.join(cur, name)
                rel = os.path.relpath(path, src).replace(os.sep, "/")
                info = tf.gettarinfo(path, arcname=lead + rel)
                info.mode = mode_for(rel, True)
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                tf.addfile(info)
                count += 1
            for name in sorted(files):
                path = os.path.join(cur, name)
                rel = os.path.relpath(path, src).replace(os.sep, "/")
                info = tf.gettarinfo(path, arcname=lead + rel)
                info.mode = mode_for(rel, False)
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                with open(path, "rb") as fh:
                    tf.addfile(info, fh)
                count += 1

    print(count)
    return 0


def check(archive: str) -> int:
    """Assert the modes a package has to carry to be usable at all.

    This is the assertion that was missing the first time: the wrappers under usr/bin had mode
    0666, so dpkg would have installed them as ordinary files, and install.sh in the tarball
    had mode 0666 so `./install.sh` failed with "Permission denied" while the README told the
    reader to run exactly that.
    """
    bad = []
    with tarfile.open(archive, "r:gz") as tf:
        for m in tf.getmembers():
            rel = m.name
            if rel.startswith("./"):
                rel = rel[2:]
            elif "/" in rel:
                rel = rel.split("/", 1)[1]
            if not rel:
                continue
            want = mode_for(rel, m.isdir())
            if m.mode != want:
                bad.append(f"{m.name}: mode {m.mode:04o}, expected {want:04o}")
            if m.uname != "root" or m.gname != "root":
                bad.append(f"{m.name}: owner {m.uname}:{m.gname}, expected root:root")
    if bad:
        for b in bad:
            print(f"  [!!] {b}", file=sys.stderr)
        return 1
    print("ok")
    return 0


def main() -> int:
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == "--check":
        return check(args[1])
    prefix = "./"
    if "--prefix" in args:
        i = args.index("--prefix")
        prefix = args[i + 1]
        del args[i:i + 2]
    if len(args) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    return build(args[0], args[1], prefix)


if __name__ == "__main__":
    sys.exit(main())
