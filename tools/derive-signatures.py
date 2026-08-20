#!/usr/bin/env python3
"""Surface candidate version strings from binaries whose versions are known.

This is the harness behind `src-tauri/src/binscan/native/signatures.toml`, and
behind the claim that those signatures are ours rather than transcribed from
cve-bin-tool. It takes a root filesystem that still has its package metadata,
reads the version the package manager recorded for each package, and prints the
strings inside that package's binaries which contain it.

Those strings are the raw material. Turning one into a signature is a judgement
call a person makes — pick an anchor that is prose rather than digits, avoid ELF
symbol-version tags, require enough context that a mention cannot pass for a
declaration — and the reasoning for each is recorded next to it in the TOML.

Usage:
    python3 tools/derive-signatures.py <rootfs> [pkg1,pkg2,...]

Getting a corpus with ground truth, e.g. from any distribution image:
    cid=$(docker create debian:trixie /bin/true)
    docker export "$cid" | tar -x -C rootfs && docker rm "$cid"
"""

import os, re, sys, collections

ROOT = sys.argv[1]
WANT = set(sys.argv[2].split(",")) if len(sys.argv) > 2 else None

def dpkg_versions(root):
    out = {}
    status = os.path.join(root, "var/lib/dpkg/status")
    pkg = ver = None
    for line in open(status, errors="replace"):
        if line.startswith("Package: "): pkg = line.split(": ",1)[1].strip()
        elif line.startswith("Version: "): ver = line.split(": ",1)[1].strip()
        elif line.strip() == "" and pkg and ver:
            out[pkg] = ver; pkg = ver = None
    if pkg and ver: out[pkg] = ver
    return out

def upstream(version):
    """Strip the Debian epoch and revision: 1:8.14.1-2+deb13u1 -> 8.14.1"""
    v = version.split(":",1)[-1]
    v = re.split(r"[-+]", v)[0]
    return v

def files_for(root, pkg):
    for suffix in (".list",):
        p = os.path.join(root, "var/lib/dpkg/info", pkg + suffix)
        if os.path.exists(p):
            for line in open(p, errors="replace"):
                f = os.path.join(root, line.strip().lstrip("/"))
                if os.path.isfile(f) and not os.path.islink(f):
                    yield f

PRINTABLE = re.compile(rb"[\x20-\x7e\t]{4,}")

def strings_of(path, cap=32*1024*1024):
    with open(path, "rb") as fh:
        data = fh.read(cap)
    return [m.group().decode("ascii", "replace") for m in PRINTABLE.finditer(data)]

versions = dpkg_versions(ROOT)
for pkg, raw in sorted(versions.items()):
    if WANT and pkg not in WANT: continue
    up = upstream(raw)
    if not re.match(r"^\d+(\.\d+)+", up): continue
    hits = collections.Counter()
    n_files = 0
    for f in files_for(ROOT, pkg):
        try:
            with open(f, "rb") as fh: head = fh.read(4)
        except OSError: continue
        if head[:4] != b"\x7fELF": continue
        n_files += 1
        for s in strings_of(f):
            if up in s and len(s) < 200:
                hits[s.strip()] += 1
    if hits:
        print(f"\n### {pkg} {raw}  (upstream {up}, {n_files} ELF files)")
        for s, c in hits.most_common(8):
            print(f"    [{c}] {s!r}")
