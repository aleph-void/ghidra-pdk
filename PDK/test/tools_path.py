"""Locates the SDCC tools used as black-box references: ucsim_pdk and sdaspdk13/14/15.
Looks in $UCSIM_PDK, on PATH, then under $SDCC_ROOT/usr/bin (a prefix holding an SDCC install)."""
import os, shutil


def find(name, env=None):
    if env and os.environ.get(env):
        return os.environ[env]
    p = shutil.which(name)
    if p:
        return p
    root = os.environ.get("SDCC_ROOT")
    if root and os.path.exists(os.path.join(root, "usr", "bin", name)):
        return os.path.join(root, "usr", "bin", name)
    raise SystemExit(f"{name} not found: put SDCC (with the pdk backends) on PATH or set SDCC_ROOT")
