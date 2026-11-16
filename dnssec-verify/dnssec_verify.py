#!/usr/bin/env python3 -I
"""Entry point so the tool can run under Python isolated mode (-I).

Isolated mode ignores PYTHONPATH, so the third-party library directory and
the package root are added explicitly here before any package import.
"""
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.path.insert(0, "/workspace/pylibs")

from dnssecverify.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
