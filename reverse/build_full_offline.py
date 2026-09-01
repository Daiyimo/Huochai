#!/usr/bin/env python3
"""Compatibility entry point for the reviewed offline builder.

Default: build and verify draft packages without launching the application.
Use --publish to replace both root packages after BOTH pass final verification.
The incomplete historical URL-only patcher is retained in Git history.
"""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "offline"))
from build import main

if __name__ == "__main__":
    main()
