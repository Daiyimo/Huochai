"""Generate a deterministic synthetic filename-search corpus and query oracle."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import random

from common import FIXED_MTIME, require_new_output, sha256_file, write_json


EXTENSIONS = ("txt", "zip", "md", "json", "png", "log", "pdf")
WORDS = ("alpha", "bravo", "cache", "delta", "engine", "fixture", "local", "search")


def generate(output: Path, seed: int, file_count: int):
    if file_count < 20:
        raise ValueError("file-count must be at least 20")
    output = require_new_output(output)
    files_root = output / "files"
    files_root.mkdir(parents=True)
    rng = random.Random(seed)
    records = []
    for index in range(file_count):
        extension = EXTENSIONS[index % len(EXTENSIONS)]
        left, right = rng.sample(WORDS, 2)
        directory = files_root / ("group-%02d" % (index % 17)) / ("层级-%02d" % (index % 5))
        directory.mkdir(parents=True, exist_ok=True)
        name = f"{left}-{right}-{seed:04x}-{index:06d}.{extension}"
        if index == 3:
            name = f"中文 本地样例 {seed:04x}.txt"
        path = directory / name
        content = hashlib.sha256(f"{seed}:{index}:{name}".encode()).digest()
        path.write_bytes(content)
        os.utime(path, (FIXED_MTIME, FIXED_MTIME))
        relative = path.relative_to(files_root).as_posix()
        records.append({"path": relative, "size": len(content), "sha256": sha256_file(path)})
    duplicate_paths = []
    duplicate_name = f"shared-{seed:04x}.txt"
    for leaf in ("duplicates/a", "duplicates/b"):
        path = files_root / leaf / duplicate_name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(leaf, encoding="utf-8")
        os.utime(path, (FIXED_MTIME, FIXED_MTIME))
        relative = path.relative_to(files_root).as_posix()
        duplicate_paths.append(relative)
        records.append({"path": relative, "size": path.stat().st_size, "sha256": sha256_file(path)})
    records.sort(key=lambda item: item["path"])
    unique = records[3]
    manifest = {
        "schema_version": 1,
        "seed": seed,
        "file_count": len(records),
        "files": records,
        "queries": [
            {"kind": "exact", "query": Path(unique["path"]).name, "expected_paths": [unique["path"]]},
            {"kind": "duplicate", "query": duplicate_name, "expected_paths": duplicate_paths},
            {"kind": "chinese", "query": f'"中文 本地样例 {seed:04x}.txt"',
             "expected_paths": [item["path"] for item in records if "中文 本地样例" in item["path"]]},
            {"kind": "missing", "query": f"missing-{seed:04x}-never", "expected_paths": []},
        ],
        "mutations": [
            {"action": "create", "path": f"mutations/new-{seed:04x}.zip"},
            {"action": "rename", "from": f"mutations/new-{seed:04x}.zip", "to": f"mutations/renamed-{seed:04x}.zip"},
            {"action": "delete", "path": f"mutations/renamed-{seed:04x}.zip"},
        ],
        "fixed_mtime_epoch": FIXED_MTIME,
    }
    write_json(output / "manifest.json", manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--file-count", type=int, default=1000)
    args = parser.parse_args()
    result = generate(args.output, args.seed, args.file_count)
    print("Generated", result["file_count"], "deterministic corpus files")


if __name__ == "__main__":
    main()
