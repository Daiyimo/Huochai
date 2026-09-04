"""Extract a controlled original installer into a normalized, hashed tree."""
from __future__ import annotations

import argparse
from pathlib import Path
import os
import shutil
import tempfile

from common import FIXED_MTIME, require_new_output, run, sha256_file, write_json


DEFAULT_SEVEN_ZIP = Path(r"C:\Program Files\7-Zip\7z.exe")


def normalize(source: Path, expected: str, output: Path, seven_zip: Path,
              max_files: int, max_bytes: int):
    source = source.resolve()
    if not source.is_file():
        raise FileNotFoundError(source)
    actual = sha256_file(source)
    if actual != expected.lower():
        raise ValueError("Original input hash mismatch")
    if not seven_zip.is_file():
        raise FileNotFoundError(seven_zip)
    output = require_new_output(output)
    with tempfile.TemporaryDirectory(prefix=output.name + "-", dir=output.parent) as temporary:
        temporary = Path(temporary)
        extracted = temporary / "extracted"
        extracted.mkdir()
        run([seven_zip, "x", source, "-o" + str(extracted), "-y", "-bso0", "-bsp0"])
        entries = []
        total = 0
        for path in sorted(extracted.rglob("*"), key=lambda item: item.relative_to(extracted).as_posix()):
            if path.is_symlink():
                raise ValueError("Symbolic links are not accepted: " + str(path))
            if not path.is_file():
                continue
            relative = path.relative_to(extracted).as_posix()
            size = path.stat().st_size
            total += size
            entries.append({"path": relative, "size": size, "sha256": sha256_file(path)})
            if len(entries) > max_files or total > max_bytes:
                raise ValueError("Extracted input exceeds configured limits")
        if not entries:
            raise ValueError("Original input did not yield any files")
        stage = temporary / "normalized"
        files = stage / "files"
        shutil.copytree(extracted, files)
        for path in sorted(files.rglob("*"), reverse=True):
            os.utime(path, (FIXED_MTIME, FIXED_MTIME))
        manifest = {
            "schema_version": 1,
            "source": {"size": source.stat().st_size, "sha256": actual},
            "normalization": {
                "file_mtime_epoch": FIXED_MTIME,
                "paths": "relative POSIX order",
                "executed_input": False,
            },
            "file_count": len(entries),
            "total_size": total,
            "files": entries,
        }
        write_json(stage / "manifest.json", manifest)
        shutil.move(stage, output)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seven-zip", type=Path, default=DEFAULT_SEVEN_ZIP)
    parser.add_argument("--max-files", type=int, default=20000)
    parser.add_argument("--max-bytes", type=int, default=2 * 1024 * 1024 * 1024)
    args = parser.parse_args()
    result = normalize(args.input, args.expected_sha256, args.output, args.seven_zip,
                       args.max_files, args.max_bytes)
    print("Normalized", result["file_count"], "files without executing the input")


if __name__ == "__main__":
    main()
