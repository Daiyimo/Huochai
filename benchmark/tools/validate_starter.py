"""Verify starter isolation and re-hash every protected input."""
from __future__ import annotations

import argparse
from pathlib import Path

from common import checked_relative, read_json, sha256_file, write_json


def validate(starter: Path):
    starter = starter.resolve()
    if not starter.is_dir():
        raise FileNotFoundError(starter)
    for forbidden in (".git", "reverse"):
        if (starter / forbidden).exists():
            raise ValueError("Starter contains forbidden answer material: " + forbidden)
    lock = read_json(starter / ".input-lock.json")
    checked = []
    for item in lock["files"]:
        path = starter / checked_relative(item["path"])
        if path.is_symlink() or not path.is_file():
            raise ValueError("Protected starter input missing or linked: " + item["path"])
        if path.stat().st_size != item["size"] or sha256_file(path) != item["sha256"]:
            raise ValueError("Protected starter input changed: " + item["path"])
        checked.append(item["path"])
    return {"schema_version": 1, "task_id": lock["task_id"], "valid": True,
            "answer_material_absent": True, "protected_inputs": checked}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--starter", type=Path, required=True)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    result = validate(args.starter)
    if args.receipt:
        write_json(args.receipt, result)
    print("Starter valid:", len(result["protected_inputs"]), "protected inputs")


if __name__ == "__main__":
    main()
