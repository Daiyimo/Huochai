"""Validate a benchmark submission contract without trusting its own claims."""
from __future__ import annotations

import argparse
from pathlib import Path

from common import checked_relative, read_json, sha256_file, write_json


def validate(task_path: Path, submission: Path):
    task = read_json(task_path)
    submission = submission.resolve()
    if not submission.is_dir():
        raise FileNotFoundError(submission)
    for path in submission.rglob("*"):
        if path.is_symlink():
            raise ValueError("Submission contains a symbolic link: " + str(path))
    missing = []
    for value in task["submission"]["required_files"]:
        relative = checked_relative(value)
        if not (submission / relative).exists():
            missing.append(value)
    if missing:
        raise ValueError("Missing submission entries: " + ", ".join(missing))
    source = submission / "source"
    if source.is_dir() and not any(path.is_file() for path in source.rglob("*")):
        raise ValueError("Submission source directory is empty")
    report = read_json(submission / "report.json")
    if report.get("schema_version") != 1 or report.get("task_id") != task["id"]:
        raise ValueError("Submission report task identity mismatch")
    expected = [item["id"] for item in task["requirements"]]
    received = [item.get("id") for item in report.get("requirements", [])]
    if len(received) != len(set(received)) or set(received) != set(expected):
        raise ValueError("Submission requirement evidence is incomplete or duplicated")
    for item in report["requirements"]:
        if not isinstance(item.get("implementation"), str) or not item["implementation"].strip():
            raise ValueError("Missing implementation evidence for " + item["id"])
        if not isinstance(item.get("evidence"), list) or not item["evidence"]:
            raise ValueError("Missing validation evidence for " + item["id"])
    files = []
    for path in sorted(submission.rglob("*")):
        if path.is_file():
            files.append({
                "path": path.relative_to(submission).as_posix(),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            })
    return {"schema_version": 1, "task_id": task["id"], "valid": True, "files": files}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task", type=Path, required=True)
    parser.add_argument("--submission", type=Path, required=True)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    result = validate(args.task, args.submission)
    if args.receipt:
        write_json(args.receipt, result)
    print("Submission contract valid:", len(result["files"]), "files")


if __name__ == "__main__":
    main()
