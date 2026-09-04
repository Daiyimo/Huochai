"""Create an answer-free starter directory for one benchmark track."""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import tempfile

from common import (
    BENCHMARK, checked_relative, copy_readonly, read_json,
    private_output, require_new_output, sha256_file, write_json,
)
from fixture_generator import generate


def validated_inputs(track: str, input_root: Path):
    manifest = read_json(BENCHMARK / "tasks" / track / "input-manifest.json")
    result = []
    for item in manifest["files"]:
        relative = checked_relative(item["path"])
        source = input_root / relative
        if not source.is_file():
            raise FileNotFoundError("Missing benchmark input: " + item["path"])
        actual = sha256_file(source)
        if actual != item["sha256"]:
            raise ValueError("Benchmark input hash mismatch: " + item["path"])
        result.append((item, relative, source))
    return result


def report_template(task):
    return {
        "schema_version": 1,
        "task_id": task["id"],
        "requirements": [
            {"id": item["id"], "implementation": "", "evidence": []}
            for item in task["requirements"]
        ],
        "known_limitations": [],
        "metrics": {},
    }


def prepare(track: str, output: Path, seed: int | None, input_root: Path | None, audit_source: Path | None):
    output = require_new_output(output)
    if audit_source is not None:
        audit_source = private_output(audit_source)
        if audit_source.is_relative_to(output):
            raise ValueError("Evaluator audit source must stay outside the starter")
    task_dir = BENCHMARK / "tasks" / track
    task = read_json(task_dir / "task.json")
    inputs = None if track == "t1" else validated_inputs(track, input_root)
    with tempfile.TemporaryDirectory(prefix=output.name + "-", dir=output.parent) as temporary:
        stage = Path(temporary) / "starter"
        stage.mkdir()
        shutil.copy2(task_dir / "task.md", stage / "TASK.md")
        shutil.copy2(task_dir / "task.json", stage / "task.json")
        shutil.copy2(BENCHMARK / "environment.lock.json", stage / "environment.lock.json")
        shutil.copy2(BENCHMARK / "submission.schema.json", stage / "submission.schema.json")
        shutil.copy2(BENCHMARK / "rubric.json", stage / "rubric.json")
        input_lock = []
        if track == "t1":
            if seed is None:
                raise ValueError("T1 requires --seed")
            generated = Path(temporary) / "generated"
            manifest = generate(generated, seed, audit_source)
            destination = stage / "inputs/original.exe"
            copy_readonly(generated / "original.exe", destination)
            shutil.copy2(generated / "manifest.json", stage / "input-manifest.json")
            input_lock.append(manifest["input"])
        else:
            if seed is not None:
                raise ValueError("--seed is only valid for T1")
            for item, relative, source in inputs:
                destination = stage / "inputs" / relative
                copy_readonly(source, destination)
                input_lock.append({
                    "path": (Path("inputs") / relative).as_posix(),
                    "size": destination.stat().st_size,
                    "sha256": item["sha256"],
                })
            write_json(stage / "input-manifest.json", {
                "schema_version": 1, "track": track, "files": input_lock
            })
        write_json(stage / ".input-lock.json", {
            "schema_version": 1, "task_id": task["id"], "files": input_lock
        })
        submission = stage / "submission"
        (submission / "source").mkdir(parents=True)
        (submission / "decisions.md").write_text("# Decisions\n", encoding="utf-8")
        write_json(submission / "report.json", report_template(task))
        shutil.move(stage, output)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--track", choices=("t1", "t2", "t3"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--inputs-dir", type=Path)
    parser.add_argument("--audit-source", type=Path,
                        help="Optional evaluator-only source path outside the starter")
    args = parser.parse_args()
    if args.track != "t1" and args.inputs_dir is None:
        parser.error("T2/T3 require --inputs-dir")
    result = prepare(args.track, args.output, args.seed, args.inputs_dir, args.audit_source)
    print("Prepared answer-free starter:", result)


if __name__ == "__main__":
    main()
