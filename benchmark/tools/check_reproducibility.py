"""Run a command repeatedly and report semantic and byte reproducibility."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess

from common import require_new_output, sha256_file, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=2)
    parser.add_argument("--artifact", action="append", required=True,
                        help="Relative artifact path under each {output}")
    parser.add_argument("command", nargs=argparse.REMAINDER,
                        help="Command after --; use {output} as a token or inside an argument")
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if args.runs < 2 or not command:
        parser.error("At least two runs and a command are required")
    output = require_new_output(args.output)
    output.mkdir(parents=True)
    runs = []
    for index in range(args.runs):
        directory = output / ("run-%02d" % (index + 1))
        directory.mkdir()
        rendered = [token.replace("{output}", str(directory)) for token in command]
        result = subprocess.run(rendered, capture_output=True)
        if result.returncode:
            raise RuntimeError(result.stdout.decode("utf-8", "replace") + result.stderr.decode("utf-8", "replace"))
        artifacts = {}
        for relative in args.artifact:
            path = directory / relative
            if not path.is_file():
                raise FileNotFoundError(path)
            artifacts[relative] = {"size": path.stat().st_size, "sha256": sha256_file(path)}
        runs.append({
            "index": index + 1,
            "stdout_sha256": __import__("hashlib").sha256(result.stdout).hexdigest(),
            "artifacts": artifacts,
        })
    byte_reproducible = all(
        run["artifacts"] == runs[0]["artifacts"] for run in runs[1:]
    )
    stdout_reproducible = all(
        run["stdout_sha256"] == runs[0]["stdout_sha256"] for run in runs[1:]
    )
    report = {
        "schema_version": 1,
        "run_count": len(runs),
        "byte_reproducible": byte_reproducible,
        "stdout_reproducible": stdout_reproducible,
        "runs": runs,
    }
    write_json(output / "reproducibility.json", report)
    print("Byte reproducible:", byte_reproducible)
    print("Stdout reproducible:", stdout_reproducible)


if __name__ == "__main__":
    main()
