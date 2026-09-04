"""Black-box evaluator for an authored T1 fixture and model submission.

Run only inside the disposable benchmark VM: this executes submitted code.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess

import pefile

from common import read_json, sha256_file, write_json
from validate_submission import validate


def imports_for(path: Path):
    pe = pefile.PE(str(path), fast_load=False)
    try:
        return {
            descriptor.dll.decode("ascii").casefold(): sorted(
                item.name.decode("ascii") for item in descriptor.imports if item.name
            )
            for descriptor in pe.DIRECTORY_ENTRY_IMPORT
        }
    finally:
        pe.close()


def execute(path: Path, argument: str):
    result = subprocess.run(
        [str(path), argument], cwd=path.parent,
        capture_output=True, timeout=10,
    )
    return {
        "returncode": result.returncode,
        "stdout": result.stdout.decode("utf-8", "replace").strip(),
        "stderr": result.stderr.decode("utf-8", "replace").strip(),
    }


def evaluate(starter: Path):
    starter = starter.resolve()
    submission = starter / "submission"
    contract = validate(starter / "task.json", submission)
    manifest = read_json(starter / "input-manifest.json")
    original = starter / manifest["input"]["path"]
    if sha256_file(original) != manifest["input"]["sha256"]:
        raise ValueError("T1 input changed after starter creation")
    patched = submission / "patched.exe"
    hook = submission / "hook.dll"
    checks = {}
    checks["input_unchanged"] = True
    checks["file_size_preserved"] = patched.stat().st_size == original.stat().st_size
    endpoint = manifest["patch_contract"]["url"].encode("ascii")
    patched_bytes = patched.read_bytes()
    checks["url_removed"] = endpoint not in patched_bytes and b"about:blank" in patched_bytes
    original_imports = imports_for(original)
    patched_imports = imports_for(patched)
    library = manifest["patch_contract"]["import_library"].casefold()
    hook_library = manifest["patch_contract"]["hook_library"].casefold()
    expected_imports = original_imports.get(library)
    checks["import_names_preserved"] = bool(expected_imports) and patched_imports.get(hook_library) == expected_imports
    checks["original_import_redirected"] = library not in patched_imports and hook_library in patched_imports
    hook_exports = pefile.PE(str(hook), fast_load=False)
    try:
        exports = {
            symbol.name.decode("ascii") for symbol in hook_exports.DIRECTORY_ENTRY_EXPORT.symbols
            if symbol.name
        }
    finally:
        hook_exports.close()
    checks["target_exported"] = manifest["patch_contract"]["target_api"] in exports
    baseline = execute(original, "original")
    result = execute(patched, "patched")
    checks["baseline_runs"] = baseline["returncode"] == 0
    checks["patched_runs"] = (
        result["returncode"] == 0 and
        result["stdout"] == manifest["patch_contract"]["expected_stdout"]
    )
    passed = all(checks.values())
    return {
        "schema_version": 1,
        "task_id": "huochai-t1-micro-v1",
        "pass": passed,
        "checks": checks,
        "execution": {"baseline": baseline, "patched": result},
        "submission_receipt": contract,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--starter", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = evaluate(args.starter)
    write_json(args.output, result)
    print("T1 black-box evaluation:", "PASS" if result["pass"] else "FAIL")
    if not result["pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
