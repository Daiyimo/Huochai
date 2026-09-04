"""Generate seed-varying authored PE inputs for the T1 benchmark."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import random
import shutil
import tempfile

from common import require_new_output, run, vc_environment, write_json, sha256_file


TARGETS = (
    ("GetTickCount", 0xC0DEC0DE),
    ("GetCurrentProcessId", 0xA11CE101),
    ("GetCurrentThreadId", 0xB16B00B5),
)


def source_for(seed: int):
    rng = random.Random(seed)
    api, expected = TARGETS[rng.randrange(len(TARGETS))]
    token = "".join(rng.choice("abcdef0123456789") for _ in range(12))
    endpoint = f"https://case-{token}.invalid/demo/{seed % 997:03d}"
    source = f'''/* Authored benchmark fixture; generated from seed {seed}. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

volatile char benchmark_endpoint[] = "{endpoint}";

int main(int argc, char **argv) {{
    const char replacement[] = "about:blank";
    unsigned i;
    int cleaned = 1;
    int hooked = {api}() == 0x{expected:08X}u;
    for (i = 0; i < sizeof(replacement) - 1; ++i)
        if (benchmark_endpoint[i] != replacement[i]) cleaned = 0;
    if (argc != 2) return 2;
    printf("hooked=%d url_cleaned=%d\\n", hooked, cleaned);
    if (!strcmp(argv[1], "original")) return cleaned ? 3 : 0;
    if (!strcmp(argv[1], "patched")) return hooked && cleaned ? 0 : 4;
    return 2;
}}
'''
    return source, endpoint, api, expected


def generate(output: Path, seed: int, audit_source: Path | None = None):
    output = require_new_output(output)
    source, endpoint, api, expected = source_for(seed)
    environment = vc_environment()
    with tempfile.TemporaryDirectory(prefix="huochai-benchmark-fixture-") as directory:
        work = Path(directory)
        source_path = work / "fixture.c"
        source_path.write_text(source, encoding="utf-8")
        binary = work / "original.exe"
        run([
            environment["HUOCHAI_BENCHMARK_CL"], "/nologo", "/utf-8", "/MT", "/O1", source_path,
            "/link", "kernel32.lib", "/DYNAMICBASE", "/NXCOMPAT", "/OUT:" + str(binary)
        ], cwd=work, env=environment)
        output.mkdir(parents=True)
        shutil.copy2(binary, output / "original.exe")
    if audit_source:
        audit_source.parent.mkdir(parents=True, exist_ok=True)
        audit_source.write_text(source, encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "track": "t1",
        "seed": seed,
        "input": {
            "path": "inputs/original.exe",
            "size": (output / "original.exe").stat().st_size,
            "sha256": sha256_file(output / "original.exe"),
        },
        "patch_contract": {
            "url": endpoint,
            "replacement": "about:blank",
            "import_library": "KERNEL32.dll",
            "hook_library": "hook.dll",
            "target_api": api,
            "expected_value": f"0x{expected:08X}",
            "expected_stdout": "hooked=1 url_cleaned=1",
        },
    }
    write_json(output / "manifest.json", manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--audit-source", type=Path)
    args = parser.parse_args()
    generate(args.output, args.seed, args.audit_source)
    print("Generated deterministic T1 fixture contract for seed", args.seed)


if __name__ == "__main__":
    main()
