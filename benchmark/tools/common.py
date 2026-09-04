"""Shared fail-closed helpers for benchmark preparation tools."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
BENCHMARK = ROOT / "benchmark"
FIXED_MTIME = 946684800  # 2000-01-01 UTC; representable by Windows archives.


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".new")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def checked_relative(value: str) -> Path:
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or any(part in ("", ".", "..") for part in pure.parts):
        raise ValueError("Unsafe relative path: " + value)
    if "\\" in value:
        raise ValueError("Manifest paths must use forward slashes: " + value)
    return Path(*pure.parts)


def private_output(value: Path) -> Path:
    path = value.resolve()
    if path.is_relative_to(ROOT) and not path.is_relative_to((ROOT / ".local").resolve()):
        raise ValueError("Benchmark outputs inside the repository must be under .local/")
    return path


def require_new_output(value: Path) -> Path:
    path = private_output(value)
    if path.exists():
        raise FileExistsError("Output already exists: " + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def copy_readonly(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    destination.chmod(stat.S_IREAD)


def run(args, *, cwd: Path | None = None, env=None) -> bytes:
    result = subprocess.run(
        [str(arg) for arg in args], cwd=cwd, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if result.returncode:
        raise RuntimeError("Command failed (%d): %s\n%s" % (
            result.returncode, " ".join(map(str, args)), result.stdout.decode("utf-8", "replace")
        ))
    return result.stdout


def vc_environment() -> dict[str, str]:
    program_files_x86 = os.environ.get("ProgramFiles(x86)")
    if not program_files_x86:
        raise RuntimeError("ProgramFiles(x86) is unavailable")
    vswhere = Path(program_files_x86) / "Microsoft Visual Studio/Installer/vswhere.exe"
    installation = Path(run([
        vswhere, "-latest", "-products", "*", "-property", "installationPath"
    ]).decode().strip())
    msvc = max(
        (installation / "VC/Tools/MSVC").iterdir(),
        key=lambda item: tuple(map(int, item.name.split("."))),
    )
    windows_kits = Path(program_files_x86) / "Windows Kits/10"
    sdk_version = max(
        (windows_kits / "Include").iterdir(),
        key=lambda item: tuple(map(int, item.name.split("."))),
    ).name
    environment = os.environ.copy()
    environment["PATH"] = str(msvc / "bin/Hostx64/x86") + os.pathsep + environment.get("PATH", "")
    environment["HUOCHAI_BENCHMARK_CL"] = str(msvc / "bin/Hostx64/x86/cl.exe")
    environment["INCLUDE"] = os.pathsep.join(map(str, [
        msvc / "include",
        *[windows_kits / "Include" / sdk_version / leaf for leaf in ("ucrt", "shared", "um", "winrt")],
    ]))
    environment["LIB"] = os.pathsep.join(map(str, [
        msvc / "lib/x86",
        windows_kits / "Lib" / sdk_version / "ucrt/x86",
        windows_kits / "Lib" / sdk_version / "um/x86",
    ]))
    # cl.exe invokes link.exe; LINK applies deterministic PE timestamps to every
    # benchmark fixture without depending on the caller's command-line layout.
    environment["LINK"] = (environment.get("LINK", "") + " /Brepro").strip()
    return environment


def staging_directory(output: Path):
    return tempfile.TemporaryDirectory(prefix=output.name + "-staging-", dir=output.parent)
