"""Private, hash-pinned integration inputs; no binary data is read from Git."""
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUTS = ROOT / '.local' / 'inputs'
SOURCES = {
    'single': ('火柴单文件版.exe', '452541a3327935ac452504ff0355bbea801090837f626f1a82c5245e3f89ef1a'),
    'green': ('火柴绿色版.exe', '0b32b5f393806f0c154b2b7f2ff2c93459848e85832c4584d7b3099d25e80e8b'),
}


def require_input(path, digest):
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError('Missing private input: ' + path.name + '. See docs/build.md; the standalone demo needs no legacy inputs.')
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise ValueError('Private input hash mismatch: ' + path.name)
    return path


def private_output(path):
    path = Path(path).resolve()
    if path.is_relative_to(ROOT) and not path.is_relative_to(ROOT / '.local'):
        raise ValueError('Build output inside this repository must be under .local/')
    return path
