"""Preserve known upstream notices byte-for-byte, including their URLs."""
from pathlib import Path
import shutil

NOTICE_DIR = Path(__file__).resolve().parent.parent / 'third_party' / 'licenses'
NOTICES = {
    'duilib license.txt': 'DuiLib-LICENSE.txt',
    'everything license.txt': 'Everything-legacy-LICENSE.txt',
    'Everything-1.5-LICENSE.txt': 'Everything-LICENSE.txt',
    'Everything-SDK-LICENSE.txt': 'Everything-SDK-LICENSE.txt',
}


def copy_notices(folder):
    for name, source in NOTICES.items():
        shutil.copy2(NOTICE_DIR / source, folder / name)


def preserved_notice(path, folder):
    relative = path.relative_to(folder).as_posix()
    if relative not in NOTICES:
        return False
    if path.read_bytes() != (NOTICE_DIR / NOTICES[relative]).read_bytes():
        raise ValueError('Third-party notice changed: ' + relative)
    return True
