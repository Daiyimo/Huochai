"""Exercise actual renames on the observed legacy layout, including note backups."""
import ctypes
from ctypes import wintypes
from pathlib import Path
import subprocess
import tempfile


def verify_migration(build, env, run, source):
    run(['cl.exe','/nologo','/utf-8','/MT','/O1',source/'test_migration.c',
         '/link','kernel32.lib','user32.lib','/OUT:test_migration.exe'],cwd=build,env=env)
    root=Path(tempfile.mkdtemp(prefix='migration-tests-',dir=build))
    data={
        'user data/config':b'user configuration', 'user data/history':b'user history',
        'user data/note':'我的便签'.encode(), 'user data/note_backup/20260901':b'older note',
        'user data/backup/20260901':b'older config', 'user data/tam/config':b'local preference',
        'user data/Temp/apps.txt':b'cached apps', 'Everything.ini':b'[Everything]\nfolders=G:\\\n',
        'HuoChatIndex/Everything.db':b'persistent index', 'HuoChat/site.db':b'old seed',
        'Tencent/WeGame/test':b'wegame state', 'claude-cli-nodejs/test':b'cli state',
        'Temp/cache':b'old temporary data', 'unknown-user-folder/keep':b'do not guess',
    }
    def populate(directory):
        for relative,content in data.items():
            target=directory/relative; target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(content)
    def invoke(directory,expected=0):
        result=subprocess.run([str(build/'test_migration.exe'),str(directory)],capture_output=True,timeout=20)
        assert result.returncode==expected,(result.returncode,result.stdout)
    first=root/'成功 中文';populate(first);invoke(first)
    mapping={'user data':'Data/User','Everything.ini':'Data/Index.ini','HuoChatIndex':'Data/Index',
             'HuoChat':'Data/HuoChat','Temp':'Data/Temp','Tencent':'Data/Apps/Tencent',
             'claude-cli-nodejs':'Data/Apps/claude-cli-nodejs'}
    for relative,content in data.items():
        head,slash,tail=relative.partition('/')
        target=first/(mapping.get(head,head)+(slash+tail if slash else ''))
        assert target.read_bytes()==content,target
        if head in mapping: assert not (first/relative).exists()
    invoke(first)
    conflict=root/'conflict';populate(conflict)
    (conflict/'Data'/'User').mkdir(parents=True);(conflict/'Data'/'User'/'note').write_bytes(b'new note')
    invoke(conflict,21)
    for relative,content in data.items(): assert (conflict/relative).read_bytes()==content
    assert (conflict/'Data'/'User'/'note').read_bytes()==b'new note'
    locked=root/'locked';populate(locked)
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
    kernel.CreateFileW.restype=wintypes.HANDLE;kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    handle=kernel.CreateFileW(str(locked/'Tencent/WeGame/test'),0x40000000,7,None,3,0,None)
    assert handle not in (None,ctypes.c_void_p(-1).value)
    try:
        invoke(locked,21)
        for relative,content in data.items(): assert (locked/relative).read_bytes()==content
    finally: kernel.CloseHandle(handle)
    invoke(locked)
    # An existing target that is a file is also a conflict, never replaced.
    collision=root/'file-collision';populate(collision);(collision/'Data').mkdir();(collision/'Data'/'User').write_bytes(b'file')
    invoke(collision,21);assert (collision/'user data'/'note').read_bytes()==data['user data/note']
    linked=root/'reparse';populate(linked);outside=root/'outside.txt';outside.write_bytes(b'outside data')
    link=linked/'user data'/'linked-file'
    kernel.CreateSymbolicLinkW.argtypes=[wintypes.LPCWSTR,wintypes.LPCWSTR,wintypes.DWORD]
    kernel.CreateSymbolicLinkW.restype=wintypes.BOOLEAN
    symlink=bool(kernel.CreateSymbolicLinkW(str(link),str(outside),2))
    if symlink:
        try:
            invoke(linked,21);assert outside.read_bytes()==b'outside data'
            assert (linked/'user data'/'note').read_bytes()==data['user data/note']
        finally: link.unlink()  # only the created link, never its target
    regenerated=root/'regenerated';regenerated.mkdir()
    (regenerated/'Data'/'Index').mkdir(parents=True)
    (regenerated/'Data'/'layout.ini').write_text('[Layout]\nroot='+str(regenerated)+'\\\n')
    (regenerated/'Data'/'Index.ini').write_bytes(b'[Everything]\nshow_tray_icon=0\n')
    (regenerated/'Data'/'Index'/'Everything.db').write_bytes(b'preserved old index')
    (regenerated/'Everything.ini').write_bytes(b'[Everything]\nshow_tray_icon=1\n')
    (regenerated/'Everything.db').write_bytes(b'regenerated index')
    invoke(regenerated)
    assert (regenerated/'Data'/'Index.ini').read_bytes()==b'[Everything]\nshow_tray_icon=0\n'
    assert (regenerated/'Data'/'Index'/'Everything.db').read_bytes()==b'preserved old index'
    assert not (regenerated/'Everything.ini').exists() and not (regenerated/'Everything.db').exists()
    archived=list((regenerated/'Data'/'Recovery').rglob('Everything.ini'));assert len(archived)==1
    assert archived[0].read_bytes()==b'[Everything]\nshow_tray_icon=1\n'
    assert (archived[0].parent/'Everything.db').read_bytes()==b'regenerated index'
    invoke(regenerated)
    # With no canonical cache, reuse the sole existing index instead of forcing
    # a full rebuild. The conflicting default configuration is still archived.
    (regenerated/'Data'/'Index'/'Everything.db').unlink()
    (regenerated/'Everything.ini').write_bytes(b'[Everything]\nshow_tray_icon=1\n')
    (regenerated/'Everything.db').write_bytes(b'sole reusable index')
    invoke(regenerated)
    assert (regenerated/'Data'/'Index'/'Everything.db').read_bytes()==b'sole reusable index'
    assert (regenerated/'Data'/'Index.ini').read_bytes()==b'[Everything]\nshow_tray_icon=0\n'
    empty=root/'empty-app-directory';empty.mkdir()
    (empty/'Microsoft'/'Windows'/'Caches').mkdir(parents=True)
    (empty/'Data'/'Apps'/'Microsoft'/'Windows'/'Caches').mkdir(parents=True)
    invoke(empty)
    assert not (empty/'Microsoft').exists()
    assert (empty/'Data'/'Apps'/'Microsoft'/'Windows'/'Caches').is_dir()
    (empty/'Microsoft').mkdir();(empty/'Microsoft'/'keep.txt').write_bytes(b'preserve actual content')
    invoke(empty,21)
    assert (empty/'Microsoft'/'keep.txt').read_bytes()==b'preserve actual content'
    return ['legacy config/history/notes/backups/index/profile migration','migration idempotence',
            'regenerated engine files archived without replacing canonical config/cache',
            'sole root index reused when canonical index is absent',
            'empty duplicate app directory pruned, actual contents retained',
            'conflicting data retained','active third-party writer blocks all moves','unknown folder retained',
            'reparse traversal refused' if symlink else 'reparse test unavailable: symbolic-link privilege']
