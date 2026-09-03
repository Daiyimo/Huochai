"""Optional, isolated compatibility probe for an unmodified Everything engine.

No download, service installation, production database access or full-drive scan.
Supply the x86 test_engine_ipc.exe produced by a retained normal build.
"""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid


def probe(engine, query, parent):
    identity='HuoChatBetaProbe'+uuid.uuid4().hex
    root=parent/identity;root.mkdir()
    exe=root/'Everything.exe';shutil.copy2(engine,exe)
    fixture=root/'中文 fixture';fixture.mkdir()
    target='sample-archive-001.zip'
    (fixture/target).write_bytes(b'compatibility fixture, not an actual archive')
    (fixture/'中文 本地文件.txt').write_bytes(b'fixture')
    (fixture/'unrelated.txt').write_bytes(b'fixture')
    config=root/'Index.ini';cache=root/'Everything.db'
    config.write_text('[Everything]\nrun_as_admin=0\nshow_tray_icon=0\n'
        'show_in_taskbar=0\ncheck_for_updates_on_startup=0\nbeta_updates=0\n'
        'http_server_enabled=0\netp_server_enabled=0\n'
        'auto_include_fixed_volumes=0\nauto_include_removable_volumes=0\n'
        'auto_include_fixed_refs_volumes=0\nauto_include_removable_refs_volumes=0\n'
        'auto_include_fixed_fat_volumes=0\nauto_include_removable_fat_volumes=0\n'
        'scan_volume_drive_letters=0\nntfs_volume_guids=\nrefs_volume_guids=\n'
        'db_multi_user_filename=0\ndb_compress=0\n'
        'folders="'+str(fixture).replace('\\','\\\\')+'"\nfolder_monitor_changes=0\n',encoding='utf-8')
    command=[str(exe),'-instance',identity,'-config',str(config),'-db',str(cache),'-startup']
    flags=subprocess.CREATE_NO_WINDOW
    def until(predicate,seconds=20):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            if predicate():return
            time.sleep(.05)
        raise AssertionError('Beta probe condition timed out: '+identity)
    def count(text):
        result=subprocess.run([str(query),str(process.pid),text],capture_output=True,timeout=7)
        return int(result.stdout) if result.returncode==0 else -1
    def snapshot():
        try:return cache.read_bytes()
        except OSError:return b''
    user=ctypes.WinDLL('user32',use_last_error=True)
    callback_type=ctypes.WINFUNCTYPE(wintypes.BOOL,wintypes.HWND,wintypes.LPARAM)
    user.EnumWindows.argtypes=[callback_type,wintypes.LPARAM]
    user.GetWindowThreadProcessId.argtypes=[wintypes.HWND,ctypes.POINTER(wintypes.DWORD)]
    user.GetClassNameW.argtypes=[wintypes.HWND,wintypes.LPWSTR,ctypes.c_int]
    user.PostMessageW.argtypes=[wintypes.HWND,wintypes.UINT,wintypes.WPARAM,wintypes.LPARAM]
    def save():
        windows=[]
        @callback_type
        def locate(window,_):
            pid=wintypes.DWORD();name=ctypes.create_unicode_buffer(128)
            user.GetWindowThreadProcessId(window,ctypes.byref(pid))
            user.GetClassNameW(window,name,128)
            if pid.value==process.pid and name.value.startswith('EVERYTHING_TASKBAR_NOTIFICATION'):
                windows.append(window)
            return True
        user.EnumWindows(locate,0)
        assert len(windows)==1 and user.PostMessageW(windows[0],0x400,407,0)
    process=None
    try:
        start=time.monotonic();process=subprocess.Popen(command,cwd=root,creationflags=flags)
        until(lambda:count(target)==1)
        ready_ms=round((time.monotonic()-start)*1000)
        searches={target:1,'wholefilename:'+target:1,'sample 001':1,
            'ext:zip sample':1,'"中文 本地文件.txt"':1,'no-such-archive-unique':0}
        observed={text:count(text) for text in searches};assert observed==searches,observed
        save();until(lambda:bool(snapshot()) and not (root/'Everything.db.tmp').exists())
        first=snapshot()
        (fixture/target).rename(fixture/'renamed-sample.zip')
        subprocess.run([str(exe),'-instance',identity,'-rescan-all'],cwd=root,timeout=5,check=True,creationflags=flags)
        until(lambda:count(target)==0 and count('renamed-sample.zip')==1)
        save();until(lambda:snapshot() not in (b'',first) and not (root/'Everything.db.tmp').exists())
        saved=snapshot();process.terminate();process.wait(timeout=5);process=None
        (fixture/'renamed-sample.zip').unlink()
        process=subprocess.Popen(command+['-read-only'],cwd=root,creationflags=flags)
        until(lambda:count('renamed-sample.zip')==1)
        assert snapshot()==saved
        return {'engine':str(engine),'sha256':hashlib.sha256(engine.read_bytes()).hexdigest(),
            'fixture_dir':str(root),'pass':True,'fixture_ready_ms':ready_ms,'searches':observed,
            'checks':['x86 IPC v1 queries to isolated named instance','Chinese and space paths',
                'explicit folder rescan sees rename and removes old result',
                'public SAVE_DB creates and refreshes cache',
                'forced exit then read-only restart reloads saved results'],
            'scope':'Tiny folder fixture; no services, NTFS full-drive benchmark or real HuoChat UI.'}
    finally:
        if process and process.poll() is None:process.terminate();process.wait(timeout=5)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine',type=Path,action='append',required=True)
    parser.add_argument('--query',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    parent=Path(tempfile.mkdtemp(prefix='huochai_beta_probe_'))
    results=[probe(engine.resolve(),args.query.resolve(),parent) for engine in args.engine]
    args.output.write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(results,ensure_ascii=False,indent=2))
