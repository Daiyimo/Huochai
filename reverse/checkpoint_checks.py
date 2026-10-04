"""Real engine + production launcher: cache creation, refresh and cancelled save."""
import ctypes
from ctypes import wintypes
from pathlib import Path
import shutil
import subprocess
import time
import uuid

from build import isolated_definition_source


def verify_checkpoints(folder, build, env, run, source):
    root=build/'checkpoint 中文';root.mkdir(exist_ok=True)
    identity='HuoChatCheckpoint'+uuid.uuid4().hex
    definitions=isolated_definition_source(identity,'HuoChatCheckpointTests',False)
    wrapper=root/'launcher_test.c'
    wrapper.write_text(definitions+'#define HC_CHECKPOINT_INTERVAL_MS 1000\n'
                       '#define HC_CHECKPOINT_RETRY_MS 1000\n'
                       '#define HC_CHECKPOINT_SAVE_WAIT_MS 2000\n#include "launcher.c"\n',encoding='utf-8')
    run(['cl.exe','/nologo','/utf-8','/MT','/O1','/I'+str(source),wrapper,
         '/link','kernel32.lib','user32.lib','advapi32.lib','/SUBSYSTEM:WINDOWS','/OUT:HuoChat_launcher.exe'],cwd=root,env=env)
    ui=root/'ui_test.c';ui.write_text(definitions+'#include "test_checkpoint_ui.c"\n',encoding='utf-8')
    run(['cl.exe','/nologo','/utf-8','/MT','/O1','/I'+str(source),ui,
         '/link','kernel32.lib','/SUBSYSTEM:WINDOWS','/OUT:HuoChat.exe'],cwd=root,env=env)
    query=build/'test_engine_ipc.exe'
    run(['cl.exe','/nologo','/utf-8','/MT','/O1',source/'test_engine_ipc.c',
         '/link','kernel32.lib','user32.lib','/OUT:'+str(query)],cwd=build,env=env)
    for name in ('hc_engine.exe','hcg.dll','hcn.dll'):shutil.copy2(folder/name,root/name)
    (root/'Data/Index').mkdir(parents=True)
    fixture=root/'fixture';fixture.mkdir();(fixture/'checkpoint-initial.txt').write_bytes(b'fixture')
    config=('[Everything]\nrun_as_admin=0\nshow_tray_icon=0\nshow_in_taskbar=0\n'
            'auto_include_fixed_volumes=0\nauto_include_removable_volumes=0\n'
            'auto_include_fixed_refs_volumes=0\nauto_include_removable_refs_volumes=0\n'
            'scan_volume_drive_letters=0\nntfs_volume_guids=\nrefs_volume_guids=\n'
            'db_multi_user_filename=0\ndb_compress=0\n'
            'folders="'+str(fixture).replace('\\','\\\\')+'"\nfolder_monitor_changes=0\n')
    (root/'Data/Index.ini').write_text(config,encoding='utf-8')
    cache=root/'Data/Index/Everything.db'
    environment=env.copy();environment['HUOCHAT_TEST_INSTANCE']=identity
    def until(predicate,seconds=12):
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            if predicate():return
            time.sleep(.05)
        raise AssertionError('Checkpoint condition timed out')
    def count(pid,text):
        p=subprocess.run([str(query),str(pid),text],capture_output=True,timeout=7)
        return int(p.stdout) if p.returncode==0 else -1
    def cache_bytes():
        try:return cache.read_bytes()
        except OSError:return b''
    def start():
        (root/'test-stop').unlink(missing_ok=True);(root/'engine.pid').unlink(missing_ok=True)
        p=subprocess.Popen([str(root/'HuoChat_launcher.exe')],cwd=root,env=environment,creationflags=subprocess.CREATE_NO_WINDOW)
        until(lambda:(root/'engine.pid').exists() and (root/'engine.pid').stat().st_size>0)
        pid=int((root/'engine.pid').read_text());until(lambda:count(pid,'checkpoint-initial.txt')==1)
        return p,pid
    def stop(p):
        begin=time.monotonic();(root/'test-stop').write_bytes(b'1')
        assert p.wait(timeout=6)==0
        return round((time.monotonic()-begin)*1000)
    process=None;locked=None;foreign=None
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
    kernel.CreateFileW.restype=wintypes.HANDLE;kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    try:
        process,pid=start();until(lambda:bool(cache_bytes()))
        until(lambda:'搜索索引缓存已保存' in (root/'Data/offline.log').read_text(encoding='utf-8'))
        first=cache_bytes();assert not (root/'Everything.db').exists()
        exit_ms=stop(process);process=None;assert cache_bytes()==first
        process,pid=start();until(lambda:bool(cache_bytes()))
        # Hold the canonical cache against replacement while a changed index saves.
        locked=kernel.CreateFileW(str(cache),0x80000000,1,None,3,0,None)
        assert locked not in (None,ctypes.c_void_p(-1).value)
        baseline=cache_bytes();(fixture/'checkpoint-added.txt').write_bytes(b'new')
        # Explicitly rescan the tiny folder: this test isolates checkpointing
        # from NTFS services and platform-specific folder watcher scheduling.
        subprocess.run([str(root/'hc_engine.exe'),'-instance',identity,'-rescan-all'],cwd=root,check=True,timeout=5,creationflags=subprocess.CREATE_NO_WINDOW)
        until(lambda:count(pid,'checkpoint-added.txt')==1)
        time.sleep(3);assert cache_bytes()==baseline
        exit_ms=max(exit_ms,stop(process));process=None
        assert cache_bytes()==baseline
        kernel.CloseHandle(locked);locked=None
        process,pid=start();until(lambda:count(pid,'checkpoint-added.txt')==1)
        until(lambda:cache_bytes() not in (b'',baseline));saved=cache_bytes()
        exit_ms=max(exit_ms,stop(process));process=None;assert cache_bytes()==saved
        # Read-only engine must recover results from the saved DB, even after the file is gone.
        (fixture/'checkpoint-added.txt').unlink()
        process=subprocess.Popen([str(root/'hc_engine.exe'),'-instance',identity,'-read-only'],cwd=root,creationflags=subprocess.CREATE_NO_WINDOW)
        until(lambda:count(process.pid,'checkpoint-added.txt')==1)
        process.terminate();process.wait(timeout=3);process=None
        # Simulate an engine stuck for 16 seconds inside SAVE_DB. Also keep a
        # foreign IPC window alive, so the launcher must route by owned PID.
        run(['cl.exe','/nologo','/utf-8','/MT','/O1',source/'test_checkpoint_engine.c',
             '/link','kernel32.lib','user32.lib','/SUBSYSTEM:WINDOWS','/OUT:'+str(root/'hc_engine.exe')],cwd=build,env=env)
        foreign_dir=build/'checkpoint foreign';foreign_dir.mkdir()
        shutil.copy2(root/'hc_engine.exe',foreign_dir/'hc_engine.exe')
        foreign=subprocess.Popen([str(foreign_dir/'hc_engine.exe')],cwd=foreign_dir,creationflags=subprocess.CREATE_NO_WINDOW)
        (root/'test-stop').unlink(missing_ok=True)
        process=subprocess.Popen([str(root/'HuoChat_launcher.exe')],cwd=root,env=environment,creationflags=subprocess.CREATE_NO_WINDOW)
        until(lambda:(root/'save-requested').exists())
        exit_ms=max(exit_ms,stop(process));process=None
        assert cache_bytes()==saved and foreign.poll() is None
        assert not (foreign_dir/'save-requested').exists(),'Checkpoint reached a foreign engine'
        return {'pass':True,'max_exit_ms':exit_ms,'checks':[
            'first ready index saved while UI remains running',
            'production exit retains saved cache',
            'locked replacement preserves last completed cache and fast exit',
            'restart retries and saves changed index',
            'read-only fresh process reloads actual saved search results',
            '16-second SAVE_DB handler does not block cancellation',
            'foreign engine IPC receives no save and remains running']}
    finally:
        if foreign and foreign.poll() is None:foreign.terminate();foreign.wait(timeout=3)
        if locked:kernel.CloseHandle(locked)
        if process and process.poll() is None:
            (root/'test-stop').write_bytes(b'1')
            try:process.wait(timeout=6)
            except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=3)
