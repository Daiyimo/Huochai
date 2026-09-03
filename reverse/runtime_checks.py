"""Exercise the actual NSIS/launcher against controlled local processes."""
import ctypes
from ctypes import wintypes
import hashlib
from pathlib import Path
import shutil
import subprocess
import time
import tempfile
import uuid
import winreg
import os


def verify_runtime(build, env, compiler, icon, package, run, source):
    parent=build
    build=Path(tempfile.mkdtemp(prefix='runtime_',dir=parent))
    identity='HuoChatOfflineTest'+uuid.uuid4().hex
    launcher_source=build/'runtime_launcher.c'
    launcher_source.write_text(
        '#define HUOCHAT_LAUNCHER_MUTEX L"Local\\\\'+identity+'LauncherV1"\n'+
        '#define HUOCHAT_READY_EVENT L"Local\\\\'+identity+'LauncherReadyV2"\n'+
        '#define HUOCHAT_STOP_EVENT L"Local\\\\'+identity+'LauncherStoppingV1"\n'+
        '#define HUOCHAT_STARTUP_KEY L"Software\\\\HuoChatRuntimeTests\\\\'+identity+'"\n'+
        '#include "launcher.c"\n',encoding='utf-8')
    run(['cl.exe','/nologo','/utf-8','/MT','/O1','/I'+str(source),launcher_source,
         '/link','kernel32.lib','advapi32.lib','user32.lib','/SUBSYSTEM:WINDOWS','/OUT:HuoChat_launcher.exe'],cwd=build,env=env)
    run(['cl.exe','/nologo','/utf-8','/MT','/O1',source/'test_portable.c',
         '/link','kernel32.lib','user32.lib','/OUT:test_portable.exe'],cwd=build,env=env)
    print(run([build/'test_portable.exe',build/'config-tests'],cwd=build).decode(),flush=True)
    fixture_source=build/'runtime_fixture_wrapper.c'
    fixture_source.write_text('#define HUOCHAT_STOP_EVENT L"Local\\\\'+identity+'LauncherStoppingV1"\n'+
        '#include "runtime_fixture.c"\n',encoding='utf-8')
    run(['cl.exe','/nologo','/utf-8','/MT','/O1','/I'+str(source),fixture_source,
         '/link','kernel32.lib','/SUBSYSTEM:WINDOWS','/OUT:runtime_fixture.exe'],cwd=build,env=env)
    run(['cl.exe','/nologo','/utf-8','/MT','/O1',source/'test_environment.c',
         '/link','kernel32.lib','shell32.lib','/OUT:test_environment.exe'],cwd=build,env=env)
    folder=build/'runtime-seed'; folder.mkdir()
    for name in ('HuoChat.exe','hc_engine.exe'): shutil.copy2(build/'runtime_fixture.exe',folder/name)
    shutil.copy2(build/'HuoChat_launcher.exe',folder/'HuoChat_launcher.exe')
    shutil.copy2(build/'test_environment.exe',folder/'test_environment.exe')
    shutil.copy2(parent/'hcg.dll',folder/'hcg.dll')
    (folder/'library.bin').write_bytes(b'known immutable payload')
    (folder/'Data').mkdir()
    (folder/'Data'/'Index.ini').write_text('[Everything]\nexclude_folders=\n',encoding='utf-8')
    (folder/'Data'/'Sites.db').write_bytes(b'initial seed')
    (folder/'Data'/'default-resource').write_bytes(b'initial resource')
    archive=package(folder,build,'test',compiler,icon,identity=identity)
    location=build/'runtime space'; location.mkdir()
    exe=location/'portable.exe'; shutil.copy2(archive,exe)
    payload=location/'HuoChatOffline-v1-test'
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.OpenMutexW.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.LPCWSTR]
    kernel.OpenMutexW.restype=wintypes.HANDLE
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    kernel.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
    kernel.CreateFileW.restype=wintypes.HANDLE

    def until(predicate,seconds=15):
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            if predicate(): return
            time.sleep(.05)
        raise AssertionError('Timed out waiting for runtime condition')
    def launcher_running():
        handle=kernel.OpenMutexW(0x100000,False,'Local\\'+identity+'LauncherV1')
        if handle: kernel.CloseHandle(handle)
        return bool(handle)
    if launcher_running(): raise RuntimeError('Close the running HuoChat before the isolated runtime checks')
    results={}
    # A distinct caller profile makes accidental reassignment to Data/Apps
    # observable without writing test caches into the user's real profile.
    system_profile=build/'caller profile';system_profile.mkdir()
    launch_env=os.environ.copy()
    for name in ('APPDATA','LOCALAPPDATA','TEMP','TMP'):
        directory=system_profile/name;directory.mkdir();launch_env[name]=str(directory)
    expected_profile=[launch_env[name] for name in ('APPDATA','LOCALAPPDATA','TEMP','TMP')]
    def invoke(expected=0, args=(), quiet=True):
        start=time.perf_counter()
        result=subprocess.run([str(exe),*(['/S'] if quiet else []),*args],cwd=location,env=launch_env,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode==expected, (result.returncode,expected,(payload/'package-error.log').read_bytes() if (payload/'package-error.log').exists() else '')
        return round((time.perf_counter()-start)*1000)
    def ready():
        until(lambda:(payload/'ui.ready').exists() and (payload/'engine.ready').exists())
        until(lambda:'停止周期性进程扫描' in (payload/'Data'/'offline.log').read_text(encoding='utf-8'))
        assert (payload/'env-harness.exit').read_text()=='0'
        for i in range(7):
            assert (payload/f'env-child-{i}.txt').read_text(encoding='utf-8').splitlines()==expected_profile
    def stop():
        cache=payload/'Data'/'Index'/'Everything.db'
        previous=cache.read_bytes() if cache.exists() else None
        (payload/'test-stop').write_bytes(b'1')
        until(lambda:not launcher_running(),6)
        assert (cache.read_bytes() if cache.exists() else None)==previous
        for name in ('test-stop','ui.ready','engine.ready'): (payload/name).unlink(missing_ok=True)
    def snapshot():
        return {p.name:(p.stat().st_mtime_ns,hashlib.sha256(p.read_bytes()).hexdigest())
                for p in payload.iterdir() if p.suffix in ('.exe','.bin')}
    try:
        # An existing file at the intended data-directory path must be preserved.
        payload.write_bytes(b'not a directory')
        invoke(20); assert payload.read_bytes()==b'not a directory'; payload.unlink()
        (payload/'user data'/'note_backup').mkdir(parents=True)
        (payload/'user data'/'note').write_bytes(b'legacy note')
        (payload/'user data'/'note_backup'/'20260901').write_bytes(b'legacy backup')
        (payload/'Everything.ini').write_text('[Everything]\nexclude_folders=C:\\Legacy\n',encoding='utf-8')
        key=winreg.CreateKey(winreg.HKEY_CURRENT_USER,'Software\\HuoChatRuntimeTests\\'+identity)
        winreg.SetValueEx(key,'HuoChat',0,winreg.REG_SZ,str(payload/'HuoChat.exe')+' -s')
        results['cold_wrapper_ms']=invoke(quiet=False); ready()
        assert not (payload/'user data').exists() and not (payload/'Everything.ini').exists()
        assert (payload/'Data'/'User'/'note').read_bytes()==b'legacy note'
        assert (payload/'Data'/'User'/'note_backup'/'20260901').read_bytes()==b'legacy backup'
        assert 'exclude_folders=C:\\Legacy' in (payload/'Data'/'Index.ini').read_text(encoding='utf-8')
        assert winreg.QueryValueEx(key,'HuoChat')[0]=='"'+str(exe)+'" -s'
        for leaf,expected in zip(('env-appdata','env-localappdata','env-temp','env-tmp'),expected_profile):
            assert (payload/leaf).read_text(encoding='utf-8')==expected
        original=snapshot(); assert invoke(10)>=0; assert snapshot()==original
        old_pid=(payload/'engine.ready').read_text()
        (payload/'test-restart').write_bytes(b'1')
        until(lambda:(payload/'engine.ready').read_text()!=old_pid)
        until(lambda:(payload/'Data'/'offline.log').read_text(encoding='utf-8').count('停止周期性进程扫描')>=2)
        stop()
        ini=payload/'Data'/'Index.ini'
        ini.write_text(ini.read_text(encoding='utf-8').replace('exclude_folders=C:\\Legacy','exclude_folders=C:\\Keep'),encoding='utf-8')
        (payload/'Data'/'Sites.db').write_bytes(b'user database')
        (payload/'Data'/'User'/'note').write_text('user note',encoding='utf-8')
        results['warm_wrapper_ms']=invoke(args=('-s',),quiet=False); ready(); assert (payload/'ui.args').read_text()=='-s'; assert snapshot()==original; stop()
        assert 'exclude_folders=C:\\Keep' in ini.read_text(encoding='utf-8')
        assert (payload/'Data'/'Sites.db').read_bytes()==b'user database'
        (payload/'test-delay-ms').write_text('16000')
        invoke(); ready();begin=time.monotonic();stop()
        assert time.monotonic()-begin<5
        assert '取消本次索引工作' in (payload/'Data'/'offline.log').read_text(encoding='utf-8')
        (payload/'test-delay-ms').unlink()
        assert (payload/'Data'/'User'/'note').read_text()=='user note'
        (payload/'library.bin').write_bytes(b'x'*len(b'known immutable payload'))
        invoke(); ready(); assert (payload/'library.bin').read_bytes()==b'known immutable payload'; stop()
        (payload/'library.bin').unlink(); (payload/'Data'/'default-resource').unlink()
        invoke(); ready(); stop()
        assert (payload/'Data'/'default-resource').read_bytes()==b'initial resource'
        assert (payload/'Data'/'User'/'note').read_text()=='user note'
        assert (payload/'Data'/'Sites.db').read_bytes()==b'user database'
        # Upgrade keeps all data, even when a stale package marker forces repair.
        (payload/'.package.ini').write_text('[Package]\nid=old-build\n')
        invoke(); ready(); stop(); assert (payload/'Data'/'Sites.db').read_bytes()==b'user database'
        # A same-size corruption locked against writes must abort before launch.
        (payload/'library.bin').write_bytes(b'y'*len(b'known immutable payload'))
        lock=kernel.CreateFileW(str(payload/'library.bin'),0x80000000,1,None,3,0,None)
        assert lock not in (None,ctypes.c_void_p(-1).value)
        try:
            invoke(20); assert not launcher_running(); assert not (payload/'ui.ready').exists()
        finally: kernel.CloseHandle(lock)
        invoke(); ready(); stop()
        moved=build/'runtime moved 中文'; location.rename(moved)
        location=moved; exe=location/'portable.exe'; payload=location/'HuoChatOffline-v1-test'
        invoke(); ready(); stop()
        assert winreg.QueryValueEx(key,'HuoChat')[0]=='"'+str(exe)+'" -s'
        assert 'db_location='+str(payload/'Data'/'Index') in (payload/'Data'/'Index.ini').read_text(encoding='utf-8')
        assert (payload/'Data'/'Sites.db').read_bytes()==b'user database'
        results['checks']=['unwritable data path','first launch','warm cache','duplicate launch before extraction','engine restart',
            'cancel index without changing completed cache','configuration and user data retention','same-size corruption repair',
            'missing files and seeds','upgrade retention','locked repair fails closed','Unicode directory migration',
            'cancel slow indexing without waiting 15 seconds']
        results['checks']+=['default NSIS silent mode on cold/warm launch without /S',
                            'seven real child launch routes preserve the caller profile and temporary directories',
                            'silent startup argument passed to UI','startup path repaired after move',
                            'legacy migration precedes NSIS default seeding']
        results['pass']=True
        print('Runtime package checks passed: '+', '.join(results['checks']),flush=True)
        return results
    finally:
        if 'key' in locals():
            winreg.CloseKey(key);winreg.DeleteKey(winreg.HKEY_CURRENT_USER,'Software\\HuoChatRuntimeTests\\'+identity)
        if payload.exists() and launcher_running():
            (payload/'test-stop').write_bytes(b'1')
            until(lambda:not launcher_running(),70)
