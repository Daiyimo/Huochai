"""Regress the real engine's implicit launch, shutdown, and repeated start.

Each instance has its own name, no service, and only a tiny fixture folder to
index. It never uses the user's running Everything instance or disk indexes.
"""
from pathlib import Path
import shutil
import subprocess
import time
import uuid


def verify_engine(folder, build, env, run, source):
    seam=build/'engine-entry';seam.mkdir()
    shutil.copy2(build/'hcg.dll',seam/'hcg.dll')
    run(['cl.exe','/nologo','/utf-8','/MT','/O1',source/'test_engine_entry.c',
         '/link','kernel32.lib','/OUT:hc_engine.exe'],cwd=seam,env=env)
    checks=[]
    print(run([seam/'hc_engine.exe'],cwd=seam).decode(),flush=True)
    for flag in ('-exit','-svc','-install-service','-uninstall-service'):
        run([seam/'hc_engine.exe','expect-unchanged',flag],cwd=seam)
    shutil.copy2(seam/'hc_engine.exe',seam/'HuoChat.exe')
    run([seam/'HuoChat.exe','expect-unchanged'],cwd=seam)
    checks.extend(['A/W config/cache paths injected on engine entry',
                   'dynamic engine tray calls suppressed',
                   'main application and engine control commands unchanged'])
    root=build/'real engine 中文';root.mkdir()
    for name in ('hc_engine.exe','hcg.dll','hcn.dll'):
        shutil.copy2(folder/name,root/name)
    data=root/'Data';(data/'Index').mkdir(parents=True)
    fixture=root/'fixture';fixture.mkdir();(fixture/'engine-regression.txt').write_bytes(b'fixture')
    config=data/'Index.ini'
    config.write_text('[Everything]\nrun_as_admin=0\nshow_tray_icon=0\nshow_in_taskbar=0\n'
        'check_for_updates_on_startup=0\nbeta_updates=0\nhttp_server_enabled=0\netp_server_enabled=0\n'
        'auto_include_fixed_volumes=0\nauto_include_removable_volumes=0\n'
        'auto_include_fixed_refs_volumes=0\nauto_include_removable_refs_volumes=0\n'
        'scan_volume_drive_letters=0\nntfs_volume_guids=\nrefs_volume_guids=\n'
        'db_multi_user_filename=0\ndb_compress=0\n'
        'folders="'+str(fixture).replace('\\','\\\\')+'"\nfolder_monitor_changes=0\n',encoding='utf-8')
    instance='HuoChatRegression'+uuid.uuid4().hex
    command=[str(root/'hc_engine.exe'),'-instance',instance]
    for cycle in range(2):
        process=subprocess.Popen(command,cwd=root,creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            time.sleep(2)
            assert process.poll() is None,('engine exited before shutdown',process.returncode)
            subprocess.run([*command,'-exit'],cwd=root,timeout=10,check=True,
                           creationflags=subprocess.CREATE_NO_WINDOW)
            assert process.wait(timeout=15)==0
        finally:
            if process.poll() is None:
                process.terminate();process.wait(timeout=5)
        assert not (root/'Everything.ini').exists(), 'engine regenerated a root config'
        assert not (root/'Everything.db').exists(), 'engine regenerated a root cache'
        assert (data/'Index'/'Everything.db').stat().st_size>0
        # The real engine must have read and rewritten this non-default config.
        content=config.read_text(encoding='utf-8-sig')
        assert 'show_tray_icon=0' in content and 'auto_include_fixed_volumes=0' in content
        assert str(fixture).replace('\\','\\\\') in content or str(fixture) in content
    checks.append('two real engine startup/shutdown cycles keep config/cache under Data')
    run(['cl.exe','/nologo','/utf-8','/MT','/O1',source/'test_cancel_engine.c',
         '/link','kernel32.lib','user32.lib','advapi32.lib','/OUT:test_cancel_engine.exe'],cwd=build,env=env)
    cache=data/'Index'/'Everything.db';previous=cache.read_bytes()
    for fresh in (False,True):
        if fresh:cache.unlink()
        process=subprocess.Popen(command,cwd=root,creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            time.sleep(.3);assert process.poll() is None
            print(run([build/'test_cancel_engine.exe',root],cwd=root,timeout=5).decode(),flush=True)
            process.wait(timeout=2)
            assert (not cache.exists()) if fresh else cache.read_bytes()==previous
        finally:
            if process.poll() is None:process.terminate();process.wait(timeout=5)
    # A cancelled first build can initialise normally next time.
    process=subprocess.Popen(command,cwd=root,creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        time.sleep(2)
        subprocess.run([*command,'-exit'],cwd=root,timeout=10,check=True,creationflags=subprocess.CREATE_NO_WINDOW)
        assert process.wait(timeout=15)==0 and cache.stat().st_size>0
    finally:
        if process.poll() is None:process.terminate();process.wait(timeout=5)
    checks.extend(['production cancellation stops real engine promptly with/without a cache',
                   'completed cache unchanged on cancellation; interrupted first build restarts'])
    print('Real engine regression passed: startup, cancellation and restart.',flush=True)
    return checks
