"""Fast tray-exit/reopen through the real package and launcher, isolated PIDs."""
import json
import shutil
import subprocess
import time
import uuid
import psutil
from pathlib import Path


def read_pid(path):
    try:
        return int(path.read_text())
    except (FileNotFoundError, ValueError):
        # The fixture atomically changes process ownership, but Windows readers
        # can observe the truncate/write window. Treat that as "not ready" so
        # the bounded polling loop retries instead of reporting a false failure.
        return None


def executable_in_root(executable, root):
    if not executable:
        return False
    try:
        # Process APIs may return an 8.3 path even when the fixture was created
        # through its long path. resolve() expands that alias before containment.
        return Path(executable).resolve().is_relative_to(Path(root).resolve())
    except OSError:
        return False


def verify_shutdown(parent,env,compiler,icon,package,run,source):
    root=parent/('shutdown-'+uuid.uuid4().hex);root.mkdir()
    identity='HuoChatCancelTest'+uuid.uuid4().hex
    definitions=('#define HUOCHAT_LAUNCHER_MUTEX L"Local\\\\'+identity+'LauncherV1"\n'
        '#define HUOCHAT_READY_EVENT L"Local\\\\'+identity+'LauncherReadyV2"\n'
        '#define HUOCHAT_STOP_EVENT L"Local\\\\'+identity+'LauncherStoppingV1"\n'
        '#define HUOCHAT_STARTUP_KEY L"Software\\\\HuoChatRuntimeTests\\\\'+identity+'"\n')
    seed=root/'seed';seed.mkdir()
    for filename,include in [('HuoChat_launcher.exe','launcher.c'),('HuoChat.exe','runtime_fixture.c')]:
        wrapper=root/(filename+'.c');wrapper.write_text(definitions+'#include "'+include+'"\n',encoding='utf-8')
        run(['cl.exe','/nologo','/utf-8','/MT','/O1','/I'+str(source),wrapper,'/link','kernel32.lib',
             'advapi32.lib','user32.lib','/SUBSYSTEM:WINDOWS','/OUT:'+str(seed/filename)],cwd=root,env=env)
    shutil.copy2(seed/'HuoChat.exe',seed/'hc_engine.exe')
    (seed/'Data').mkdir();(seed/'Data/Index.ini').write_text('[Everything]\n',encoding='utf-8')
    archive=package(seed,root,'cancel',compiler,icon,identity=identity)
    location=root/'中文 fast restart';location.mkdir();exe=location/'portable.exe';shutil.copy2(archive,exe)
    payload=location/'HuoChatOffline-v1-cancel'
    def until(condition,seconds=8):
        start=time.monotonic()
        while time.monotonic()-start<seconds:
            if condition():return
            time.sleep(.02)
        raise AssertionError('Timed out waiting for shutdown/reopen')
    def pid(name):return read_pid(payload/name)
    def alive(pid):
        if pid is None:return False
        try:return psutil.Process(pid).is_running()
        except psutil.NoSuchProcess:return False
    def invoke(expected=0):
        p=subprocess.run([str(exe),'/S'],cwd=location,timeout=12,creationflags=subprocess.CREATE_NO_WINDOW)
        assert p.returncode==expected,('rapid reopen return code',p.returncode,expected)
    def ready():until(lambda:pid('ui.ready') is not None and pid('engine.ready') is not None)
    def restarted(first_ui,first_engine):
        current_ui=pid('ui.ready');current_engine=pid('engine.ready')
        return (current_ui is not None and current_engine is not None and
                current_ui!=first_ui and current_engine!=first_engine)
    foreign=None
    try:
        invoke();ready()
        invoke(10) # A genuine duplicate still refuses extraction/start.
        cache=payload/'Data/Index/Everything.db';cache.write_bytes(b'previous completed index')
        (payload/'Data/User/config').write_bytes(b'previous user settings')
        (payload/'test-delay-ms').write_text('16000')
        (payload/'test-late-engine').write_bytes(b'1')
        # This same-named engine belongs to a different directory and must survive.
        foreign_dir=root/'separate program';foreign_dir.mkdir()
        shutil.copy2(seed/'hc_engine.exe',foreign_dir/'hc_engine.exe')
        foreign=subprocess.Popen([str(foreign_dir/'hc_engine.exe')],cwd=foreign_dir,creationflags=subprocess.CREATE_NO_WINDOW)
        first_ui=pid('ui.ready');first_engine=pid('engine.ready')
        begin=time.monotonic();(payload/'test-stop').write_bytes(b'1')
        until(lambda:(payload/'ui.stopping').exists())
        invoke() # During UI teardown: wait briefly, then relaunch without code 10.
        until(lambda:restarted(first_ui,first_engine))
        elapsed=time.monotonic()-begin
        assert elapsed<6,('slow exit/restart',elapsed)
        assert not alive(first_ui) and not alive(first_engine),'Old processes survived reopen'
        assert not alive(pid('late-engine.pid')),'Engine launched during teardown survived'
        (payload/'test-late-engine').unlink()
        assert foreign.poll() is None,'Touched another program directory'
        assert cache.read_bytes()==b'previous completed index'
        assert (payload/'Data/User/config').read_bytes()==b'previous user settings'
        # Fresh/no-cache indexing may be cancelled too; next launch recreates it.
        cache.unlink();second_engine=pid('engine.ready');second_ui=pid('ui.ready')
        (payload/'test-stop').write_bytes(b'1')
        until(lambda:not alive(second_ui) and not alive(second_engine),5)
        assert not cache.exists(),'Cancelled indexing wrote an incomplete cache'
        time.sleep(.1);invoke();until(lambda:(pid('ui.ready') is not None and pid('ui.ready')!=second_ui))
        assert not cache.exists()
        result={'pass':True,'rapid_reopen_ms':round(elapsed*1000),'checks':[
            'UI exit cancels a 16-second index flush',
            'rapid reopen waits for teardown and launches successfully',
            'old UI/engine PIDs gone before new launch',
            'engine launched during UI teardown is also removed',
            'completed cache and user settings preserved',
            'no-cache first indexing can be cancelled and restarted',
            'same-named engine in another directory is untouched',
            'genuine duplicate launch still returns 10']}
        (root/'result.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
        return result
    finally:
        # psutil can terminate this child, but only the owning Popen object can
        # reap and release its Windows process handle. Without wait(), the image
        # file remains undeletable until the Python evaluator itself exits.
        if foreign is not None:
            if foreign.poll() is None:
                foreign.terminate()
            try:foreign.wait(timeout=5)
            except subprocess.TimeoutExpired:
                foreign.kill();foreign.wait(timeout=5)
        # Only controlled fixtures whose full executable path lies in this test.
        remaining=[]
        for p in psutil.process_iter(['exe']):
            if executable_in_root(p.info['exe'],root):
                try:p.terminate();remaining.append(p)
                except psutil.Error:pass
        _,alive_processes=psutil.wait_procs(remaining,timeout=5)
        for process in alive_processes:
            try:process.kill()
            except psutil.Error:pass
        _,alive_processes=psutil.wait_procs(alive_processes,timeout=5)
        if alive_processes:
            raise AssertionError('Controlled shutdown fixtures survived cleanup')
        # process_iter caches Process objects between calls. Drop those wrappers
        # before the outer build removes PE files that were just executed.
        psutil.process_iter.cache_clear()
