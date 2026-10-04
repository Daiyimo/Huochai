"""Fast tray-exit/reopen through the real package and launcher, isolated PIDs."""
import json
import shutil
import subprocess
import time
import uuid
import psutil

from build import isolated_definition_source


def verify_shutdown(parent,env,compiler,icon,package,run,source):
    root=parent/('shutdown-'+uuid.uuid4().hex);root.mkdir()
    identity='HuoChatCancelTest'+uuid.uuid4().hex
    definitions=isolated_definition_source(identity,'HuoChatRuntimeTests',True)
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
    def pid(name):return int((payload/name).read_text())
    def alive(pid):
        try:return psutil.Process(pid).is_running()
        except psutil.NoSuchProcess:return False
    def invoke(expected=0):
        p=subprocess.run([str(exe),'/S'],cwd=location,timeout=12,creationflags=subprocess.CREATE_NO_WINDOW)
        assert p.returncode==expected,('rapid reopen return code',p.returncode,expected)
    def ready():until(lambda:(payload/'ui.ready').exists() and (payload/'engine.ready').exists())
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
        until(lambda:pid('ui.ready')!=first_ui and pid('engine.ready')!=first_engine)
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
        time.sleep(.1);invoke();until(lambda:pid('ui.ready')!=second_ui)
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
        # Only controlled fixtures whose full executable path lies in this test.
        prefix=str(root.resolve()).casefold()+'\\'
        remaining=[]
        for p in psutil.process_iter(['exe']):
            if p.info['exe'] and p.info['exe'].casefold().startswith(prefix):
                try:p.terminate();remaining.append(p)
                except psutil.Error:pass
        psutil.wait_procs(remaining,timeout=5)
