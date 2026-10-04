"""Prove external cache handles survive exit without locking HuoChat's folder."""
from pathlib import Path
import hashlib
import os
import shutil
import subprocess
import time
import uuid
import psutil

from build import isolated_definition_source


def verify_environment_release(build, env, run, source):
    root=(build/('environment-release-'+uuid.uuid4().hex[:8])).resolve();root.mkdir()
    payload=root/'portable';payload.mkdir()
    external=root/'external application';external.mkdir()
    profile=root/'caller profile';profile.mkdir()
    identity='HuoChatEnvironment'+uuid.uuid4().hex
    definitions=isolated_definition_source(identity,'HuoChatEnvironmentTests',False)
    for name,include in [('HuoChat_launcher.exe','launcher.c'),('HuoChat.exe','test_environment_hold.c')]:
        wrapper=root/(name+'.c');wrapper.write_text(definitions+'#include "'+include+'"\n',encoding='utf-8')
        run(['cl.exe','/nologo','/utf-8','/MT','/O1','/I'+str(source),wrapper,'/link',
             'kernel32.lib','user32.lib','advapi32.lib','/SUBSYSTEM:WINDOWS','/OUT:'+str(payload/name)],cwd=root,env=env)
    shutil.copy2(payload/'HuoChat.exe',external/'external.exe')
    shutil.copy2(build/'hcg.dll',payload/'hcg.dll')
    data=payload/'Data';(data/'User').mkdir(parents=True);(data/'Index').mkdir()
    (data/'Apps/Tencent').mkdir(parents=True)
    (data/'Index.ini').write_text('[Everything]\n',encoding='utf-8')
    protected={'User/config':b'keep user configuration','User/note':b'keep user note',
               'Index/Everything.db':b'keep completed index','Apps/Tencent/previous-settings':b'keep old third-party data'}
    for name,value in protected.items():(data/name).write_bytes(value)
    launch_env=os.environ.copy()
    names=('APPDATA','LOCALAPPDATA','TEMP','TMP')
    for name in names:
        folder=profile/name;folder.mkdir();launch_env[name]=str(folder)
    ready=root/'external.ready';stop=root/'external.stop'
    launch_env.update(HC_HOLDER_EXE=str(external/'external.exe'),HC_HOLDER_READY=str(ready),HC_HOLDER_STOP=str(stop))
    process=None;worker=None;moved=root/'portable moved 中文'
    def until(predicate,seconds=12):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            if predicate():return
            if process is not None and process.poll() is not None:raise AssertionError(('launcher exited early',process.returncode))
            time.sleep(.03)
        raise AssertionError('Environment release test timed out: '+str(root))
    try:
        process=subprocess.Popen([str(payload/'HuoChat_launcher.exe')],cwd=root,env=launch_env,creationflags=subprocess.CREATE_NO_WINDOW)
        until(lambda:ready.exists() and (payload/'ui.ready').exists())
        worker=psutil.Process(int(ready.read_text()))
        expected={str(profile/name/f'cache-holder-{i}.dat').casefold() for i,name in enumerate(names)}
        actual={f.path.casefold() for f in worker.open_files()}
        assert expected<=actual,('external cache redirected into portable folder',expected,actual)
        for i,name in enumerate(names):assert not (data/('Apps' if i<2 else 'Temp')/f'cache-holder-{i}.dat').exists()
        before=hashlib.sha256((payload/'HuoChat_launcher.exe').read_bytes()).hexdigest()
        started=time.monotonic();(payload/'test-stop').write_bytes(b'1');assert process.wait(timeout=8)==0
        exit_ms=round((time.monotonic()-started)*1000);assert worker.is_running(),'Exit killed the external application'
        # Check both resolved targets before moving only our allocated fixture.
        assert payload.resolve().parent==root and moved.resolve().parent==root and not moved.exists()
        payload.rename(moved)
        assert worker.is_running() and expected<={f.path.casefold() for f in worker.open_files()}
        assert hashlib.sha256((moved/'HuoChat_launcher.exe').read_bytes()).hexdigest()==before
        for name,value in protected.items():assert (moved/'Data'/name).read_bytes()==value
        moved.rename(payload)
        return {'pass':True,'exit_ms':exit_ms,'checks':[
            'external application holds actual cache files in unchanged caller APPDATA/LOCALAPPDATA/TEMP/TMP',
            'HuoChat-only GetTempPath stays under Data/Temp',
            'external process and its cache handles survive production launcher exit',
            'entire portable directory can be renamed while the external process remains alive',
            'own configuration, notes, completed index and legacy third-party data remain unchanged']}
    finally:
        stop.write_bytes(b'1')
        if worker:
            try:worker.wait(timeout=5)
            except psutil.NoSuchProcess:pass
            except psutil.TimeoutExpired:worker.terminate();worker.wait(timeout=3)
        if process and process.poll() is None:
            (payload/'test-stop').write_bytes(b'1')
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=3)
