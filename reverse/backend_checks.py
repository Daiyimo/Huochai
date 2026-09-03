"""Production launcher/broker, actual routed SDK and signed 1.5 engine."""
from pathlib import Path
import hashlib
import shutil
import subprocess
import time
import uuid
import psutil
from backend_build import ENGINE_SHA256

def verify_backend(folder,build,env,run,source):
    root=build/('beta integration 中文 '+uuid.uuid4().hex[:8]);shutil.copytree(folder,root)
    # Keep the actual main binary before replacing its UI with the lifecycle
    # fixture. Its real query block is a separate, mandatory regression gate.
    original_ui=root/'HuoChat-query-source.exe';shutil.copy2(root/'HuoChat.exe',original_ui)
    other=root.with_name(root.name+' foreign')
    identity='HuoChatBetaTest'+uuid.uuid4().hex
    definitions=('#define HUOCHAT_LAUNCHER_MUTEX L"Local\\\\'+identity+'LauncherV1"\n'
        '#define HUOCHAT_READY_EVENT L"Local\\\\'+identity+'Ready"\n'
        '#define HUOCHAT_STOP_EVENT L"Local\\\\'+identity+'Stop"\n'
        '#define HUOCHAT_STARTUP_KEY L"Software\\\\HuoChatBetaTests\\\\'+identity+'"\n')
    for name,include in [('HuoChat_launcher.exe','launcher.c'),('HuoChat.exe','test_backend_ui.c')]:
        wrapper=root/(name+'.c');wrapper.write_text(definitions+'#define HC_CHECKPOINT_INTERVAL_MS 1000\n#include "'+include+'"\n',encoding='utf-8')
        run(['cl.exe','/nologo','/utf-8','/MT','/O1','/I'+str(source),wrapper,'/link','kernel32.lib',
             'advapi32.lib','user32.lib','/SUBSYSTEM:WINDOWS','/OUT:'+str(root/name)],cwd=build,env=env)
    run(['cl.exe','/nologo','/utf-8','/MT','/O1',source/'test_backend_sdk.c','/link','kernel32.lib',
         '/OUT:'+str(root/'sdk-query.exe')],cwd=build,env=env)
    run(['cl.exe','/nologo','/utf-8','/MT','/O1',source/'test_ui_query.c','/link','kernel32.lib','user32.lib',
         '/OUT:'+str(root/'ui-query.exe')],cwd=build,env=env)
    # Everything folder monitoring needs canonical paths: an 8.3 alias can
    # enumerate successfully yet miss notifications carrying the long path.
    fixture=(root/'www.local.example 中文').resolve();fixture.mkdir();target=fixture/'sample-archive-001.zip';target.write_bytes(b'fixture zip name')
    (fixture/'中文 本地文件.txt').write_bytes(b'fixture')
    config=('[Everything]\nrun_as_admin=0\nauto_include_fixed_volumes=0\nauto_include_removable_volumes=0\n'
        'auto_include_fixed_refs_volumes=0\nauto_include_removable_refs_volumes=0\n'
        'auto_include_fixed_fat_volumes=0\nauto_include_removable_fat_volumes=0\n'
        'scan_volume_drive_letters=0\nntfs_volume_guids=\nrefs_volume_guids=\n'
        'folders="'+str(fixture).replace('\\','\\\\')+'"\nfolder_monitor_changes=1\nfolder_update_types=0\n')
    old_ini=root/'Data/Index.ini';old_ini.write_text(config,encoding='utf-8')
    old_db=root/'Data/Index/Everything.db';old_db.parent.mkdir(exist_ok=True);old_db.write_bytes(b'unchanged 1.4 cache')
    db=root/'Data/Index-1.5/Everything.db';process=None;foreign=None
    def until(predicate,seconds=25):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            if predicate():return
            time.sleep(.1)
        raise AssertionError('Beta integration timed out: '+str(root))
    def query(text,where=root):
        p=subprocess.run([str(where/'sdk-query.exe'),text],cwd=where,capture_output=True,timeout=10)
        if p.returncode:return {}
        return dict(line.split('=',1) for line in p.stdout.decode('utf-8').splitlines())
    def engine_pid(where):
        expected=str((where/'Engine/Everything.exe').resolve()).casefold()
        return next((p.info['pid'] for p in psutil.process_iter(['pid','exe']) if (p.info['exe'] or '').casefold()==expected),None)
    def start():
        (root/'test-stop').unlink(missing_ok=True)
        return subprocess.Popen([str(root/'HuoChat_launcher.exe')],cwd=root,creationflags=subprocess.CREATE_NO_WINDOW)
    def stop(p):
        pid=engine_pid(root);begin=time.monotonic();(root/'test-stop').write_bytes(b'1');assert p.wait(timeout=7)==0
        if pid:assert not psutil.pid_exists(pid)
        return round((time.monotonic()-begin)*1000)
    try:
        process=start();until(lambda:query(target.name).get('count')=='1')
        result=query(target.name);assert result['version']=='1.5.0.1423',result
        assert Path(result['file'])==target and int(result['size'])==target.stat().st_size
        run([root/'ui-query.exe',original_ui,target.name,target.name],cwd=root,timeout=10)
        run([root/'ui-query.exe',original_ui,'"中文 本地文件.txt"','中文 本地文件.txt'],cwd=root,timeout=10)
        for term in ('wholefilename:'+target.name,'sample 001','ext:zip sample','"中文 本地文件.txt"'):
            assert query(term).get('count')=='1',term
        assert query('no-such-file-12345').get('count')=='0'
        until(lambda:db.exists() and db.stat().st_size>0)
        # Real folder monitoring, independent of the legacy -rescan-all fixture.
        added=fixture/'newly-created.zip';added.write_bytes(b'new')
        until(lambda:query(added.name).get('count')=='1')
        renamed=fixture/'newly-renamed.zip';added.rename(renamed)
        until(lambda:query(added.name).get('count')=='0' and query(renamed.name).get('count')=='1')
        renamed.unlink();until(lambda:query(renamed.name).get('count')=='0')
        # A second full copy has an independent window/DB. The SDK in it must
        # never fall back to the first copy's index while its own engine is absent.
        shutil.copytree(folder,other)
        shutil.copy2(root/'sdk-query.exe',other/'sdk-query.exe')
        shutil.copy2(root/'ui-query.exe',other/'ui-query.exe')
        raw_missing=subprocess.run([str(other/'ui-query.exe'),str(other/'HuoChat.exe'),target.name,target.name],
            cwd=other,capture_output=True,timeout=10)
        assert raw_missing.returncode==10 and b'window=00000000 reply=0' in raw_missing.stdout,raw_missing.stdout
        assert not query(target.name,other),'SDK crossed into another installation'
        second=(other/'fixture').resolve();second.mkdir();(second/'foreign-only.txt').write_bytes(b'foreign')
        (other/'Data/Index.ini').write_text(config.replace(str(fixture).replace('\\','\\\\'),str(second).replace('\\','\\\\')),encoding='utf-8')
        foreign=subprocess.Popen([str(other/'hc_engine.exe')],cwd=other,creationflags=subprocess.CREATE_NO_WINDOW);foreign.wait(timeout=5)
        until(lambda:query('foreign-only.txt',other).get('count')=='1')
        assert query('foreign-only.txt').get('count')=='0' and query(target.name,other).get('count')=='0'
        exit_ms=stop(process);process=None
        assert engine_pid(other) is not None,'Stopped foreign 1.5 engine'
        assert old_ini.read_text(encoding='utf-8')==config and old_db.read_bytes()==b'unchanged 1.4 cache'
        saved=db.read_bytes();assert saved
        process=start();until(lambda:query(target.name).get('count')=='1');exit_ms=max(exit_ms,stop(process));process=None
        assert hashlib.sha256((root/'Engine/Everything.exe').read_bytes()).hexdigest()==ENGINE_SHA256
        return {'pass':True,'max_exit_ms':exit_ms,'checks':['actual x86 SDK to signed 1.5 x64 engine with IPC v2 path/size/date',
            'original HuoChat UI query machine code receives actual IPC v1 replies for exact filename and Chinese search',
            'original UI lookup ignores another default Everything window and an engine in a different installation',
            'exact filename, multi-keyword, extension and Chinese queries','real create/rename/delete monitoring',
            'SDK and cancellation isolated from a second 1.5 installation','legacy config and cache unchanged',
            'production checkpoint creates 1.5 cache and restart searches successfully','official engine bytes unchanged']}
    finally:
        if process and process.poll() is None:
            (root/'test-stop').write_bytes(b'1')
            try:process.wait(timeout=7)
            except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=3)
        for where in (root,other):
            pid=engine_pid(where)
            if pid:
                try:p=psutil.Process(pid);p.terminate();p.wait(timeout=5)
                except psutil.NoSuchProcess:pass
        target.unlink(missing_ok=True)
