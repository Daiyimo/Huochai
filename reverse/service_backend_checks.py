"""Optional elevated test: isolated signed service plus a standard-user client.

Copies a verified payload into a new temp directory. Scans local fixed volumes,
checks the requested filename, and removes only the newly created named service.
Does not change the user's existing Everything service or running application.
"""
import argparse
import ctypes
import csv
import json
from pathlib import Path
import shutil
import statistics
import subprocess
import tempfile
import time
import psutil
from build import compiler_env,run,SOURCE_DIR


def verify_service(payload,example,output):
    if not ctypes.windll.shell32.IsUserAnAdmin():raise RuntimeError('This optional service test requires an elevated terminal.')
    root=Path(tempfile.mkdtemp(prefix='huochai_beta_service_')).resolve()
    # Some elevated temp directories grant only Administrators/OWNER RIGHTS.
    # Give this user access only to our newly created fixture before dropping
    # admin membership. Never alter the user's installation or parent ACL.
    identity=subprocess.run(['whoami','/user','/fo','csv','/nh'],capture_output=True,check=True).stdout.decode('mbcs')
    sid=next(csv.reader(identity.strip().splitlines()))[1];assert sid.startswith('S-1-')
    subprocess.run(['icacls',str(root),'/grant','*'+sid+':(OI)(CI)F'],capture_output=True,check=True)
    shutil.copytree(payload,root,dirs_exist_ok=True)
    env=compiler_env();flags=subprocess.CREATE_NO_WINDOW;service=None
    for name in ('test_launch_standard','test_backend_sdk'):
        run(['cl.exe','/nologo','/utf-8','/MT','/O1',SOURCE_DIR/(name+'.c'),'/link','kernel32.lib',
             'advapi32.lib','/OUT:'+str(root/(name+'.exe'))],cwd=root,env=env)
    broker=root/'hc_engine.exe';engine=root/'Engine/Everything.exe'
    def service_config(name):
        p=subprocess.run(['sc.exe','qc',name],capture_output=True)
        return p.returncode,p.stdout.decode('mbcs','replace')
    original_service=service_config('Everything')
    def query(text):
        p=subprocess.run([str(root/'test_backend_sdk.exe'),text],cwd=root,capture_output=True,timeout=15)
        return dict(line.split('=',1) for line in p.stdout.decode('utf-8').splitlines()) if p.returncode==0 else {}
    try:
        p=subprocess.run([str(broker),'-install-service'],cwd=root,timeout=20,creationflags=flags)
        service=next(line.split('=',1)[1] for line in (root/'Engine/Everything.ini').read_text().splitlines() if line.startswith('service_name='))
        assert p.returncode==0,p.returncode
        code,config=service_config(service);assert code==0 and str(engine).casefold() in config.casefold()
        assert service_config('Everything')==original_service,'Existing default service changed'
        print('Isolated service installed: '+service,flush=True)
        begin=time.monotonic()
        p=subprocess.run([str(root/'test_launch_standard.exe'),str(root),'"'+str(broker)+'"'],cwd=root,capture_output=True,timeout=10)
        assert p.returncode==0,(p.returncode,p.stdout)
        deadline=time.monotonic()+120;result={}
        while time.monotonic()<deadline:
            result=query('wholefilename:'+example)
            if result.get('count')=='1':break
            time.sleep(.3)
        assert result.get('count')=='1',result
        ready_ms=round((time.monotonic()-begin)*1000)
        assert result['admin']=='0' and result['version']=='1.5.0.1423',result
        assert Path(result['file']).is_file() and int(result['size'])==Path(result['file']).stat().st_size
        pid=next(p.pid for p in psutil.process_iter(['exe','cmdline']) if p.info['exe'] and
            p.info['exe'].casefold()==str(engine).casefold() and '-svc' not in p.info['cmdline'])
        process=psutil.Process(pid);network=process.net_connections(kind='inet');volumes={}
        for partition in psutil.disk_partitions():
            if partition.fstype=='NTFS' and partition.mountpoint[:2] in ('C:','D:','E:','F:'):
                values=query('file: '+partition.mountpoint);assert values,partition.mountpoint
                volumes[partition.mountpoint]=int(values['total']);assert volumes[partition.mountpoint]>0
        samples=[]
        for _ in range(7):
            start=time.perf_counter();assert query('wholefilename:'+example).get('count')=='1';samples.append((time.perf_counter()-start)*1000)
        report={'pass':True,'fixture_directory':str(root),'backend_admin':False,'service_name':service,
            'cold_example_ready_ms':ready_ms,'query':result,'files_by_drive':volumes,
            'median_probe_process_ms':round(statistics.median(samples),2),'working_set_bytes':process.memory_info().rss,
            'observed_inet_connections':len(network),'default_service_unchanged':service_config('Everything')==original_service,
            'scope':'Actual standard-user engine with isolated signed service and NTFS fixed volumes. Timing includes probe process launch and DLL loading.'}
        output.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
        return report
    finally:
        for p in psutil.process_iter(['exe','cmdline']):
            if p.info['exe'] and p.info['exe'].casefold()==str(engine).casefold() and '-svc' not in (p.info['cmdline'] or []):
                try:p.terminate();p.wait(timeout=5)
                except psutil.Error:pass
        if service:
            code,config=service_config(service)
            if code==0 and str(engine).casefold() in config.casefold():
                result=subprocess.run([str(broker),'-uninstall-service'],cwd=root,timeout=20,creationflags=flags)
                assert result.returncode==0,('service cleanup failed',service,result.returncode)
        assert service_config('Everything')==original_service,'Existing default service changed'


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--payload',type=Path,required=True)
    parser.add_argument('--example',default='sample-archive-001.zip')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(verify_service(args.payload,args.example,args.output),ensure_ascii=False,indent=2))
