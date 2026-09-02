import json
import uuid
import winreg
from pathlib import Path
import tempfile


def verify_startup(build, env, run, source):
    folder=Path(tempfile.mkdtemp(prefix='startup tests ',dir=build));(folder/'Data').mkdir()
    key='Software\\HuoChatPortableTests\\'+uuid.uuid4().hex
    define='#define HUOCHAT_STARTUP_KEY L'+json.dumps(key)+'\n'
    for name,target in [('guard-test.c','guard.c'),('startup-test.c','test_startup.c')]:
        (folder/name).write_text(define+'#include "'+target+'"\n',encoding='utf-8')
    run(['cl.exe','/nologo','/utf-8','/LD','/MT','/O1','/I'+str(source),folder/'guard-test.c',
         '/link','kernel32.lib','shell32.lib','shlwapi.lib','ole32.lib','advapi32.lib','/DEF:'+str(build/'guard.def'),
         '/OUT:startup-test.dll'],cwd=folder,env=env)
    run(['cl.exe','/nologo','/utf-8','/MT','/O1','/I'+str(source),folder/'startup-test.c',
         '/link','kernel32.lib','advapi32.lib','/OUT:startup-test.exe'],cwd=folder,env=env)
    (folder/'outer package.exe').write_bytes(b'not executed')
    (folder/'.package.ini').write_text('[Package]\nentry='+str(folder/'outer package.exe')+'\n',encoding='utf-16')
    try:
        print(run([folder/'startup-test.exe',folder],cwd=folder).decode(),flush=True)
    finally:
        # Only this uniquely allocated test subtree, never the Windows Run key.
        for sub in (key+r'\Other',key):
            try: winreg.DeleteKey(winreg.HKEY_CURRENT_USER,sub)
            except FileNotFoundError: pass
    return ['startup A/W toggles','exact current-user key and own-value scope',
            'disabled startup retained','existing direct startup repaired']
