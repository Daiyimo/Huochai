"""The real NSIS wrapper must repair nested engine code while preserving data."""
import ctypes
from ctypes import wintypes
import hashlib
import shutil
import subprocess
import time
import uuid
from backend_build import ENGINE_SHA256
from build import isolated_definition_source


def verify_backend_package(folder,build,env,run,source,package,compiler,icon):
    root=build/('nested package '+uuid.uuid4().hex[:8]);root.mkdir();seed=root/'seed';shutil.copytree(folder,seed)
    identity='HuoChatNested'+uuid.uuid4().hex
    definitions=isolated_definition_source(identity,'HuoChatNestedTests',True)
    wrapper=root/'launcher_test.c';wrapper.write_text(definitions+'#include "launcher.c"\n',encoding='utf-8')
    run(['cl.exe','/nologo','/utf-8','/MT','/O1','/I'+str(source),wrapper,'/link','kernel32.lib','advapi32.lib',
         'user32.lib','/SUBSYSTEM:WINDOWS','/OUT:'+str(seed/'HuoChat_launcher.exe')],cwd=root,env=env)
    ui=root/'ui.c';ui.write_text('#include <windows.h>\nint WINAPI WinMain(HINSTANCE a,HINSTANCE b,LPSTR c,int d){Sleep(400);return 0;}\n',encoding='ascii')
    run(['cl.exe','/nologo','/MT','/O1',ui,'/link','kernel32.lib','/SUBSYSTEM:WINDOWS','/OUT:'+str(seed/'HuoChat.exe')],cwd=root,env=env)
    archive=package(seed,root,'nested',compiler,icon,identity=identity)
    outer=root/'portable.exe';shutil.copy2(archive,outer);payload=root/'HuoChatOffline-v1-nested'
    def invoke():
        p=subprocess.run([str(outer),'/S'],cwd=root,timeout=15,creationflags=subprocess.CREATE_NO_WINDOW)
        time.sleep(.7);return p.returncode
    assert invoke()==0
    engine=payload/'Engine/Everything.exe';assert hashlib.sha256(engine.read_bytes()).hexdigest()==ENGINE_SHA256
    legacy=payload/'Data/Index/Everything.db';legacy.write_bytes(b'legacy cache')
    raw=bytearray(engine.read_bytes());raw[128]^=1;engine.write_bytes(raw)
    assert invoke()==0 and hashlib.sha256(engine.read_bytes()).hexdigest()==ENGINE_SHA256
    assert legacy.read_bytes()==b'legacy cache'
    engine.unlink();assert invoke()==0 and hashlib.sha256(engine.read_bytes()).hexdigest()==ENGINE_SHA256
    engine.write_bytes(raw)
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
    kernel.CreateFileW.restype=wintypes.HANDLE;kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    lock=kernel.CreateFileW(str(engine),0x80000000,1,None,3,0,None)
    assert lock not in (None,ctypes.c_void_p(-1).value)
    try:assert invoke()!=0,'Locked corrupt nested code was accepted'
    finally:kernel.CloseHandle(lock)
    assert invoke()==0 and legacy.read_bytes()==b'legacy cache'
    return {'pass':True,'checks':['nested official engine same-size corruption repaired','missing nested engine restored',
        'locked corrupt nested engine fails closed then repairs after unlock','legacy index preserved across repairs']}
