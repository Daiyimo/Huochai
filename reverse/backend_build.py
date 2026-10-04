"""Pinned upstream inputs and the small x86 adapters around a signed x64 engine."""
import hashlib
from pathlib import Path
import shutil
import pefile

ENGINE_VERSION='1.5.0.1423b'
ENGINE_SHA256='81b4d05e84e61891ac043dd76e97de616af17adf53b2ee2fe984d8b0bbbfcc21'
SDK_SHA256='1ffe69d856a8a071a7531d54d7b05ae04a87814b812e649521a67a606c7f93e0'
VENDOR=Path(__file__).resolve().parent/'vendor'

def pinned(name,digest):
    path=VENDOR/name
    if hashlib.sha256(path.read_bytes()).hexdigest()!=digest:raise ValueError('Pinned upstream hash mismatch: '+name)
    return path

def prepare_sdk(folder):
    shutil.copy2(pinned('Everything32.upstream.dll',SDK_SHA256),folder/'Everything32.dll')

def compile_adapters(build,env,run,source,application):
    sdk=pinned('Everything32.upstream.dll',SDK_SHA256)
    names=set()
    # The original search UI sends IPC v1 itself, bypassing the SDK. Both
    # consumers must use the same instance lookup, with all other APIs forwarded.
    for consumer in (sdk,application):
        pe=pefile.PE(str(consumer))
        for dll in pe.DIRECTORY_ENTRY_IMPORT:
            if dll.dll.lower()==b'user32.dll':names.update(item.name.decode() for item in dll.imports)
        pe.close()
    assert 'FindWindowW' in names
    definition=build/'bridge.def'
    definition.write_text('LIBRARY hce\nEXPORTS\n'+'\n'.join(
        name+'='+('_Backend_FindWindowW@8' if name=='FindWindowW' else 'USER32.'+name) for name in sorted(names)),encoding='ascii')
    run(['cl.exe','/nologo','/utf-8','/LD','/MT','/O1',source/'sdk_bridge.c','/link',
         'kernel32.lib','user32.lib','/DEF:'+str(definition),'/OUT:'+str(build/'hce.dll')],cwd=build,env=env)
    run(['cl.exe','/nologo','/utf-8','/MT','/O1',source/'engine_broker.c','/link',
         'kernel32.lib','shell32.lib','user32.lib','advapi32.lib','/SUBSYSTEM:WINDOWS','/OUT:'+str(build/'hc_engine.exe')],cwd=build,env=env)

def route_windows(path):
    raw=bytearray(path.read_bytes());pe=pefile.PE(data=raw);changed=0
    for dll in pe.DIRECTORY_ENTRY_IMPORT:
        if dll.dll.lower()==b'user32.dll':
            offset=pe.get_offset_from_rva(dll.struct.Name)
            raw[offset:offset+len(dll.dll)+1]=b'hce.dll'.ljust(len(dll.dll)+1,b'\0');changed+=1
    pe.close()
    if changed!=1:raise ValueError('USER32 routing input drifted: '+str(path))
    pe=pefile.PE(data=raw);pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();path.write_bytes(pe.write());pe.close()

def install_engine(folder,build):
    # An interrupted build can leave a half-populated Engine directory behind.
    engine=folder/'Engine';engine.mkdir(exist_ok=True)
    shutil.copy2(pinned('Everything-'+ENGINE_VERSION+'.x64.exe',ENGINE_SHA256),engine/'Everything.exe')
    shutil.copy2(build/'hc_engine.exe',folder/'hc_engine.exe')

def is_official_engine(path,folder):
    if path.relative_to(folder).as_posix()!='Engine/Everything.exe':return False
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=ENGINE_SHA256:raise ValueError('Official engine modified: '+str(path))
    pe=pefile.PE(data=raw)
    try:
        if pe.FILE_HEADER.Machine!=0x8664 or not pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size:
            raise ValueError('Official x64 engine/signature missing')
    finally:pe.close()
    return True
