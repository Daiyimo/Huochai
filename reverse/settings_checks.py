"""Real native settings persistence, without desktop interaction or user data."""
import base64
import json
import os
import shutil
import struct
import ctypes
from ctypes import wintypes
import uuid
import pefile
from Crypto.Cipher import DES
from settings_patch import append_section,save_before_shutdown


def decode_config(raw):
    data=DES.new(b'hyjconfi',DES.MODE_ECB).decrypt(base64.b64decode(raw))
    pad=data[-1]
    return json.loads(data.rstrip(bytes([pad])))


def encode_config(doc):
    data=json.dumps(doc,ensure_ascii=False,separators=(',',':')).encode('utf-8')
    data+=bytes([data[-1]^255])*(8-len(data)%8)
    return base64.b64encode(DES.new(b'hyjconfi',DES.MODE_ECB).encrypt(data))


def probe_host(path):
    data=bytearray(path.read_bytes());pe=pefile.PE(data=bytes(data))
    iat={i.name:i.address-pe.OPTIONAL_HEADER.ImageBase for d in pe.DIRECTORY_ENTRY_IMPORT for i in d.imports}
    entry=pe.get_offset_from_rva(0x7fd70)
    pe.close()
    def loader(rva):
        # WinMain's callee-saved EBX holds the image base, derived via call/pop.
        code=bytearray(b'\x53\xe8\0\0\0\0\x5b\x81\xeb'+struct.pack('<I',rva+6))
        code.extend(b'\x8d\x83'+struct.pack('<I',rva+96)+b'\x50\xff\x93'+struct.pack('<I',iat[b'LoadLibraryW']))
        code.extend(b'\x8d\x8b'+struct.pack('<I',rva+128)+b'\x51\x50\xff\x93'+struct.pack('<I',iat[b'GetProcAddress']))
        code.extend(b'\xff\xd0\x5b\xc2\x10\x00')
        return code.ljust(96,b'\x90')+'hctest.dll\0'.encode('utf-16le').ljust(32,b'\0')+b'TestMain\0'
    rva=append_section(data,b'.hcprobe',loader)
    data[entry:entry+5]=b'\xe9'+struct.pack('<i',rva-0x7fd70-5)
    path.write_bytes(data)


def verify_settings(build,folder,env,run,source):
    root=build/'settings persistence 中文';root.mkdir(exist_ok=True)
    # Only program files; never copy the user's profile or execute original UI.
    for p in folder.iterdir():
        if p.is_file() and p.suffix.lower() in ('.exe','.dll'):shutil.copy2(p,root/p.name)
    (root/'Data'/'User').mkdir(parents=True)
    run(['cl.exe','/nologo','/utf-8','/TP','/LD','/MT','/O1',source/'test_settings_persistence.c',
         '/link','kernel32.lib','user32.lib','/OUT:hctest.dll'],cwd=root,env=env)
    pristine=(root/'HuoChat.exe').read_bytes()
    def invoke(mode,enabled=False):
        probe_env=os.environ.copy();probe_env['HC_SETTINGS_PROBE']=mode
        probe_env['HC_SETTINGS_VALUE']='1' if enabled else '0'
        run([root/'HuoChat.exe'],cwd=root,env=probe_env,timeout=30)
    probe_host(root/'HuoChat.exe');invoke('seed')
    config=root/'Data'/'User'/'config';initial=config.read_bytes();doc=decode_config(initial)
    doc['extension']['b_tinynav']=False;doc['local']['b_fastside']=False
    nav='plugin_plugin_综合导航_word_enable';doc['extension'][nav]=False
    (root/'edited.json').write_text(json.dumps(doc,ensure_ascii=False),encoding='utf-8')
    invoke('write')
    assert config.read_bytes()==initial,'Baseline unexpectedly saved before teardown'
    (root/'HuoChat.exe').write_bytes(pristine)
    event_name='Local\\HuoChatSettingsStopTest'+uuid.uuid4().hex
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateEventW.argtypes=[ctypes.c_void_p,wintypes.BOOL,wintypes.BOOL,wintypes.LPCWSTR]
    kernel.CreateEventW.restype=wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD]
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    event=kernel.CreateEventW(None,True,False,event_name);assert event
    try:
        save_before_shutdown(root/'HuoChat.exe',event_name);probe_host(root/'HuoChat.exe');invoke('write')
        assert kernel.WaitForSingleObject(event,0)==0,'Native exit did not signal the launcher'
    finally:kernel.CloseHandle(event)
    updated=decode_config(config.read_bytes())
    assert updated['extension']['b_tinynav'] is False
    assert updated['local']['b_fastside'] is False
    assert updated['extension'][nav] is False
    invoke('read')
    for enabled in (True,False):
        doc['extension']['b_tinynav']=enabled;doc['local']['b_fastside']=enabled;doc['extension'][nav]=enabled
        (root/'edited.json').write_text(json.dumps(doc,ensure_ascii=False),encoding='utf-8')
        invoke('write',enabled);invoke('read',enabled)
        saved=decode_config(config.read_bytes())
        assert saved['extension'][nav] is enabled
    return ['original shutdown loses pending settings before teardown',
            'patched shutdown writes all three switches using original serializer',
            'fresh native process reloads the saved switches from Data/User/config',
            'off/on/off changes persist across process restarts and real model destruction']
