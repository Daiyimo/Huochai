"""Pinned compatibility fix for the deliberately absent embedded web engine."""
import pefile
import struct


def append_section(data, name, content, flags=0x60000020):
    """Append a pinned PE section; callers supply position-independent code."""
    pe=pefile.PE(data=bytes(data))
    align=lambda n,a:(n+a-1)//a*a
    header=pe.sections[-1].get_file_offset()+40
    if header+40>pe.sections[0].PointerToRawData or any(data[header:header+40]):
        raise ValueError('No unused PE section header')
    rva=align(pe.OPTIONAL_HEADER.SizeOfImage,pe.OPTIONAL_HEADER.SectionAlignment)
    raw=align(len(data),pe.OPTIONAL_HEADER.FileAlignment)
    payload=content(rva) if callable(content) else content
    size=align(len(payload),pe.OPTIONAL_HEADER.FileAlignment)
    data[header:header+40]=struct.pack('<8sIIIIIIHHI',name,len(payload),rva,size,raw,0,0,0,0,flags)
    data.extend(b'\0'*(raw-len(data))+payload.ljust(size,b'\0'))
    struct.pack_into('<H',data,pe.FILE_HEADER.get_field_absolute_offset('NumberOfSections'),len(pe.sections)+1)
    struct.pack_into('<I',data,pe.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfImage'),align(rva+len(payload),pe.OPTIONAL_HEADER.SectionAlignment))
    if flags&0x20:
        struct.pack_into('<I',data,pe.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfCode'),pe.OPTIONAL_HEADER.SizeOfCode+size)
    pe.close()
    return rva


def save_before_shutdown(path,shutdown_event='Local\\HuoChatOfflineLauncherStoppingV1'):
    """Flush while the configuration and its directory owner are still alive.

    The original shutdown posts settings WM_CLOSE asynchronously, clears the
    settings singleton, then destroys the configuration owner. Its five-second
    save timer is gated on that cleared singleton. A synchronous save belongs
    before teardown, not at the final TerminateProcess call (too late).
    """
    data=bytearray(path.read_bytes());pe=pefile.PE(data=bytes(data))
    call_rva=0x194f0a;offset=pe.get_offset_from_rva(call_rva)
    expected=b'\xe8'+struct.pack('<i',0xbd170-call_rva-5)
    if data[offset:offset+5]!=expected:
        raise ValueError('Shutdown entry call drifted')
    imports={i.name:i.address-pe.OPTIONAL_HEADER.ImageBase for d in pe.DIRECTORY_ENTRY_IMPORT for i in d.imports}
    for name,rva in [(b'CreateEventW',0x39546c),(b'SetEvent',0x395440),(b'CloseHandle',0x39528c)]:
        if imports.get(name)!=rva:raise ValueError('Shutdown event import drifted')
    pe.close()
    def thunk(rva):
        code=bytearray(b'\x51') # preserve the shutdown object's this pointer
        def branch(op,target):
            code.extend(bytes([op])+struct.pack('<i',target-(rva+len(code)+5)))
        branch(0xe8,0xa0200)  # existing GetConfig singleton
        code.extend(b'\x8b\xc8\x6a\x00')
        branch(0xe8,0xa4450)  # existing complete serializer, encryption and save
        # Notify the launcher immediately after saving, before the native UI
        # starts tearing down managers. All added addresses remain ASLR-safe.
        code.extend(b'\x53')
        branch(0xe8,rva+len(code)+5)
        return_rva=rva+len(code)
        code.extend(b'\x5b\x81\xeb'+struct.pack('<I',return_rva))
        code.extend(b'\x8d\x83'+struct.pack('<I',rva+128)+b'\x50\x6a\x00\x6a\x01\x6a\x00')
        code.extend(b'\xff\x93'+struct.pack('<I',imports[b'CreateEventW']))
        code.extend(b'\x85\xc0\x74\x0e\x50\x50')
        code.extend(b'\xff\x93'+struct.pack('<I',imports[b'SetEvent']))
        code.extend(b'\xff\x93'+struct.pack('<I',imports[b'CloseHandle']))
        code.extend(b'\x5b')
        code.extend(b'\x59')
        branch(0xe9,0xbd170)  # resume the displaced original call
        if len(code)>128:raise ValueError('Shutdown thunk overlaps event name')
        return code.ljust(128,b'\x90')+(shutdown_event+'\0').encode('utf-16le')
    rva=append_section(data,b'.hcfix\0\0',thunk)
    data[offset:offset+5]=b'\xe8'+struct.pack('<i',rva-call_rva-5)
    result=pefile.PE(data=bytes(data));result.OPTIONAL_HEADER.CheckSum=result.generate_checksum()
    path.write_bytes(result.write());result.close()


def disable_settings_webview(path):
    """The native settings dialog must not call an uninitialised wke entry.

    The void __thiscall routine takes one BOOL and only creates/updates an
    embedded web pane. Both native callers ignore its return value. No browser
    exists in this build, so return while popping that argument; native settings
    controls and their persistence callbacks continue to operate.
    """
    data=bytearray(path.read_bytes())
    pe=pefile.PE(data=bytes(data))
    offset=pe.get_offset_from_rva(0x191140)
    expected=bytes.fromhex('53 8b dc 83 ec 08')
    if data[offset:offset+len(expected)]!=expected:
        raise ValueError('Settings webview entry drifted')
    if pe.get_data(0x1916d7,3)!=bytes.fromhex('c2 04 00'):
        raise ValueError('Settings webview calling convention drifted')
    data[offset:offset+len(expected)]=bytes.fromhex('c2 04 00 90 90 90')
    pe.close()
    result=pefile.PE(data=bytes(data))
    result.OPTIONAL_HEADER.CheckSum=result.generate_checksum()
    path.write_bytes(result.write());result.close()
