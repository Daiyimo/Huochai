"""Build and verify the offline package, including an isolated background engine."""
import atexit
from pathlib import Path
import argparse
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
import zlib
import xml.etree.ElementTree as ET
import pefile
from backend_build import prepare_sdk,compile_adapters,route_windows,install_engine,is_official_engine,ENGINE_VERSION,ENGINE_SHA256
from PIL import Image
from guide_cards import offline_guide
from data_layout import relocate_data_paths
from settings_patch import disable_settings_webview,save_before_shutdown
from navigation_layout import clean_navigation_layout
from policy import (INTENTIONALLY_ABSENT, NETWORK_APIS, NETWORK_DLLS, GUARDED_DLLS,
                    scrub_urls, url_hits)

ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIR = Path(__file__).resolve().parent
SOURCE_REV = '39cf149bf9d7030a8f002b4198a9087f985c6b7a'
SOURCES = {
    'single': ('火柴单文件版.exe', '452541a3327935ac452504ff0355bbea801090837f626f1a82c5245e3f89ef1a'),
    'green': ('火柴绿色版.exe', '0b32b5f393806f0c154b2b7f2ff2c93459848e85832c4584d7b3099d25e80e8b'),
}
GUARDS = {
    'GetTempPathW':8,'GetTempPathA':8,
    'OpenServiceW':12,
    'LoadLibraryA':4,'LoadLibraryW':4,'LoadLibraryExA':12,'LoadLibraryExW':12,
    'GetProcAddress':8,'ShellExecuteA':24,'ShellExecuteW':24,
    'ShellExecuteExA':4,'ShellExecuteExW':4,'CoCreateInstance':20,
    'CoGetClassObject':20,'CLSIDFromProgID':8,'CreateFileA':28,'CreateFileW':28,
    'GetFileAttributesA':4,'GetFileAttributesW':4,'FindFirstFileA':8,'FindFirstFileW':8,
    'FindFirstFileExA':24,'FindFirstFileExW':24,
    # Keep application data portable. The original program asks Shell32 for
    # AppData/LocalAppData and then appends its own HuoChat subdirectory.
    'SHGetFolderPathW':20,'SHGetFolderPathA':20,
    'SHGetSpecialFolderPathW':16,'SHGetSpecialFolderPathA':16,
    'SHGetKnownFolderPath':16,
    # A child process owns its own import table, so only network-capable
    # targets are refused; local helpers must keep starting.
    'CreateProcessA':40,'CreateProcessW':40,'WinExec':8,
    'RegSetValueExW':24, 'RegSetValueExA':24,
    'SHSetValueW':24, 'SHSetValueA':24,
    'GetCommandLineW':0, 'GetCommandLineA':0,
    'Shell_NotifyIconW':8, 'Shell_NotifyIconA':8,
}

def check_policy_parity():
    """The static and runtime network lists must agree; drift hides imports.

    guard.c writes some module names without the ``.dll`` suffix, so both sides
    are normalised before comparison.
    """
    source=(SOURCE_DIR/'guard.c').read_text(encoding='utf-8',errors='replace')
    names=set()
    for match in re.finditer(r'contains\(base,\s*L"([a-z0-9._\-]+)"\)', source):
        token=match.group(1).lower()
        # Normalise the suffix: guard.c writes some modules as "ws2_32" and the
        # policy as "ws2_32.dll". Substring tests such as "api-ms-win-net-" are
        # not module names and are excluded from the comparison.
        if token.endswith('.dll') or token.endswith('.exe'):
            names.add(token)
        elif '-' not in token:
            names.add(token + '.dll')
    static={d.lower() for d in NETWORK_DLLS}
    # node.dll and the web engines are refused at load time rather than stubbed.
    only_guard=sorted(names-static-INTENTIONALLY_ABSENT)
    # sensapi is stubbed by hcn.dll, so the runtime list need not mention it.
    only_static=sorted((static-names)-{'sensapi.dll'})
    if only_guard or only_static:
        raise ValueError('Network DLL lists disagree: guard-only=%s policy-only=%s'
                         % (only_guard, only_static))

def run(args, **kwargs):
    args=list(args)
    if kwargs.get('env') and not Path(args[0]).is_absolute():
        args[0]=shutil.which(str(args[0]),path=kwargs['env'].get('PATH')) or args[0]
    result = subprocess.run([str(a) for a in args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kwargs)
    if result.returncode:
        raise RuntimeError(f'Command failed: {args[0]}\n' + result.stdout.decode('utf-8', 'replace')[-10000:])
    return result.stdout

def cleanup_build_dir(path):
    """Remove a Windows build tree after child processes release their handles."""
    path=Path(path).resolve()
    if path.parent!=Path(tempfile.gettempdir()).resolve() or not path.name.startswith('huochai_offline_build_'):
        raise ValueError('Refusing to clean a directory outside the allocated build workspace')
    for attempt in range(20):
        try:
            shutil.rmtree(path)
            return
        except FileNotFoundError:
            return
        except OSError as exc:
            if attempt == 19:
                print('Warning: could not remove temporary build directory '
                      f'{path}: {exc}', file=sys.stderr, flush=True)
                return
            time.sleep(0.25)

def sha(data): return hashlib.sha256(data).hexdigest()

def compiler_env():
    vswhere=Path(r'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe')
    base=run([vswhere,'-latest','-products','*','-property','installationPath']).decode().strip()
    msvc=max((Path(base)/'VC'/'Tools'/'MSVC').iterdir(),key=lambda p:tuple(map(int,p.name.split('.'))))
    sdk=Path(r'C:\Program Files (x86)\Windows Kits\10')
    version=max((sdk/'Include').iterdir(),key=lambda p:tuple(map(int,p.name.split('.')))).name
    env=os.environ.copy()
    env['PATH']=str(msvc/'bin'/'Hostx64'/'x86')+os.pathsep+env.get('PATH','')
    env['INCLUDE']=os.pathsep.join(map(str,[msvc/'include']+[sdk/'Include'/version/x for x in ('ucrt','shared','um','winrt')]))
    env['LIB']=os.pathsep.join(map(str,[msvc/'lib'/'x86',sdk/'Lib'/version/'ucrt'/'x86',sdk/'Lib'/version/'um'/'x86']))
    return env

def extract(exe, dest, seven):
    listing=run([seven,'l','-slt','-sccUTF-8',exe]).decode('utf-8','replace')
    for part in listing.split('----------')[1:]:
        for name in re.findall(r'^Path = (.+)$',part,re.M):
            name=name.strip()
            if Path(name).is_absolute() or '..' in Path(name).parts or ':' in name:
                raise ValueError('Unsafe archive member: '+name)
    dest.mkdir(parents=True,exist_ok=True)
    run([seven,'x',exe,'-o'+str(dest),'-y','-bso0','-bsp0'])

def pe_files(folder):
    return [p for p in sorted(folder.rglob('*')) if p.is_file() and p.read_bytes()[:2]==b'MZ']

def resources(pe):
    for typ in getattr(pe,'DIRECTORY_ENTRY_RESOURCE',type('Empty',(),{'entries':[]})).entries:
        for rid in typ.directory.entries:
            for lang in rid.directory.entries:
                yield typ, rid, lang.data.struct

def resource_zip(data, pe):
    for typ,rid,res in resources(pe):
        if str(typ.name)=='ZIPRES':
            off=pe.get_offset_from_rva(res.OffsetToData)
            yield res, off, data[off:off+res.Size]

# Disabled features still left bitmap/template debris in the embedded ZIPRES.
# Keep this list exact and reviewable: weather 23, web suggestions 24, share 5,
# navigation 3 and tic-tac-toe 2 (57 entries in total). add_nav.png is not a
# visible feature switch: HuoChat unconditionally preloads it during startup
# and crashes at HuoChat+0x1A4169 if it is physically absent.
REMOVED_UI_RESOURCES = frozenset({
    *(f'plugins/weather/{n}.png' for n in
      ('1','2','3','4','5','6','7','8','9','10','11','12','13','14','15','16','17','18','19','20','21','22','99')),
    *(f'setting/web_suggest/{n}' for n in (
      'icon_360.png','icon_amazon.png','icon_baidu.png','icon_baike.png',
      'icon_bdmap.png','icon_bilibili.png','icon_bing.png','icon_douban.png',
      'icon_github.png','icon_google.png','icon_gt.png','icon_huaban.png',
      'icon_iqiyi.png','icon_jd.png','icon_qqshipin.png','icon_sogou.png',
      'icon_suning.png','icon_taobao.png','icon_tmall.png','icon_weixin.png',
      'icon_youku.png','icon_zhihu.png','web_icon.png','web_icon_setting.png')),
    *(f'plugins/share/{n}.png' for n in ('decrease','increase','name','price','volume')),
    'nav_set_list_line.xml','icon/nav.png','plugins/icon_nav.png',
    'plugins/ticractoe/circle.png','plugins/ticractoe/cross.png',
})

GUIDE_GIFS = frozenset(f'guide/guid5_{n}.gif' for n in (1, 2, 3))


def compact_guide_gif(payload, name=None):
    """Keep the final, complete demonstration frame and its original canvas."""
    with Image.open(io.BytesIO(payload)) as source:
        if source.format != 'GIF' or source.size != (1000, 600):
            raise ValueError('Unexpected guide animation format or dimensions')
        if name in ('guide/guid5_2.gif','guide/guid5_3.gif'):
            return offline_guide(int(name[-5]))
        source.seek(source.n_frames - 1)
        frame = source.convert('RGB').quantize(colors=128)
        out = io.BytesIO()
        frame.save(out, format='GIF', optimize=True)
    if len(out.getvalue()) >= len(payload):
        raise ValueError('Guide compaction did not reduce its size')
    return out.getvalue()


def clean_zip(blob):
    out=io.BytesIO(); edits=[]; removed=[]
    with zipfile.ZipFile(io.BytesIO(blob)) as old, zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as new:
        missing=REMOVED_UI_RESOURCES-set(old.namelist())
        if missing:
            raise ValueError('Expected removable UI resources missing: '+', '.join(sorted(missing)[:8]))
        for item in old.infolist():
            if item.filename in REMOVED_UI_RESOURCES:
                removed.append(item.filename)
                continue
            payload=old.read(item)
            if item.filename in GUIDE_GIFS:
                payload=compact_guide_gif(payload,item.filename)
            text=Path(item.filename).suffix.lower() in ('.xml','.html','.htm','.js','.css','.json','.txt')
            payload,found=scrub_urls(payload,fixed_size=not text,
                                     only={h['offset'] for h in url_hits(payload)})
            edits.extend({'resource':item.filename,**x} for x in found)
            if item.filename.lower().endswith('.xml'):
                ET.fromstring(payload)
            item.date_time=(2026,8,31,0,0,0)
            new.writestr(item,payload,compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
    if set(removed)!=REMOVED_UI_RESOURCES:
        raise ValueError('UI resource removal set drifted')
    return out.getvalue(),edits,sorted(removed)

# Sister-product component names that HuoChat still tries to launch at runtime.
# These are bare filenames (not URLs), so scrub_urls never matched them and the
# app raised "Windows cannot find ... HYAmazingNavigation.exe".
# Each entry is (file offset, exact UTF-16LE string, why). Offsets are against
# the unpatched HuoChat.exe and are asserted before writing, so a version drift
# fails the build instead of silently patching the wrong bytes.
COMPONENT_STUBS = [
    (0x3C91A0, 'HYFastSide.exe',           'sidebar component'),
    (0x3C96C8, 'HYSearch.exe',             'search component'),
    (0x3CBA32, 'HYBrowser.exe',            'registry path table'),
    (0x3CBB2E, 'HYBrowser.exe',            'uninstall entry path'),
    (0x3CBB78, 'HYBrowser.exe',            'browser probe name table'),
    (0x3DBA38, 'HYAmazingNavigation.exe',  'integrated navigation (error source)'),
]

def stub_component_names(path):
    """Neutralise hardcoded HY*.exe names with equal-length UTF-16 spaces.

    Same discipline as scrub_urls: fixed-size fill, NUL terminator preserved.
    Some callers append the original fixed length to their executable directory.
    The shell guards must reject that resulting whitespace-only filename before
    forwarding to Windows; replacing the constant alone does not disable launch.
    Two assertions keep this honest:
      1. every patch offset must sit inside a *data* section, never executable
         code -- otherwise a source-version drift could silently patch bytes
         that are machine instructions;
      2. the executable section must stay byte-identical.
    """
    before = path.read_bytes()
    data = bytearray(before)
    pe = pefile.PE(data=before)

    sections = [(s.Name.rstrip(b'\0'), s.PointerToRawData, s.SizeOfRawData,
                 s.Characteristics) for s in pe.sections]
    code_spans = [(o, sz) for nm, o, sz, ch in sections
                  if nm == b'.text' or (ch & 0x20000000)]
    if not code_spans:
        pe.close()
        raise ValueError('No executable section found in ' + str(path))

    edits = []
    for off, name, why in COMPONENT_STUBS:
        enc = name.encode('utf-16-le')
        if off + len(enc) > len(data):
            pe.close()
            raise ValueError('Component stub offset out of range: ' + name)

        # Refuse to touch executable bytes.
        for code_off, code_sz in code_spans:
            if code_off <= off < code_off + code_sz:
                pe.close()
                raise ValueError(
                    'Component stub target 0x%X (%s) lies inside executable code. '
                    'Source revision has drifted.' % (off, name))

        actual = bytes(data[off:off + len(enc)])
        if actual != enc:
            pe.close()
            raise ValueError(
                'Component stub offset mismatch for %s @0x%X (expected %r, found %r). '
                'Source revision may have drifted.' % (name, off, enc[:24], actual[:24]))
        fill = ' '.encode('utf-16-le') * len(name)
        data[off:off + len(enc)] = fill
        edits.append({'offset': hex(off), 'original': name, 'purpose': why})

    after = bytes(data)
    if len(after) != len(before):
        pe.close()
        raise ValueError('Component stub changed file length')
    for code_off, code_sz in code_spans:
        if before[code_off:code_off + code_sz] != after[code_off:code_off + code_sz]:
            pe.close()
            raise ValueError('Component stub altered executable code: ' + str(path))
    for _, name, _ in COMPONENT_STUBS:
        if name.encode('utf-16-le') in after:
            pe.close()
            raise ValueError('Component stub failed for ' + name)
    pe.close()
    path.write_bytes(after)
    return {'file': path.name, 'component_stubs': edits}

def sanitize_pe(path, redirect=True):
    before=path.read_bytes(); data=bytearray(before); pe=pefile.PE(data=before)
    changes={'file':path.name,'before_sha256':sha(before),'urls':[],'imports':[],'removed_ui_resources':[]}
    for res,off,blob in resource_zip(before,pe):
        blob,edits,removed=clean_zip(blob)
        if len(blob)>res.Size: raise ValueError('ZIPRES exceeds original slot')
        data[off:off+res.Size]=blob.ljust(res.Size,b'\0')
        # Resource readers use IMAGE_RESOURCE_DATA_ENTRY.Size. Once disabled
        # assets make the ZIP more than 64 KiB smaller, leaving the old size
        # puts the end-of-central-directory record outside zipfile's search
        # window even though the bytes themselves are valid.
        size_off=res.get_field_absolute_offset('Size')
        data[size_off:size_off+4]=struct.pack('<I',len(blob))
        changes['urls'].extend(edits)
        changes['removed_ui_resources'].extend(removed)
    for typ,rid,res in resources(pe):
        if typ.id==24:  # Manifest XML must not contain fixed-width NUL padding.
            off=pe.get_offset_from_rva(res.OffsetToData)
            blob,edits=scrub_urls(bytes(data[off:off+res.Size]),fixed_size=False,
                                  only={h['offset'] for h in url_hits(bytes(data[off:off+res.Size]))})
            if edits:
                ET.fromstring(blob)
                if len(blob)>res.Size: raise ValueError('Manifest grew')
                data[off:off+res.Size]=blob.ljust(res.Size,b' ')
                changes['urls'].extend({'resource':'manifest',**x} for x in edits)
    if redirect:
        for attr in ('DIRECTORY_ENTRY_IMPORT','DIRECTORY_ENTRY_DELAY_IMPORT'):
            for dll in getattr(pe,attr,[]):
                name=dll.dll.decode().lower()
                replacement='hcn.dll' if name in NETWORK_DLLS else 'hcg.dll' if name in GUARDED_DLLS else None
                if replacement:
                    # Both modules are shorter than original import DLL names.
                    name_rva=getattr(dll.struct,'Name',None) or dll.struct.szName
                    off=pe.get_offset_from_rva(name_rva)
                    data[off:off+len(dll.dll)]=replacement.encode().ljust(len(dll.dll),b'\0')
                    if hasattr(dll.struct,'TimeDateStamp'):
                        pos=dll.struct.get_field_absolute_offset('TimeDateStamp')
                        data[pos:pos+4]=b'\0'*4
                    changes['imports'].append({'from':name,'to':replacement,'functions':[x.name.decode() if x.name else '#'+str(x.ordinal) for x in dll.imports]})
    # Authenticode metadata contains network URLs and is invalid after patching.
    cert=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    certoff,certsize=cert.VirtualAddress,cert.Size
    data[cert.get_file_offset():cert.get_file_offset()+8]=b'\0'*8
    if 0<certoff<len(data) and certoff+certsize>=len(data):
        del data[certoff:]
    elif certsize and certoff+certsize<=len(data):
        data[certoff:certoff+certsize]=b'\0'*certsize
    # Confirm first, then rewrite only the confirmed offsets: an encoded token
    # is only actionable once its decoded form is known to hold a URL, so a
    # blind sweep would zero out incidental base64-shaped data.
    confirmed = {h['offset'] for h in url_hits(bytes(data))}
    cleaned, edits = scrub_urls(bytes(data), only=confirmed)
    changes['urls'].extend(edits)
    unresolved = url_hits(cleaned)
    if unresolved:
        raise ValueError('URL scrub left residue in %s: %s' % (path, unresolved[:3]))
    for section in pe.sections:
        if section.Characteristics & 0x20000000:
            start=section.PointerToRawData; end=start+section.SizeOfRawData
            if cleaned[start:end]!=before[start:end]:
                raise ValueError('URL scrub would alter executable instructions: '+str(path))
    pe.close()
    check=pefile.PE(data=cleaned)
    check.OPTIONAL_HEADER.CheckSum=check.generate_checksum()
    final=check.write(); check.close(); path.write_bytes(final)
    changes['after_sha256']=sha(final)
    # HY*.exe names are bare filenames, invisible to URL scrubbing. Do this after
    # the PE rewrite above so the checksum already accounts for the earlier edits.
    if path.name.lower() == 'huochat.exe':
        stub = stub_component_names(path)
        changes['component_stubs'] = stub['component_stubs']
    return changes

def collect_forwarders(folders):
    forwards={}; ordinals={}; net_ordinals={}
    for folder in folders:
        for p in pe_files(folder):
            pe=pefile.PE(str(p))
            for dll in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[]):
                lib=dll.dll.decode().lower()
                if lib in NETWORK_DLLS:
                    for imp in dll.imports:
                        if not imp.name or imp.name.decode() not in NETWORK_APIS:
                            raise ValueError(f'Unimplemented network API {lib}: {imp.name or imp.ordinal}')
                        if imp.import_by_ordinal:
                            name=imp.name.decode()
                            if imp.ordinal in net_ordinals and net_ordinals[imp.ordinal]!=name: raise ValueError('Network ordinal collision')
                            net_ordinals[imp.ordinal]=name
                if lib not in GUARDED_DLLS: continue
                for imp in dll.imports:
                    if imp.name:
                        name=imp.name.decode(); target=lib[:-4]+'.'+name
                        if name in forwards and forwards[name]!=target: raise ValueError('Export collision '+name)
                        forwards[name]=target
                    else:
                        target=lib[:-4]+'.#'+str(imp.ordinal)
                        if imp.ordinal in ordinals and ordinals[imp.ordinal]!=target: raise ValueError('Ordinal collision')
                        ordinals[imp.ordinal]=target
            pe.close()
    return forwards,ordinals,net_ordinals

def compile_guards(build,folders,env):
    forwards,ordinals,net_ordinals=collect_forwarders(folders)
    net_by_name={name:ordinal for ordinal,name in net_ordinals.items()}
    definitions=['LIBRARY hcn','EXPORTS']; code=['#define WIN32_LEAN_AND_MEAN','#include <windows.h>','#include <nb30.h>']
    for name,(size,value) in NETWORK_APIS.items():
        args=', '.join(f'ULONG_PTR a{i}' for i in range(size//4)) or 'void'
        unused=''.join(f'(void)a{i};' for i in range(size//4))
        error=5 if name.startswith(('Internet','Http','Ftp','URL','WinHttp','Netbios')) else 10013
        body=f'{unused} SetLastError({error}); return (ULONG_PTR){value}u;'
        if value<0: body=f'{unused} SetLastError({error}); return (ULONG_PTR)({value});'
        if name=='Netbios':
            body='if(a0) { ((PNCB)a0)->ncb_retcode=0x34; ((PNCB)a0)->ncb_cmd_cplt=0x34; } SetLastError(5); return 0x34;'
        code.append(f'ULONG_PTR __stdcall Deny_{name}({args}) {{ {body} }}')
        suffix=' @'+str(net_by_name[name]) if name in net_by_name else ''
        definitions.append(f'  {name}=_Deny_{name}@{size}{suffix}')
    (build/'net.c').write_text('\n'.join(code),encoding='utf-8')
    (build/'net.def').write_text('\n'.join(definitions),encoding='utf-8')
    run(['cl.exe','/nologo','/LD','/O1','/GS-','net.c','/link','/NOENTRY','/NODEFAULTLIB','kernel32.lib','/DEF:net.def','/OUT:hcn.dll','/DYNAMICBASE','/NXCOMPAT'],cwd=build,env=env)
    definitions=['LIBRARY hcg','EXPORTS']
    for name in sorted(set(forwards)|set(GUARDS)):
        target=f'_Guard_{name}@{GUARDS[name]}' if name in GUARDS else forwards[name]
        definitions.append(f'  {name}={target}')
    for ordinal,target in sorted(ordinals.items()):
        known={'shell32.#16':'shell32.ILFindLastID','shell32.#155':'shell32.ILFree','shell32.#190':'shell32.ILCreateFromPathW',
               'shlwapi.#487':'shlwapi.SHLoadIndirectString'}
        if target not in known: raise ValueError('Unreviewed ordinal forwarder '+target)
        definitions.append(f'  Ordinal{ordinal}={known[target]} @{ordinal} NONAME')
    (build/'guard.def').write_text('\n'.join(definitions),encoding='utf-8')
    run(['cl.exe','/nologo','/utf-8','/LD','/MT','/O1','/W3',SOURCE_DIR/'guard.c','/link','kernel32.lib','shell32.lib','shlwapi.lib','ole32.lib','advapi32.lib','/DEF:guard.def','/OUT:hcg.dll','/DYNAMICBASE','/NXCOMPAT'],cwd=build,env=env)
    for name in ('hcn.dll','hcg.dll'): sanitize_pe(build/name,redirect=False)
    # Exercise every generated deny export with its actual stdcall arity. This
    # catches stack/pop mistakes without loading any original application code.
    tests=[]
    for i,(name,(size,value)) in enumerate(NETWORK_APIS.items()):
        types=','.join(['ULONG_PTR']*(size//4)) or 'void'
        args=','.join(['0']*(size//4))
        tests.append(f'{{ typedef ULONG_PTR (__stdcall *FN)({types}); FN fn=(FN)GetProcAddress(net,"{name}"); CHECK(fn); CHECK(fn({args})==(ULONG_PTR)({value})); }}')
    for name in sorted(forwards): tests.append(f'CHECK(GetProcAddress(guard,"{name}")!=NULL);')
    for ordinal in ordinals: tests.append(f'CHECK(GetProcAddress(guard,(LPCSTR){ordinal})!=NULL);')
    (build/'all_exports_test.inc').write_text('\n'.join(tests),encoding='utf-8')
    (build/'forwarders.json').write_text(json.dumps({'named':forwards,'ordinals':ordinals,'guards':GUARDS},indent=2),encoding='utf-8')

def icon_from(exe, out):
    pe=pefile.PE(str(exe)); images={}; group=None
    for typ,rid,res in resources(pe):
        if typ.id==3: images[rid.id]=pe.get_data(res.OffsetToData,res.Size)
        if typ.id==14 and group is None: group=pe.get_data(res.OffsetToData,res.Size)
    if group:
        count=struct.unpack_from('<H',group,4)[0]; header=bytearray(group[:6]); pixels=[]; offset=6+count*16
        for i in range(count):
            entry=group[6+i*14:20+i*14]; ident=struct.unpack_from('<H',entry,12)[0]; payload=images[ident]
            header.extend(entry[:8]+struct.pack('<II',len(payload),offset)); pixels.append(payload); offset+=len(payload)
        out.write_bytes(bytes(header)+b''.join(pixels))
    pe.close()

def verify(folder, require_guards=True, system32=None):
    failures=[]; files=[]; exportmaps={}
    modern=(folder/'Engine/Everything.exe').exists()
    for name in ('hcn.dll','hcg.dll','hce.dll'):
        p=folder/name
        if p.exists():
            pe=pefile.PE(str(p)); exportmaps[name]={}
            for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exportmaps[name]['#'+str(symbol.ordinal)]=symbol
                if symbol.name: exportmaps[name][symbol.name.decode()]=symbol
            pe.close()
        elif require_guards and (name!='hce.dll' or modern): failures.append('Missing '+name)
    # The deny layer must cover every declared network API: a missing export
    # means an import resolves to nothing and the payload fails to load.
    if 'hcn.dll' in exportmaps and require_guards:
        missing=[n for n in NETWORK_APIS if n not in exportmaps['hcn.dll']]
        if missing: failures.append('hcn.dll missing deny exports: '+', '.join(sorted(missing)[:8]))
    if 'hcg.dll' in exportmaps and require_guards:
        missing=[n for n in GUARDS if n not in exportmaps['hcg.dll']]
        if missing: failures.append('hcg.dll missing guards: '+', '.join(sorted(missing)[:8]))
    # Forwarders must resolve against the 32-bit system view: System32 is the
    # 64-bit tree, and four Interlocked exports do not exist there.
    if system32 is None:
        windir=os.environ.get('WINDIR') or os.environ.get('SystemRoot') or r'C:\Windows'
        system32=Path(windir)/'SysWOW64' if (Path(windir)/'SysWOW64').is_dir() else Path(windir)/'System32'
    system_exports={}
    def resolves(target):
        if '.' not in target: return True
        lib, _, symbol=target.partition('.')
        if not lib.lower().endswith('.dll'):lib+='.dll'
        path=system32/lib
        if not path.exists(): return True   # not a system DLL; nothing to prove
        if path not in system_exports:
            try: pe=pefile.PE(str(path),fast_load=True)
            except pefile.PEFormatError: return True
            try:
                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
                exports={'#'+str(s.ordinal) for s in pe.DIRECTORY_ENTRY_EXPORT.symbols}
                exports|={s.name.decode() for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name}
                system_exports[path]=exports
            except AttributeError:
                return True
            finally: pe.close()
        return symbol in system_exports[path]
    for p in sorted(folder.rglob('*')):
        if not p.is_file(): continue
        data=p.read_bytes(); rel=str(p.relative_to(folder))
        # The signed upstream engine is checked byte-for-byte, never scrubbed.
        if is_official_engine(p,folder):
            files.append({'path':rel,'size':len(data),'sha256':sha(data)});continue
        hits=url_hits(data)
        if hits: failures.append(f'{rel}: {len(hits)} URL(s), first={hits[0]}')
        files.append({'path':rel,'size':len(data),'sha256':sha(data)})
        if data[:2]!=b'MZ': continue
        pe=pefile.PE(data=data)
        is_guard=p.name in ('hcn.dll','hcg.dll','hce.dll','HuoChat_launcher.exe','hc_engine.exe')
        for attr in ('DIRECTORY_ENTRY_IMPORT','DIRECTORY_ENTRY_DELAY_IMPORT'):
            for dll in getattr(pe,attr,[]):
                lib=dll.dll.decode().lower()
                if lib in NETWORK_DLLS: failures.append(f'{rel}: network import {lib}')
                if require_guards and not is_guard and lib in GUARDED_DLLS: failures.append(f'{rel}: unguarded import {lib}')
                if lib in exportmaps:
                    for imp in dll.imports:
                        name=imp.name.decode() if imp.name else '#'+str(imp.ordinal)
                        if name not in exportmaps[lib]: failures.append(f'{rel}: unresolved {lib}!{name}')
                if require_guards and modern and p.name in ('HuoChat.exe','Everything32.dll'):
                    if any(imp.name==b'FindWindowW' for imp in dll.imports) and lib!='hce.dll':
                        failures.append(f'{rel}: engine window lookup bypasses the instance bridge')
        # Every hcg forwarder must point at an export that really exists in the
        # 32-bit system DLL, otherwise loading hcg fails and the app never starts.
        if p.name in ('hcg.dll','hce.dll'):
            try: pe=pefile.PE(str(p))
            except pefile.PEFormatError: pe=None
            if pe:
                try:
                    for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        fwd=getattr(symbol,'forwarder',None)
                        if not fwd: continue
                        target=fwd.decode() if isinstance(fwd,bytes) else str(fwd)
                        if not resolves(target):
                            failures.append(f'{rel}: forwarder {target} missing in system DLL')
                finally: pe.close()
        for _,_,blob in resource_zip(data,pe):
            with zipfile.ZipFile(io.BytesIO(blob)) as z:
                stale=REMOVED_UI_RESOURCES & set(z.namelist())
                if stale: failures.append(f'{rel}: stale disabled UI resources: {sorted(stale)[:8]}')
                if GUIDE_GIFS - set(z.namelist()): failures.append(f'{rel}: guide resources missing')
                for item in z.infolist():
                    value=z.read(item)
                    if item.filename in GUIDE_GIFS:
                        with Image.open(io.BytesIO(value)) as guide:
                            if guide.format != 'GIF' or guide.size != (1000, 600) or guide.n_frames != 1:
                                failures.append(f'{rel}: invalid compact guide {item.filename}')
                    if url_hits(value): failures.append(f'{rel}!{item.filename}: embedded URL')
                    if item.filename.lower().endswith('.xml'): ET.fromstring(value)
        for typ,rid,res in resources(pe):
            if typ.id==24: ET.fromstring(pe.get_data(res.OffsetToData,res.Size).rstrip(b'\0 '))
        pe.close()
    for forbidden in ('web','plugins','shot.dll','user data/config','user data/tam/config',
                      'HuoChat/user data/config','HuoChat/user data/tam/config'):
        if (folder/forbidden).exists(): failures.append('Forbidden opaque/network component: '+forbidden)
    data_root=folder/'Data'
    if any((folder/name).exists() for name in ('site.db','user data','HuoChat','Everything.ini')):
        failures.append('Legacy seed data remains outside Data')
    if not (data_root/'Sites.db').exists() or not (data_root/'HuoChat'/'user data'/'resource').is_dir():
        failures.append('Portable HuoChat seed data is incomplete')
    if (data_root/'Sites.db').exists():
        con=sqlite3.connect((data_root/'Sites.db').resolve().as_uri()+'?mode=ro&immutable=1',uri=True)
        for table in ('bookmark','top_site'):
            if con.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]: failures.append('Nonempty '+table)
        con.close()
    if (data_root/'Index.ini').exists():
        ini=(data_root/'Index.ini').read_text(encoding='utf-8-sig')
        for key in ('check_for_updates_on_startup','beta_updates','http_server_enabled','etp_server_enabled','allow_http_server','allow_etp_server'):
            if not re.search(r'^'+key+r'=0\s*$',ini,re.M): failures.append('Unsafe setting '+key)
    if failures: raise ValueError('\n'.join(failures))
    return {'pass':True,'file_count':len(files),'files':files,'checked':f'ASCII/UTF16 URLs, nested ZIPRES, 3 compact guides, {len(REMOVED_UI_RESOURCES)} removed UI resources, manifests, imports/exports, configs, stripped components'}

def prepare(source, dest):
    dest.mkdir(parents=True)
    allowed=['HuoChat.exe','hc_engine.exe','Everything32.dll','sqlite3.dll','msvcp120.dll','msvcr120.dll','Everything.ini','duilib license.txt','everything license.txt']
    for name in allowed: shutil.copy2(source/name,dest/name)
    prepare_sdk(dest)
    data_root=dest/'Data'; data_root.mkdir()
    shutil.copy2(source/'site.db',data_root/'Sites.db')
    # Keep local note backgrounds and the default skin. The removed web engine's
    # error HTML/JPEG are no longer useful and are omitted from new installs.
    shutil.copytree(source/'user data'/'resource',data_root/'HuoChat'/'user data'/'resource')
    navigation=data_root/'User'/'tam';navigation.mkdir(parents=True)
    (navigation/'config').write_bytes(clean_navigation_layout((source/'user data'/'tam'/'config').read_bytes()))
    # Opaque user config is deliberately not shipped; defaults will be regenerated.
    con=sqlite3.connect(data_root/'Sites.db')
    for table in ('bookmark','top_site'): con.execute(f'DELETE FROM {table}')
    con.commit(); con.execute('VACUUM'); con.close()
    ini=(dest/'Everything.ini').read_text(encoding='utf-8-sig')
    for key in ('check_for_updates_on_startup','beta_updates','http_server_enabled','etp_server_enabled','allow_http_server','allow_etp_server','etp_server_allow_file_download','http_server_allow_file_download','ftp_allow_port'):
        ini=re.sub(r'^'+key+r'=.*$',key+'=0',ini,flags=re.M) if re.search(r'^'+key+'=',ini,re.M) else ini+'\n'+key+'=0\n'
    for key in ('index_etp_server','connect_history_hosts','connect_history_ports','connect_history_usernames','folders','filelists'):
        ini=re.sub(r'^'+key+r'=.*$',key+'=',ini,flags=re.M)
    (data_root/'Index.ini').write_text(ini,encoding='utf-8')
    (dest/'Everything.ini').unlink()

def verify_windows_manifests(folder,build,variant):
    paths=[]; directory=build/(variant+'-manifests'); directory.mkdir()
    for p in pe_files(folder):
        if is_official_engine(p,folder):continue # x64 manifest is checked with the signed upstream hash
        pe=pefile.PE(str(p))
        for typ,rid,res in resources(pe):
            if typ.id==24:
                path=directory/(p.name+'.xml')
                path.write_bytes(pe.get_data(res.OffsetToData,res.Size).rstrip(b'\0 ')); paths.append(path)
        pe.close()
    print(run([build/'test_manifests.exe',*paths],cwd=build).decode('utf-8','replace'),flush=True)

def package(folder, build, variant, compiler, icon, identity='HuoChatOffline'):
    immutable = sorted(p for p in folder.rglob('*') if p.is_file() and
        (p.parent==folder and p.name!='Everything.ini' or p.relative_to(folder).parts[0]=='Engine' and p.suffix.lower() in ('.exe','.dll')))
    seeds = sorted(p for p in folder.rglob('*') if p.is_file() and p not in immutable)
    inventory = [(p.relative_to(folder).as_posix(), sha(p.read_bytes())) for p in immutable + seeds]
    package_id = sha(json.dumps(inventory, ensure_ascii=True).encode())
    def nsis_path(p):
        return str(p).replace('$', '$$').replace('"', '$\\"')
    def checks(files, target):
        lines=[]
        for p in files:
            rel=nsis_path(p.relative_to(folder))
            lines += [f'StrCpy $HashFile "$INSTDIR\\{rel}"', 'Call SHA256',
                      f'StrCmp $HashResult "{sha(p.read_bytes())}" 0 {target}']
        return '\n '.join(lines)
    def file_commands(files):
        lines=[]
        for p in files:
            rel=p.relative_to(folder)
            parent='' if rel.parent == Path('.') else '\\'+nsis_path(rel.parent)
            lines += [f'SetOutPath "$EXEDIR\\HuoChatOffline-v1-{variant}{parent}"', f'File "{nsis_path(p)}"']
        return '\n '.join(lines)
    # Keep the trusted hashing plugin before the solid payload stream.
    plugins=build/'nsis-plugins'; plugins.mkdir(exist_ok=True)
    plugin=plugins/'System.dll'
    shutil.copy2(compiler.parent/'Plugins'/'x86-unicode'/'System.dll', plugin)
    sanitize_pe(plugin, redirect=False)
    replacements={
        '@OUTFILE@':nsis_path(build/(variant+'.exe')), '@ICON@':nsis_path(icon),
        '@PLUGINS@':nsis_path(plugins), '@VARIANT@':variant, '@PACKAGE_ID@':package_id,
        '@IDENTITY@':identity,
        '@ASSERT_SILENT@':('' if identity=='HuoChatOffline' else
            'IfSilent silent_ok\n SetErrorLevel 91\n Quit\n silent_ok:'),
        '@CACHE_CHECKS@':checks(immutable,'repair'),
        '@VERIFY_CHECKS@':checks(immutable,'failed'),
        '@IMMUTABLE_FILES@':file_commands(immutable),
        '@SEED_FILES@':file_commands(seeds),
        '@SEED_CHECKS@':'\n '.join(f'IfFileExists "$INSTDIR\\{nsis_path(p.relative_to(folder))}" +2 0\n Goto seeds' for p in seeds),
    }
    script=(SOURCE_DIR/'package.nsi').read_text(encoding='utf-8')
    for key,value in replacements.items(): script=script.replace(key,value)
    nsi=build/(variant+'.nsi'); nsi.write_text(script,encoding='utf-8-sig')
    run([compiler,'/V2',nsi])
    exe=build/(variant+'.exe')
    original=exe.read_bytes()
    if struct.unpack_from('<I',original,len(original)-4)[0]!=(zlib.crc32(original[512:-4])&0xffffffff):
        raise ValueError('Unexpected NSIS CRC format')
    # Compiler stub also embeds an NSIS help URL. Clean it and refresh its CRC.
    sanitize_pe(exe,redirect=False)
    data=bytearray(exe.read_bytes()); data[-4:]=struct.pack('<I',zlib.crc32(data[512:-4])&0xffffffff)
    pe=pefile.PE(data=bytes(data)); pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum(); data=pe.write(); pe.close()
    if struct.unpack_from('<I',data,len(data)-4)[0]!=(zlib.crc32(data[512:-4])&0xffffffff):
        raise ValueError('NSIS CRC mismatch after sanitizing')
    exe.write_bytes(data)
    return exe

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--publish','--publish-single',dest='publish',action='store_true',
                    help='Replace the root single-file package after final verification')
    ap.add_argument('--keep-workdir',action='store_true',
                    help='Retain the temporary build directory and verification evidence')
    ap.add_argument('--verify',type=Path,help='Check an already extracted payload; never launches it')
    args=ap.parse_args()
    if args.verify:
        print(json.dumps(verify(args.verify),ensure_ascii=True,indent=2)); return
    seven=Path(r'C:\Program Files\7-Zip\7z.exe'); nsis=Path(r'C:\Program Files (x86)\NSIS\makensis.exe')
    # The static deny list and the runtime list in guard.c must agree.
    check_policy_parity()
    build=Path(tempfile.mkdtemp(prefix='huochai_offline_build_'))
    if not args.keep_workdir:
        atexit.register(cleanup_build_dir, build)
    print('Build directory:',build,flush=True)
    folders={}; originals={}
    for variant,(filename,expected) in SOURCES.items():
        data=run(['git','show',SOURCE_REV+':'+filename],cwd=ROOT)
        if sha(data)!=expected: raise ValueError('Pinned source hash mismatch')
        archive=build/(variant+'-source.exe'); archive.write_bytes(data); originals[variant]=archive
        extract(archive,build/(variant+'-source'),seven)
        source=next((build/(variant+'-source')).rglob('HuoChat.exe')).parent
        folder=build/(variant+'-files'); prepare(source,folder); folders[variant]=folder
    # The earlier single-file patch inserted NULs into an SQL string. Restore
    # only that constant from the same green binary before safe URL rewriting.
    single_main=folders['single']/'HuoChat.exe'; a=bytearray(single_main.read_bytes()); b=(folders['green']/'HuoChat.exe').read_bytes()
    prefix=b'insert into top_site(site_name, site_url,'
    pos=b.find(prefix)
    if pos<0 or a[pos:pos+len(prefix)]!=prefix: raise ValueError('SQL baseline mismatch')
    end=b.index(b'\0',pos)+1; a[pos:end]=b[pos:end]; single_main.write_bytes(a)
    env=compiler_env(); compile_guards(build,[folders['single']],env)
    compile_adapters(build,env,run,SOURCE_DIR,folders['single']/'HuoChat.exe')
    for name in ('hce.dll','hc_engine.exe'):sanitize_pe(build/name,redirect=False)
    run(['cl.exe','/nologo','/utf-8','/MT','/O1','/W4',SOURCE_DIR/'launcher.c','/link','kernel32.lib','advapi32.lib','user32.lib','/SUBSYSTEM:WINDOWS','/OUT:HuoChat_launcher.exe'],cwd=build,env=env)
    sanitize_pe(build/'HuoChat_launcher.exe',redirect=False)
    # Test only newly authored guard DLLs in our own harness, never original modules.
    run(['cl.exe','/nologo','/MT','/O1','/I'+str(build),SOURCE_DIR/'test_guards.c','/link','kernel32.lib','/OUT:test_guards.exe'],cwd=build,env=env)
    run(['cl.exe','/nologo','/MT','/O1',SOURCE_DIR/'test_shell_targets.c','/link','kernel32.lib','shell32.lib','/OUT:test shell targets.exe'],cwd=build,env=env)
    # Spawn guard: local helpers must start, browser/remote targets must not.
    spawn=(build/'spawn'); spawn.mkdir(exist_ok=True)
    shutil.copy2(build/'hcg.dll',spawn/'hcg.dll')
    run(['cl.exe','/nologo','/MT','/O1','/I'+str(build),SOURCE_DIR/'test_spawn_guard.c','/link','kernel32.lib',f'/OUT:{spawn}\\test_spawn_guard.exe'],cwd=spawn,env=env)
    print(run([spawn/'test_spawn_guard.exe'],cwd=spawn).decode('utf-8','replace'),flush=True)
    run(['cl.exe','/nologo','/MT','/O1',SOURCE_DIR/'test_manifests.c','/link','kernel32.lib','/OUT:test_manifests.exe'],cwd=build,env=env)
    print(run([build/'test_guards.exe'],cwd=build).decode('utf-8','replace'),flush=True)
    print(run([build/'test shell targets.exe'],cwd=build).decode('utf-8','replace'),flush=True)
    run(['cl.exe','/nologo','/utf-8','/MT','/O1',SOURCE_DIR/'test_local_paths.c',
         '/link','kernel32.lib','/OUT:test_local_paths.exe'],cwd=build,env=env)
    print(run([build/'test_local_paths.exe'],cwd=build).decode('utf-8','replace'),flush=True)
    run(['cl.exe','/nologo','/utf-8','/MT','/O1',SOURCE_DIR/'test_service_cleanup.c',
         '/link','kernel32.lib','advapi32.lib','user32.lib','/OUT:test_service_cleanup.exe'],cwd=build,env=env)
    print(run([build/'test_service_cleanup.exe'],cwd=build).decode('utf-8','replace'),flush=True)
    publication=['single'] if args.publish else []
    report={'source_revision':SOURCE_REV,'published_variants':publication,
            'original_targets_executed':True,
            'guard_harness_executed':True,'shell_target_harness_executed':True,'local_path_harness_executed':True,
            'engine':{'version':ENGINE_VERSION,'architecture':'x64','signed_upstream_sha256':ENGINE_SHA256},
            'portable_layout':{'system_localappdata_junction':False,
                'index':'HuoChatOffline-v1-<variant>/Data/Index-1.5',
                'user_data':'HuoChatOffline-v1-<variant>/Data/User',
                'external_app_data':'unchanged caller APPDATA/LOCALAPPDATA/TEMP/TMP; legacy Data/Apps retained'},
            'removed_ui_resource_count':len(REMOVED_UI_RESOURCES),'variants':{}}
    from migration_checks import verify_migration
    from startup_checks import verify_startup
    report['migration_checks']=verify_migration(build,env,run,SOURCE_DIR)
    report['startup_checks']=verify_startup(build,env,run,SOURCE_DIR)
    from environment_release_checks import verify_environment_release
    report['environment_release_checks']=verify_environment_release(build,env,run,SOURCE_DIR)
    for variant in ('single',):
        folder=folders[variant]
        edits=[]
        for p in pe_files(folder): edits.append(sanitize_pe(p))
        route_windows(folder/'Everything32.dll')
        route_windows(folder/'HuoChat.exe')
        relocate_data_paths(folder/'HuoChat.exe')
        run(['cl.exe','/nologo','/utf-8','/TP','/MT','/O1',SOURCE_DIR/'test_settings_webview.c',
             '/link','kernel32.lib','user32.lib','/BASE:0x10000000','/DYNAMICBASE:NO',
             '/OUT:test_settings_webview.exe'],cwd=build,env=env)
        print(run([build/'test_settings_webview.exe',folder/'HuoChat.exe','expect-crash'],cwd=build).decode(),flush=True)
        disable_settings_webview(folder/'HuoChat.exe')
        print(run([build/'test_settings_webview.exe',folder/'HuoChat.exe','expect-pass'],cwd=build).decode(),flush=True)
        report['settings_webview_checks']=['original null web entry crash reproduced',
            'native settings routine safe with absent web engine; x86 argument cleanup preserved']
        # Exercise the real model and serializer after their original CRT init;
        # only WinMain and non-config teardown are substituted in the fixture.
        # Copy guards first so the isolated native host keeps offline imports.
        for name in ('hcg.dll','hcn.dll','hce.dll'):
            shutil.copy2(build/name,folder/name)
        from settings_checks import verify_settings
        report['settings_persistence_checks']=verify_settings(build,folder,env,run,SOURCE_DIR)
        report['original_settings_model_executed']=True
        save_before_shutdown(folder/'HuoChat.exe')
        for p in folder.rglob('*'):
            if p.is_file() and p.suffix.lower() not in ('.exe','.dll','.db'):
                text=p.suffix.lower() in ('.xml','.html','.htm','.js','.css','.json','.txt','.ini','.hyjs')
                original=p.read_bytes(); clean,hits=scrub_urls(original,fixed_size=not text,
                    only={h['offset'] for h in url_hits(original)})
                if hits: p.write_bytes(clean); edits.append({'file':str(p.relative_to(folder)),'urls':hits})
        for name in ('hcn.dll','hcg.dll','HuoChat_launcher.exe'): shutil.copy2(build/name,folder/name)
        from engine_checks import verify_engine
        report['engine_checks']=verify_engine(folder,build,env,run,SOURCE_DIR)
        from checkpoint_checks import verify_checkpoints
        report['checkpoint_checks']=verify_checkpoints(folder,build,env,run,SOURCE_DIR)
        install_engine(folder,build)
        from backend_checks import verify_backend
        report['backend_checks']=verify_backend(folder,build,env,run,SOURCE_DIR)
        report['original_engine_executed']=True
        report['original_main_application_executed']=False
        before=verify(folder)
        verify_windows_manifests(folder,build,variant)
        icon=build/(variant+'.ico'); icon_from(originals[variant],icon)
        from backend_package_checks import verify_backend_package
        report['backend_package_checks']=verify_backend_package(folder,build,env,run,SOURCE_DIR,package,nsis,icon)
        from shutdown_checks import verify_shutdown
        report['shutdown_checks']=verify_shutdown(build,env,nsis,icon,package,run,SOURCE_DIR)
        from runtime_checks import verify_runtime
        report['runtime_checks']=verify_runtime(build,env,nsis,icon,package,run,SOURCE_DIR)
        exe=package(folder,build,variant,nsis,icon)
        if url_hits(exe.read_bytes()): raise ValueError('Outer package contains URL')
        extracted=build/(variant+'-final'); extract(exe,extracted,seven)
        final=next(extracted.rglob('HuoChat.exe')).parent
        after=verify(final)
        if before['files']!=after['files']: raise ValueError('Packaged payload changed')
        if any(p.name.lower()=='nsexec.dll' for p in extracted.rglob('*')):
            raise ValueError('Final package still carries the obsolete nsExec junction helper')
        for p in extracted.rglob('*'):
            if p.is_relative_to(final) and is_official_engine(p,final):continue
            if p.is_file() and url_hits(p.read_bytes()): raise ValueError('URL in final archive member '+str(p))
        report['variants'][variant]={'archive':str(exe),'sha256':sha(exe.read_bytes()),'size':exe.stat().st_size,'verification':after,'changes':edits}
        print(variant+': final package verified',flush=True)
    report['root_artifacts']={variant:{
        'path':SOURCES[variant][0],
        'size':report['variants'][variant]['size'],
        'sha256':report['variants'][variant]['sha256']}
        for variant in publication}
    (build/'verification.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    # No publication happens before the final single-file package passes.
    if args.publish:
        publish_variants=['single']
        for variant in publish_variants:
            filename,_=SOURCES[variant]
            backup=build/(variant+'-previous-root.exe'); shutil.copy2(ROOT/filename,backup)
        for variant in publish_variants:
            filename,_=SOURCES[variant]
            temporary=ROOT/(filename+'.new'); shutil.copy2(build/(variant+'.exe'),temporary); os.replace(temporary,ROOT/filename)
        print('Published verified package(s): '+', '.join(publish_variants),flush=True)
    if args.keep_workdir:
        print('Retained evidence:',build/'verification.json',flush=True)
    else:
        print('Verification complete; temporary build files will be removed.',flush=True)

if __name__=='__main__':
    main()
