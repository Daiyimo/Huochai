"""Re-extract ROOT packages and independently scan strings. No target execution."""
from pathlib import Path
import hashlib
import io
import json
import re
import struct
import zlib
import zipfile
import pefile
import build

URL = re.compile(r'(?i)\b(?:https?|ftps?|wss?|ldap|smb|gopher)://[^\s\x00<>"\x27]+|\bwww\.[a-z0-9.-]+\.[a-z]{2,}')

def matches(data):
    found=[]
    for pattern,encoding in [(rb'[\x20-\x7e]{5,}','ascii'),(rb'(?:[\x20-\x7e]\0){5,}','utf-16le')]:
        for m in re.finditer(pattern,data): found.extend(URL.findall(m.group().decode(encoding)))
    return found

def main():
    record_path=build.ROOT/'offline'/'verification.json'
    record=json.loads(record_path.read_text(encoding='utf-8'))
    folder=Path(record['variants']['single']['archive']).parent
    checks=[]
    for variant,(name,_) in build.SOURCES.items():
        archive=build.ROOT/name; data=archive.read_bytes()
        digest=hashlib.sha256(data).hexdigest()
        if digest!=record['variants'][variant]['sha256']: raise ValueError('Root archive hash mismatch')
        if struct.unpack_from('<I',data,len(data)-4)[0]!=(zlib.crc32(data[512:-4])&0xffffffff): raise ValueError('NSIS CRC mismatch')
        dest=folder/(variant+'-root-recheck')
        if dest.exists(): raise ValueError('Choose a fresh build for independent verification; will not overwrite evidence')
        build.extract(archive,dest,Path(r'C:\Program Files\7-Zip\7z.exe'))
        payload=next(dest.rglob('HuoChat.exe')).parent
        checked=build.verify(payload)
        residual=[]; pe_count=0; zip_count=0
        for p in [archive]+[p for p in dest.rglob('*') if p.is_file()]:
            blob=p.read_bytes(); hits=matches(blob)
            if hits: residual.append({'path':str(p),'urls':hits})
            if blob[:2]!=b'MZ': continue
            pe_count+=1; pe=pefile.PE(data=blob)
            for _,_,zipdata in build.resource_zip(blob,pe):
                with zipfile.ZipFile(io.BytesIO(zipdata)) as z:
                    for item in z.infolist():
                        zip_count+=1; hits=matches(z.read(item))
                        if hits: residual.append({'path':str(p)+'!'+item.filename,'urls':hits})
            pe.close()
        if residual: raise ValueError(json.dumps(residual,ensure_ascii=False))
        checks.append({'variant':variant,'root_sha256':digest,'independent_url_matches':0,'pe_files_including_wrapper':pe_count,'zipres_members':zip_count,'payload_files':checked['file_count'],'nsis_crc_ok':True,'application_started':False})
    record['post_publication_independent_checks']=checks
    record_path.write_text(json.dumps(record,ensure_ascii=False,indent=2),encoding='utf-8')
    (folder/'independent_checks.json').write_text(json.dumps(checks,indent=2),encoding='utf-8')
    print(json.dumps(checks,ensure_ascii=False,indent=2))

if __name__=='__main__': main()
