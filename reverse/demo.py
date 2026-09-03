"""Build an authored PE/import-hook/URL-cleaning demo without third-party binaries."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import pefile
from build import compiler_env, run
from build_inputs import ROOT, private_output
from policy import scrub_urls, url_hits


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=ROOT/'.local/demo')
    args = parser.parse_args()
    output = private_output(args.output_dir)
    source = Path(__file__).resolve().parent
    env = compiler_env()
    with tempfile.TemporaryDirectory(prefix='huochai_teaching_demo_') as directory:
        work = Path(directory)
        original = work/'demo-original.exe'
        run(['cl.exe', '/nologo', '/utf-8', '/MT', '/O1', source/'demo_fixture.c',
             '/link', 'kernel32.lib', '/OUT:'+str(original)], cwd=work, env=env)
        baseline = run([original, 'original'], cwd=work).decode().strip()
        raw = original.read_bytes()
        pe = pefile.PE(data=raw)
        try:
            imports = [d for d in pe.DIRECTORY_ENTRY_IMPORT if d.dll.lower() == b'kernel32.dll']
            if len(imports) != 1:
                raise ValueError('Fixture import layout changed')
            library = imports[0]
            if any(i.name is None for i in library.imports):
                raise ValueError('Fixture unexpectedly imports an ordinal')
            names = sorted({i.name.decode() for i in library.imports})
            assert 'GetTickCount' in names
            offset = pe.get_offset_from_rva(library.struct.Name)
            capacity = len(library.dll)+1
        finally:
            pe.close()
        definition = work/'demo.def'
        definition.write_text('LIBRARY demohook\nEXPORTS\n'+'\n'.join(
            name+'='+('_DemoGetTickCount@0' if name == 'GetTickCount' else 'KERNEL32.'+name)
            for name in names)+'\n', encoding='ascii')
        run(['cl.exe', '/nologo', '/utf-8', '/LD', '/MT', '/O1', source/'demo_hook.c',
             '/link', 'kernel32.lib', '/DEF:'+str(definition), '/OUT:'+str(work/'demohook.dll')],
            cwd=work, env=env)
        confirmed = {hit['offset'] for hit in url_hits(raw)}
        cleaned, edits = scrub_urls(raw, fixed_size=True, only=confirmed)
        assert edits and len(cleaned) == len(raw) and not url_hits(cleaned)
        checked = pefile.PE(data=cleaned)
        try:
            remaining = next(d for d in checked.DIRECTORY_ENTRY_IMPORT if d.dll.lower() == b'kernel32.dll')
            assert sorted(i.name.decode() for i in remaining.imports) == names
        finally:
            checked.close()
        patched = bytearray(cleaned)
        replacement = b'demohook.dll\0'
        assert len(replacement) <= capacity
        patched[offset:offset+capacity] = replacement.ljust(capacity, b'\0')
        pe = pefile.PE(data=patched)
        try:
            pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
            patched = pe.write()
        finally:
            pe.close()
        assert len(patched) == len(raw)
        destination = work/'demo-patched.exe'
        destination.write_bytes(patched)
        result = run([destination, 'patched'], cwd=work).decode().strip()
        report = {'pass': True, 'fixture': 'authored source only', 'before': baseline, 'after': result,
                  'checks': ['fixed-size URL rewrite', 'PE import redirection', 'actual API hook execution'],
                  'artifacts': {name: hashlib.sha256((work/name).read_bytes()).hexdigest()
                                for name in ('demo-original.exe', 'demo-patched.exe', 'demohook.dll')}}
        output.mkdir(parents=True, exist_ok=True)
        for name in report['artifacts']:
            shutil.copy2(work/name, output/name)
        (output/'verification.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
