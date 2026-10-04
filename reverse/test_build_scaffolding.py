"""Regression tests for the build scaffolding's fail-closed guards.

These cover the module-level invariants that used to be enforced only by
convention: import-name slot lengths, net.def ordinals, the launcher's kernel
object names, the guide size rule, and the PE icon reader. Each test drives the
real function, so a regression fails here instead of in the middle of a build.

Run: python -m unittest discover -s reverse -p "test_*.py" -v
"""
import io
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

import pefile
from PIL import Image

import build
from build import (GUARDS, INTENTIONALLY_ABSENT, NETWORK_APIS, NETWORK_DLLS,
                   check_policy_parity, compact_guide_gif, guard_intercept_names,
                   guard_module_names, icon_from, isolated_definition_source,
                   isolated_definitions, net_export_ordinals, sanitize_pe)

SOURCE_DIR = Path(build.__file__).resolve().parent


# --------------------------------------------------------------------------
# A minimal PE32 with one import descriptor, for the import-rewrite rules.
# --------------------------------------------------------------------------
PE_OFF = 0x80


def write_import_pe(path, dll_name):
    """Write a parseable PE whose single import descriptor names ``dll_name``."""
    data = bytearray(b'MZ' + b'\0' * 0x3a + struct.pack('<I', PE_OFF))
    data.extend(b'\0' * (PE_OFF - len(data)))
    data += b'PE\0\0'
    data += struct.pack('<HHIIIHH', 0x14c, 2, 0, 0, 0, 0xe0, 0x102)
    optional = bytearray(0xe0)
    struct.pack_into('<H', optional, 0, 0x10b)          # PE32
    struct.pack_into('<I', optional, 0x04, 0x200)       # SizeOfCode
    struct.pack_into('<I', optional, 0x08, 0x200)       # SizeOfInitializedData
    struct.pack_into('<I', optional, 0x10, 0x1000)      # AddressOfEntryPoint
    struct.pack_into('<I', optional, 0x1C, 0x400000)    # ImageBase
    struct.pack_into('<I', optional, 0x20, 0x1000)      # SectionAlignment
    struct.pack_into('<I', optional, 0x24, 0x200)       # FileAlignment
    struct.pack_into('<I', optional, 0x38, 0x3000)      # SizeOfImage
    struct.pack_into('<I', optional, 0x3C, 0x200)       # SizeOfHeaders
    struct.pack_into('<H', optional, 0x44, 3)           # Subsystem
    struct.pack_into('<I', optional, 0x5C, 16)          # NumberOfRvaAndSizes
    data += optional
    # .text raw data fills 0x200..0x400; .idata raw data follows at 0x400.
    data += (b'.text\0\0\0' + struct.pack('<IIIIIIHHI', 0x200, 0x1000, 0x200, 0x200,
                                          0, 0, 0, 0, 0x60000020))
    data += (b'.idata\0\0' + struct.pack('<IIIIIIHHI', 0x200, 0x2000, 0x200, 0x400,
                                         0, 0, 0, 0, 0xC0000040))
    data.extend(b'\0' * (0x400 - len(data)))

    body = bytearray(0x200)
    name, hint, ilt, iat = 0x040, 0x050, 0x028, 0x030
    struct.pack_into('<IIIII', body, 0, 0x2000 + ilt, 0, 0, 0x2000 + name, 0x2000 + iat)
    struct.pack_into('<I', body, ilt, 0x2000 + hint)
    body[name:name + len(dll_name) + 1] = dll_name + b'\0'
    body[hint:hint + 2] = b'\0\0'
    body[hint + 2:hint + 12] = b'SampleExport\0'
    data.extend(body)

    # DataDirectory[1] (import) points at the single descriptor.
    struct.pack_into('<II', data, PE_OFF + 4 + 20 + 0x60 + 8, 0x2000, 40)
    path.write_bytes(bytes(data))
    return path


class ImportRewriteTests(unittest.TestCase):
    """The rewrite of an import DLL name is a fixed-size in-place edit."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='import_rewrite_'))
        self.network = build.NETWORK_DLLS

    def tearDown(self):
        build.NETWORK_DLLS = self.network
        shutil.rmtree(self.tmp, ignore_errors=True)

    def sanitize(self, dll_name, listing):
        p = write_import_pe(self.tmp / 'sample.exe', dll_name)
        before = p.read_bytes()
        build.NETWORK_DLLS = listing
        try:
            report = sanitize_pe(p)
        finally:
            build.NETWORK_DLLS = self.network
        return before, p.read_bytes(), report

    def test_short_replacement_is_refused_instead_of_shifting_the_file(self):
        # "hcn.dll" is seven bytes; a six-byte module name cannot hold it. The
        # equal-length slice assignment would otherwise become an insertion.
        p = write_import_pe(self.tmp / 'sample.exe', b'ab.dll')
        before = p.read_bytes()
        build.NETWORK_DLLS = {'ab.dll'}
        try:
            with self.assertRaises(ValueError) as caught:
                sanitize_pe(p)
        finally:
            build.NETWORK_DLLS = self.network
        self.assertIn('too long', str(caught.exception))
        self.assertEqual(before, p.read_bytes(),
                         'a refused rewrite must not modify the file')

    def test_the_old_expression_actually_grew_the_file(self):
        """Proof the guard binds: the pre-fix one-liner shifted every later byte."""
        p = write_import_pe(self.tmp / 'sample.exe', b'ab.dll')
        raw = p.read_bytes()
        pe = pefile.PE(data=raw)
        off = pe.get_offset_from_rva(pe.DIRECTORY_ENTRY_IMPORT[0].struct.Name)
        pe.close()
        grown = bytearray(raw)
        grown[off:off + 6] = b'hcn.dll'.ljust(6, b'\0')
        self.assertGreater(len(grown), len(raw))
        pe = pefile.PE(data=bytes(grown))
        try:
            self.assertFalse(hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'),
                             'the shifted file must no longer parse as an import table')
        finally:
            pe.close()

    def test_a_name_that_fits_is_still_rewritten_in_place(self):
        before, after, report = self.sanitize(b'abcdefgh.dll', {'abcdefgh.dll'})
        self.assertEqual([('abcdefgh.dll', 'hcn.dll')],
                         [(x['from'], x['to']) for x in report['imports']])
        self.assertEqual(len(before), len(after))
        self.assertIn(b'hcn.dll\0', after)


class NetExportOrdinalTests(unittest.TestCase):
    """The harness and net.def must number the same exports the same way."""

    def test_ordinals_follow_the_def_file_order(self):
        ordinals = net_export_ordinals({})
        self.assertEqual(len(NETWORK_APIS), len(ordinals))
        self.assertEqual(sorted(ordinals.values()),
                         list(range(1, len(NETWORK_APIS) + 1)))
        # The two names the guard harness probes by ordinal. ws2_32's real
        # numbers (111 and 23) are not ordinals a 103-export hcn.dll can carry.
        self.assertEqual(1, ordinals['WSAGetLastError'])
        self.assertEqual(5, ordinals['socket'])

    def test_an_ordinal_the_source_binaries_already_use_is_kept(self):
        ordinals = net_export_ordinals({'socket': 23})
        self.assertEqual(23, ordinals['socket'])
        self.assertEqual(1, ordinals['WSAGetLastError'])

    def test_reordering_the_apis_moves_the_ordinals_with_it(self):
        """Whatever order net.def is written in is the order the harness reads."""
        first = list(NETWORK_APIS)[0]
        build.NETWORK_APIS = dict(reversed(list(NETWORK_APIS.items())))
        try:
            self.assertEqual(len(NETWORK_APIS), net_export_ordinals({})[first])
        finally:
            build.NETWORK_APIS = NETWORK_APIS


class IsolatedDefinitionTests(unittest.TestCase):
    """Every test family would isolate itself from production on a rename."""

    def test_the_packaged_family_matches_package_nsi(self):
        """package.nsi opens the launcher mutex and stopping event by name."""
        script = (SOURCE_DIR / 'package.nsi').read_text(encoding='utf-8')
        wanted = isolated_definitions('ID', 'Root', True)
        for key in ('mutex', 'ready', 'stop'):
            name = wanted[key]
            self.assertTrue(name.startswith('Local\\'), name)
            suffix = name[len('Local\\ID'):]
            self.assertIn('Local\\@IDENTITY@' + suffix, script,
                          'package.nsi no longer opens ' + name)
        # The startup key is a registry path, not a kernel object.
        self.assertIn('Software\\Root\\ID', wanted['startup'])

    def test_the_two_families_stay_distinct_and_stable(self):
        identity = 'deadbeef'
        direct = isolated_definition_source(identity, 'Root', False)
        packaged = isolated_definition_source(identity, 'Root', True)
        for macro in ('HUOCHAT_LAUNCHER_MUTEX', 'HUOCHAT_READY_EVENT',
                      'HUOCHAT_STOP_EVENT', 'HUOCHAT_STARTUP_KEY'):
            self.assertIn('#define ' + macro + ' ', direct)
            self.assertIn('#define ' + macro + ' ', packaged)
        self.assertIn('L"Local\\\\' + identity + 'Ready"', direct)
        self.assertIn('L"Local\\\\' + identity + 'LauncherReadyV2"', packaged)
        self.assertIn('L"Software\\\\Root\\\\' + identity + '"', direct)
        # The names must not collide across families, or one test family sees
        # the other's launcher as "already running" and waits it out.
        self.assertNotEqual(direct, packaged)

    def test_the_renderer_doubles_backslashes_for_c(self):
        line = isolated_definition_source('abc', 'HuoChatTests', False)
        self.assertIn('#define HUOCHAT_STARTUP_KEY L"Software\\\\HuoChatTests\\\\abc"\n',
                      line)
        self.assertIn('#define HUOCHAT_LAUNCHER_MUTEX L"Local\\\\abcLauncher"\n', line)


def guard_source(intercepted=None, absent=None, modules=None):
    """A guard.c-shaped document that satisfies every parity rule by default."""
    if intercepted is None:
        intercepted = sorted(GUARDS)
    if absent is None:
        absent = sorted(INTENTIONALLY_ABSENT)
    if modules is None:
        modules = sorted(({d.lower() for d in NETWORK_DLLS} - {'sensapi.dll'})
                         | set(absent))
    chain = ' ||\n        '.join('contains(base, L"%s")' % m for m in modules)
    absent_chain = ' || '.join('contains(leaf, L"%s")' % m for m in absent)
    entries = ','.join('"%s"' % name for name in intercepted)
    return ('static BOOL network_module(LPCWSTR name) {\n'
            '    LPCWSTR base = name;\n'
            '    return %s;\n}\n'
            'HMODULE WINAPI Guard_LoadLibraryExW(LPCWSTR name, HANDLE file, DWORD flags) {\n'
            '    LPCWSTR leaf = name;\n'
            '    if (%s) return NULL;\n'
            '    return LoadLibraryExW(name, file, flags);\n}\n'
            'static LPCSTR GUARDED_EXPORTS[] = { %s };\n'
            'FARPROC WINAPI Guard_GetProcAddress(HMODULE module, LPCSTR name) {\n'
            '    return GetProcAddress(module, name);\n}\n'
            'HRESULT WINAPI Guard_CLSIDFromProgID(LPCOLESTR name) {\n'
            '    if(contains(name,L"xmlhttp") || contains(name,L"internetexplorer"))\n'
            '        return E_ACCESSDENIED;\n'
            '    return S_OK;\n}\n' % (chain, absent_chain, entries))


class GuardParityTests(unittest.TestCase):
    """Drift between guard.c and the static policy must stop the build."""

    def setUp(self):
        self.network = build.NETWORK_DLLS

    def tearDown(self):
        build.NETWORK_DLLS = self.network

    def test_a_consistent_document_passes(self):
        check_policy_parity(guard_source())

    def test_a_document_missing_a_module_function_is_rejected(self):
        source = guard_source()
        source = source[:source.index('HMODULE WINAPI Guard_LoadLibraryExW')]
        with self.assertRaises(ValueError):
            check_policy_parity(source)

    def test_prog_id_fragments_are_not_mistaken_for_modules(self):
        """guard.c also compares ProgID fragments through the same helper.

        A whole-file scan of ``contains`` turns "internetexplorer" and "xmlhttp"
        into module names the policy never had to refuse, so the scan is confined
        to the two functions that decide what a loaded module is.
        """
        names = guard_module_names(guard_source())
        self.assertNotIn('internetexplorer.dll', names)
        self.assertNotIn('xmlhttp.dll', names)
        self.assertIn('node.dll', names)
        # Both spellings the argument has had must be read.
        self.assertTrue({'mshtml.dll', 'msxml.dll', 'ieframe.dll'} <= names)

    def test_the_real_guard_c_still_yields_an_interception_list(self):
        source = (SOURCE_DIR / 'guard.c').read_text(encoding='utf-8', errors='replace')
        self.assertTrue(guard_intercept_names(source))

    def test_an_unrefused_module_that_must_stay_missing_is_rejected(self):
        absent = sorted(INTENTIONALLY_ABSENT - {'node.dll'})
        modules = sorted({d.lower() for d in NETWORK_DLLS}
                        - {'sensapi.dll'} | set(absent))
        with self.assertRaises(ValueError) as caught:
            check_policy_parity(guard_source(absent=absent, modules=modules))
        self.assertIn('node.dll', str(caught.exception))

    def test_a_module_that_is_both_stubbed_and_refused_is_rejected(self):
        build.NETWORK_DLLS = frozenset(self.network) | {'mshtml.dll'}
        with self.assertRaises(ValueError) as caught:
            check_policy_parity(guard_source())
        self.assertIn('mshtml.dll', str(caught.exception))

    def test_a_guarded_export_the_hook_does_not_name_is_rejected(self):
        with self.assertRaises(ValueError) as caught:
            check_policy_parity(guard_source(intercepted=sorted(set(GUARDS)
                                                               - {'WinExec'})))
        self.assertIn('WinExec', str(caught.exception))

    def test_an_interception_that_no_export_backs_is_rejected(self):
        with self.assertRaises(ValueError) as caught:
            check_policy_parity(guard_source(intercepted=sorted(set(GUARDS))
                                                             + ['GetTickCount']))
        self.assertIn('GetTickCount', str(caught.exception))

    def test_the_chain_form_is_still_read(self):
        source = ('FARPROC WINAPI Guard_GetProcAddress(HMODULE module, LPCSTR name) {\n'
                  '    if (lstrcmpA(name, "LoadLibraryA") == 0 || '
                  'lstrcmpA(name, "CreateFileW") == 0) {\n'
                  '        return GetProcAddress(module, name);\n'
                  '    }\n'
                  '    return GetProcAddress(module, name);\n'
                  '}\n'
                  'static BOOL other(LPCSTR name) { '
                  'return lstrcmpA(name, "GetTickCount") == 0; }\n')
        self.assertEqual({'LoadLibraryA', 'CreateFileW'},
                         guard_intercept_names(source))

    def test_a_document_with_no_names_at_all_is_rejected(self):
        with self.assertRaises(ValueError):
            guard_intercept_names('static BOOL nothing(void) { return TRUE; }\n')


class GuideSizeRuleTests(unittest.TestCase):
    """Both compaction paths answer to the same "must be smaller" rule."""

    def animation(self):
        out = io.BytesIO()
        frames = [Image.new('RGB', (1000, 600), c) for c in ('red', 'green', 'blue')]
        frames[0].save(out, format='GIF', save_all=True, append_images=frames[1:],
                       duration=100)
        return out.getvalue()

    def noisy_animation(self):
        """A payload no rendered page could compress below."""
        import random
        rng = random.Random(20260903)
        image = Image.new('RGB', (1000, 600))
        image.putdata([(rng.randrange(256), rng.randrange(256), rng.randrange(256))
                       for _ in range(1000 * 600)])
        out = io.BytesIO()
        image.save(out, format='GIF', save_all=True, duration=100)
        return out.getvalue()

    def test_a_rendered_page_that_does_not_shrink_is_refused(self):
        # The early return used to hand this value straight back to the caller.
        original = build.offline_guide
        build.offline_guide = lambda page: b'x' * 5000
        try:
            with self.assertRaises(ValueError) as caught:
                compact_guide_gif(self.animation(), 'guide/guid5_2.gif')
            self.assertIn('did not reduce', str(caught.exception))
        finally:
            build.offline_guide = original

    def test_a_rendered_page_that_shrinks_is_returned(self):
        rendered = b'small'
        original = build.offline_guide
        build.offline_guide = lambda page: rendered
        try:
            self.assertEqual(rendered,
                             compact_guide_gif(self.animation(), 'guide/guid5_3.gif'))
        finally:
            build.offline_guide = original

    def test_the_real_pages_still_beat_the_original_animation(self):
        huge = self.noisy_animation()
        self.assertGreater(len(huge), 60000)
        for name in ('guide/guid5_2.gif', 'guide/guid5_3.gif'):
            result = compact_guide_gif(huge, name)
            self.assertLess(len(result), len(huge), name)
            with Image.open(io.BytesIO(result)) as image:
                self.assertEqual((1000, 600), image.size)
                self.assertEqual('GIF', image.format)


# --------------------------------------------------------------------------
# A minimal PE32 with a group icon, for icon_from.
# --------------------------------------------------------------------------
RSRC_RVA, RSRC_SIZE, RSRC_FILE = 0x5000, 0x400, 0x600
ICON_BYTES = 16


def write_icon_pe(path, *, icon_ids=(1,), group_ids=None):
    """Write a parseable PE whose group icon references ``group_ids``.

    ``icon_ids`` become real RT_ICON entries; an id listed in ``group_ids``
    with no matching RT_ICON is the dangling reference icon_from must report
    instead of raising a bare KeyError.
    """
    if group_ids is None:
        group_ids = icon_ids
    icon_ids = tuple(sorted(icon_ids))
    pixels = [bytes(range(16 * (i + 1), 16 * (i + 2))) for i in range(len(icon_ids))]
    group = struct.pack('<HHH', 0, 1, len(group_ids))
    for ident in group_ids:
        group += struct.pack('<BBBBHHIH', 16, 16, 0, 0, 1, 32, ICON_BYTES, ident)

    data = bytearray(b'MZ' + b'\0' * 0x3a + struct.pack('<I', PE_OFF))
    data.extend(b'\0' * (PE_OFF - len(data)))
    data += b'PE\0\0'
    data += struct.pack('<HHIIIHH', 0x14c, 2, 0, 0, 0, 0xe0, 0x102)
    optional = bytearray(0xe0)
    struct.pack_into('<H', optional, 0, 0x10b)
    struct.pack_into('<I', optional, 0x1C, 0x400000)     # ImageBase
    struct.pack_into('<I', optional, 0x20, 0x1000)       # SectionAlignment
    struct.pack_into('<I', optional, 0x24, 0x200)        # FileAlignment
    struct.pack_into('<I', optional, 0x38, 0x6000)       # SizeOfImage
    struct.pack_into('<I', optional, 0x3C, 0x200)        # SizeOfHeaders
    struct.pack_into('<H', optional, 0x44, 3)            # Subsystem
    struct.pack_into('<I', optional, 0x5C, 16)           # NumberOfRvaAndSizes
    data += optional
    data += (b'.text\0\0\0' + struct.pack('<IIIIIIHHI', 0x200, 0x1000, 0x200,
                                           0x200, 0, 0, 0, 0, 0x60000020))
    data += (b'.rsrc\0\0\0' + struct.pack('<IIIIIIHHI', RSRC_SIZE, RSRC_RVA,
                                          RSRC_SIZE, RSRC_FILE, 0, 0, 0, 0,
                                          0x40000040))
    data.extend(b'\0' * (RSRC_FILE - len(data)))

    # Three-level resource tree: type -> id -> language -> data entry. Each node
    # is an IMAGE_RESOURCE_DIRECTORY (two DWORDs, two version words, then the
    # named/id entry counts) followed by its IMAGE_RESOURCE_DIRECTORY_ENTRY
    # list, so a directory with n children occupies 16 + 8n bytes.
    tree = bytearray(RSRC_SIZE)
    # Offset 0 is the type directory, and it has to list every icon id plus the
    # group icon: an id that is missing from it is invisible to the loader, so
    # its RT_ICON would never reach icon_from's lookup table.
    used = [16 + 8 * (len(icon_ids) + 1)]

    def directory(children):
        at = used[0]
        used[0] += 16 + 8 * len(children)
        struct.pack_into('<IIHHHH', tree, at, 0, 0, 0, 0, 0, len(children))
        for i, (name, target) in enumerate(children):
            struct.pack_into('<II', tree, at + 16 + 8 * i, name, target)
        return at

    def leaf(rva, size):
        at = used[0]
        used[0] += 16
        struct.pack_into('<IIII', tree, at, rva, size, 0, 0)
        return at

    # The data blobs sit at the end of the section; the tree grows from the top.
    blobs = RSRC_SIZE - ICON_BYTES * len(icon_ids) - len(group)
    icon_entries = [leaf(RSRC_RVA + blobs + ICON_BYTES * i, ICON_BYTES)
                    for i in range(len(icon_ids))]
    icon_langs = [directory([(0x409, icon_entries[i])])
                  for i in range(len(icon_ids))]
    icon_dirs = [directory([(icon_ids[i], 0x80000000 | icon_langs[i])])
                 for i in range(len(icon_ids))]
    group_entry = leaf(RSRC_RVA + blobs + ICON_BYTES * len(icon_ids), len(group))
    group_lang = directory([(0x409, group_entry)])
    group_dir = directory([(1, 0x80000000 | group_lang)])
    # The type directory is the tree root, so it lives at the reserved offset 0.
    struct.pack_into('<IIHHHH', tree, 0, 0, 0, 0, 0, 0, len(icon_ids) + 1)
    for i, ident in enumerate(icon_ids):
        struct.pack_into('<II', tree, 16 + 8 * i, 3, 0x80000000 | icon_dirs[i])
    struct.pack_into('<II', tree, 16 + 8 * len(icon_ids), 14,
                     0x80000000 | group_dir)
    for i, blob in enumerate(pixels):
        tree[blobs + ICON_BYTES * i:blobs + ICON_BYTES * (i + 1)] = blob
    tree[blobs + ICON_BYTES * len(icon_ids):] = group.ljust(
        RSRC_SIZE - blobs - ICON_BYTES * len(icon_ids), b'\0')

    data.extend(tree)
    # DataDirectory[2] (resource) points at the tree root.
    struct.pack_into('<II', data, PE_OFF + 4 + 20 + 0x60 + 8 * 2, RSRC_RVA, RSRC_SIZE)
    path.write_bytes(bytes(data))
    return path


class IconFromTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='icon_from_'))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_a_group_entry_pointing_at_a_missing_id_is_reported(self):
        # The group names icon id 7, but only id 1 exists as an RT_ICON.
        p = write_icon_pe(self.tmp / 'sample.exe', icon_ids=(1,), group_ids=(7,))
        out = self.tmp / 'sample.ico'
        with self.assertRaises(ValueError) as caught:
            icon_from(p, out)
        message = str(caught.exception)
        self.assertIn('sample.exe', message, 'the failure must name the file')
        self.assertIn('7', message)
        self.assertFalse(out.exists())

    def test_a_consistent_group_icon_is_rebuilt(self):
        p = write_icon_pe(self.tmp / 'sample.exe', icon_ids=(1, 9))
        out = self.tmp / 'sample.ico'
        icon_from(p, out)
        blob = out.read_bytes()
        self.assertEqual(struct.unpack_from('<H', blob, 4)[0], 2)
        self.assertEqual(6 + 2 * 16 + 2 * 16, len(blob))
        # Each rebuilt entry is eight descriptor bytes, then the payload length
        # and the accumulating file offset.
        self.assertEqual(16, struct.unpack_from('<I', blob, 6 + 8)[0])
        self.assertEqual(38, struct.unpack_from('<I', blob, 6 + 12)[0])
        self.assertEqual(16, struct.unpack_from('<I', blob, 22 + 8)[0])
        self.assertEqual(54, struct.unpack_from('<I', blob, 22 + 12)[0])


if __name__ == '__main__':
    unittest.main()
