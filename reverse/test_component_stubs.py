"""Regression tests for component-name stubbing.

Builds a synthetic PE-shaped fixture that carries the same UTF-16LE component
names at the same offsets, runs stub_component_names against it, and asserts the
patch is byte-exact, code-preserving, and refuses to run on drifted input.

Run: python -m unittest discover -s reverse -p "test_*.py" -v
"""
import struct
import tempfile
import unittest
from pathlib import Path

import pefile

from build import COMPONENT_STUBS, stub_component_names

def make_fixture(path: Path, *, with_names: bool = True, drift: bool = False):
    """Write a parseable PE whose .rdata carries the component names."""
    # Keep the fixture self-contained. Historical tests borrowed a multi-megabyte
    # audit artifact that is intentionally no longer part of the source tree.
    pe_offset = 0x80
    data = bytearray(b'MZ' + b'\0' * 0x3a + struct.pack('<I', pe_offset))
    data.extend(b'\0' * (pe_offset - len(data)))
    data += b'PE\0\0'
    data += struct.pack('<HHIIIHH', 0x14c, 1, 0, 0, 0, 0xe0, 0x102)
    optional = bytearray(0xe0)
    struct.pack_into('<H', optional, 0, 0x10b)  # PE32
    data += optional
    data += (b'.text\0\0\0' +
             struct.pack('<IIIIIIHHI', 0x100, 0x1000, 0x200, 0x400,
                         0, 0, 0, 0, 0x60000020))
    data.extend(b'\0' * (0x600 - len(data)))

    fixture_size = max(off + len(name.encode('utf-16-le')) + 2
                       for off, name, _ in COMPONENT_STUBS)
    data.extend(b'\0' * (fixture_size - len(data)))
    if with_names:
        for off, name, _ in COMPONENT_STUBS:
            enc = name.encode('utf-16-le')
            data[off:off + len(enc)] = enc
    if drift:
        # Corrupt one target so the offset assertion must fire.
        off, _, _ = COMPONENT_STUBS[0]
        data[off] = (data[off] + 1) & 0xFF

    path.write_bytes(bytes(data))
    return path


class ComponentStubTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='stub_test_'))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_stub_replaces_all_component_names(self):
        p = self.tmp / 'HuoChat.exe'
        make_fixture(p)
        before = p.read_bytes()
        report = stub_component_names(p)
        after = p.read_bytes()

        self.assertEqual(len(before), len(after), 'length must not change')
        self.assertEqual(len(report['component_stubs']), len(COMPONENT_STUBS))

        for _, name, _ in COMPONENT_STUBS:
            self.assertNotIn(name.encode('utf-16-le'), after,
                             '%s still present after stub' % name)

    def test_patch_offsets_must_lie_outside_executable_code(self):
        """A stub target inside .text would patch machine instructions, so the
        builder must refuse it. This is the assertion that actually binds."""
        import pefile

        p = self.tmp / 'HuoChat.exe'
        make_fixture(p)
        pristine = p.read_bytes()
        pe = pefile.PE(data=pristine)
        code = None
        for s in pe.sections:
            if s.Name.rstrip(b'\0') == b'.text':
                code = s
        pe.close()
        self.assertIsNotNone(code)

        # Plant one component name inside .text and require refusal.
        name = COMPONENT_STUBS[0][1]
        enc = name.encode('utf-16-le')
        off = code.PointerToRawData + 0x40
        planted = pristine[:off] + enc + pristine[off + len(enc):]
        p.write_bytes(planted)

        original = list(COMPONENT_STUBS)
        COMPONENT_STUBS[0] = (off, name, 'planted in .text')
        try:
            with self.assertRaises(ValueError):
                stub_component_names(p)
            self.assertEqual(p.read_bytes(), planted,
                             'a refused stub must not modify the file')
        finally:
            COMPONENT_STUBS[:] = original

        # The real offsets must all be outside executable code.
        pe = pefile.PE(data=pristine)
        spans = [(s.PointerToRawData, s.SizeOfRawData) for s in pe.sections
                 if s.Name.rstrip(b'\0') == b'.text' or (s.Characteristics & 0x20000000)]
        pe.close()
        for off_, name_, _ in original:
            for c_off, c_sz in spans:
                self.assertFalse(c_off <= off_ < c_off + c_sz,
                                 'offset 0x%X (%s) is inside executable code'
                                 % (off_, name_))

    def test_stub_preserves_nul_terminators_and_neighbours(self):
        p = self.tmp / 'HuoChat.exe'
        make_fixture(p)
        stub_component_names(p)
        data = p.read_bytes()
        for off, name, _ in COMPONENT_STUBS:
            self.assertEqual(data[off + len(name) * 2:off + len(name) * 2 + 2],
                             b'\x00\x00', 'NUL terminator eaten at 0x%X' % off)

    def test_stub_fills_are_spaces_not_nuls(self):
        p = self.tmp / 'HuoChat.exe'
        make_fixture(p)
        stub_component_names(p)
        data = p.read_bytes()
        for off, name, _ in COMPONENT_STUBS:
            seg = data[off:off + len(name) * 2].decode('utf-16-le')
            self.assertTrue(seg.strip() == '', 'fill is not blank at 0x%X' % off)
            self.assertNotIn('\x00', seg, 'fill leaked NUL bytes')

    def test_stub_refuses_drifted_input(self):
        p = self.tmp / 'HuoChat.exe'
        make_fixture(p, drift=True)
        with self.assertRaises(ValueError):
            stub_component_names(p)
        # A refused patch must leave the file untouched.
        data = p.read_bytes()
        for _, name, _ in COMPONENT_STUBS[1:]:
            self.assertIn(name.encode('utf-16-le'), data)


if __name__ == '__main__':
    unittest.main()
