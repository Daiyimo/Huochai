"""Pinned data-path changes. Only three existing address operands change.

The central user-directory constructor is shared by config/history/notes and
their backups. Its nine-character argument becomes Data\\User. The two site
database PathAppend calls also receive a data path. Existing HIGHLOW relocation
entries continue to relocate those operands under ASLR; no opcodes are changed.
"""
import struct
import pefile


def relocate_data_paths(path):
    original = path.read_bytes()
    data = bytearray(original)
    pe = pefile.PE(data=original)
    if path.name.lower() == 'huochat.exe':
        strings = ('Data\\User\0Data\\Sites.db\0').encode('utf-16le')
        refs = [(0xD2F97, 0x7C53F8, 0),
                (0x7FB92, 0x7D07C4, 20), (0x12B91E, 0x7D07C4, 20)]
        relocations = {e.rva for block in pe.DIRECTORY_ENTRY_BASERELOC
                       for e in block.entries if e.type == 3}
        header = pe.sections[-1].get_file_offset() + 40
        if header + 40 > pe.sections[0].PointerToRawData or any(data[header:header+40]):
            raise ValueError('No unused PE section header for data paths')
        align = lambda n, a: (n + a - 1) // a * a
        raw = align(len(data), pe.OPTIONAL_HEADER.FileAlignment)
        rva = align(pe.OPTIONAL_HEADER.SizeOfImage, pe.OPTIONAL_HEADER.SectionAlignment)
        size = align(len(strings), pe.OPTIONAL_HEADER.FileAlignment)
        for off, expected, relative in refs:
            if data[off-1] != 0x68 or struct.unpack_from('<I', data, off)[0] != expected:
                raise ValueError('Pinned data-path operand drift: ' + hex(off))
            if pe.get_rva_from_offset(off) not in relocations:
                raise ValueError('Data-path operand lacks ASLR relocation')
            struct.pack_into('<I', data, off, pe.OPTIONAL_HEADER.ImageBase+rva+relative)
        section = struct.pack('<8sIIIIIIHHI', b'.hcdata\0', len(strings), rva,
                              size, raw, 0, 0, 0, 0, 0x40000040)
        data[header:header+40] = section
        data.extend(b'\0'*(raw-len(data)) + strings.ljust(size, b'\0'))
        struct.pack_into('<H', data, pe.FILE_HEADER.get_field_absolute_offset('NumberOfSections'), len(pe.sections)+1)
        struct.pack_into('<I', data, pe.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfImage'),
                         align(rva+len(strings), pe.OPTIONAL_HEADER.SectionAlignment))
        struct.pack_into('<I', data, pe.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfInitializedData'),
                         pe.OPTIONAL_HEADER.SizeOfInitializedData+size)
        # All executable bytes apart from the reviewed pointer operands remain identical.
        permitted = {i for off, _, _ in refs for i in range(off, off+4)}
        for s in pe.sections:
            if s.Characteristics & 0x20000000:
                for i in range(s.PointerToRawData, s.PointerToRawData+s.SizeOfRawData):
                    if original[i] != data[i] and i not in permitted:
                        raise ValueError('Unexpected instruction change')
        offsets, encoding = [0x3C934C], 'utf-16le'
    else:
        raise ValueError('Unexpected payload for data-path relocation')
    old, new = 'Everything.ini'.encode(encoding), 'Data\\Index.ini'.encode(encoding)
    assert len(old) == len(new)
    for off in offsets:
        section = pe.get_section_by_rva(pe.get_rva_from_offset(off))
        if section.Characteristics & 0x20000000 or data[off:off+len(old)] != old:
            raise ValueError('Pinned configuration literal drift: ' + hex(off))
        data[off:off+len(old)] = new
    pe.close()
    result = pefile.PE(data=bytes(data))
    result.OPTIONAL_HEADER.CheckSum = result.generate_checksum()
    path.write_bytes(result.write())
    result.close()
