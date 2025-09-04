# -*- coding: UTF-8 -*-

import json
import struct
from datetime import datetime
from common import get_int, get_long, get_string

macho_magics = {
    0xFEEDFACE: (False, False),  # 32 bit, big endian
    0xFEEDFACF: (True, False),  # 64 bit, big endian
    0xCEFAEDFE: (False, True),  # 32 bit, little endian
    0xCFFAEDFE: (True, True),  # 64 bit, little endian
}
g_is_64_bit = True
g_byteorder = 'little'
g_endian = '<'


def parse_header(header):
    """
    parse macho header in memory
    """
    is_fat = header.startswith(b'\xca\xfe\xba\xbe')
    if is_fat:
        info = parse_fat(header)
    else:
        info = parse_macho(header, 0)

    # print(json.dumps(info, indent=2))
    return info


def parse_macho(base, offset):
    """
    Parse mach-o in memory
    """
    global g_byteorder, g_is_64_bit, g_endian
    magic = int.from_bytes(base[offset:offset + 4], byteorder='big')
    g_is_64_bit, is_little_endian = macho_magics[magic]

    if is_little_endian:
        g_endian = '<'
        g_byteorder = 'little'
        magic = int.from_bytes(base[offset:offset + 4], byteorder=g_byteorder)
    else:
        g_endian = '>'
        g_byteorder = 'big'

    header_bytes = base[offset + 4:offset + 24]
    cputype, subtype, filetype, ncmds, scmds = struct.unpack(g_endian + '2i3I', header_bytes)
    # skip header
    if g_is_64_bit:
        offset += 32
    else:
        offset += 28

    macho = {
        'magic': '{:X}'.format(magic),
        'cputype': '{:X}'.format(cputype),
        'subtype': '{:X}'.format(subtype),
        'filetype': '{:X}'.format(filetype),
        'ncmds': '{:X}'.format(ncmds),
        'scmds': '{:X}'.format(scmds),
    }
    # Parse load commands
    parse_lcs(base, offset, ncmds, macho)
    # print(json.dumps(macho, indent=2))

    return macho


def parse_lcs(base, offset, n_cmds, macho):
    """
    Parse load commands.
    """
    macho['lcs'] = []

    seg_linkedit = None
    linkedit_secs = []
    module_size = 0
    for _ in range(n_cmds):
        cmd = get_int(base, offset)  # load command type
        cmd_size = get_int(base, offset + 4)  # size of load command

        if g_is_64_bit and cmd_size % 8 != 0:
            raise ValueError('Load command size "{}" for 64-bit mach-o at '
                             'offset "{}" is not divisible by 8.'.format(cmd_size, offset))
        elif cmd_size % 4 != 0:
            raise ValueError('Load command size "{}" for 32-bit mach-o at '
                             'offset "{}" is not divisible by 4.'.format(cmd_size, offset))

        if cmd == 0x1 or cmd == 0x19:  # 'SEGMENT' or 'SEGMENT_64'
            segment = parse_segment(base, offset, cmd, cmd_size)
            macho['lcs'].append(segment)
            seg_name = segment['name']
            if seg_name == '__LINKEDIT':
                seg_linkedit = segment
            elif seg_name == '__TEXT':
                macho['text_vmaddr'] = segment['vmaddr']

            if seg_name != '__PAGEZERO':
                module_size += int(segment['vmsize'], 16)
        elif cmd == 0xe or cmd == 0xf or cmd == 0x27:  # LC_LOAD_DYLINKER LC_ID_DYLINKER LC_DYLD_ENVIRONMENT
            lc_info = parse_dylib_linker(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0xd:  # LC_ID_DYLIB
            lc_info = parse_load_dylib(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
            name = lc_info.get('name')
            if name:
                macho['name'] = name
            else:
                print('module name not found')
        elif cmd in (0x21, 0x2C):  # ('ENCRYPTION_INFO', 'ENCRYPTION_INFO_64')
            macho['lcs'].append(parse_encryption_info(base, offset, cmd, cmd_size))
        elif cmd == 0x28 | 0x80000000:  # LC_MAIN (0x28|LC_REQ_DYLD)
            macho['lcs'].append(parse_main(base, offset, cmd, cmd_size))
        elif cmd == 0x2:  # LC_SYMTAB
            lc_symtab = parse_symtab(base, offset, cmd, cmd_size)
            symtab = {
                'name': 'Symbol Table',
                'segname': '__LINKEDIT',
                'offset': '{:X}'.format(lc_symtab['symoff']),
                'size': '{:X}'.format(lc_symtab['nsyms'] * 16 if g_is_64_bit else 12),  # sizeof(struct nlist_64)
            }
            linkedit_secs.append(symtab)

            strtab = {
                'name': 'String Table',
                'segname': '__LINKEDIT',
                'offset': '{:X}'.format(lc_symtab['stroff']),
                'size': '{:X}'.format(lc_symtab['strsize']),
            }
            linkedit_secs.append(strtab)
        elif cmd == 0xb:  # LC_DYSYMTAB
            lc_dysymtab = parse_dysymtab(base, offset, cmd, cmd_size)
            dysymtab = {
                'name': 'Dynamic Symbol Table',
                'segname': '__LINKEDIT',
                'offset': '{:X}'.format(lc_dysymtab['indirectsymoff']),
                'size': '{:X}'.format(lc_dysymtab['nindirectsyms'] * 4),
            }
            linkedit_secs.append(dysymtab)
        elif cmd == 0x26:  # LC_FUNCTION_STARTS
            lc_function_starts = parse_linkedit_data(base, offset, cmd, cmd_size)
            functions = {
                'name': 'Function Starts',
                'segname': '__LINKEDIT',
                'offset': '{}'.format(lc_function_starts['dataoff']),
                'size': '{}'.format(lc_function_starts['datasize']),
            }
            linkedit_secs.append(functions)
        elif cmd == 0x29:  # LC_DATA_IN_CODE
            lc_data_in_code = parse_linkedit_data(base, offset, cmd, cmd_size)
            functions = {
                'name': 'Data In Code Entries',
                'segname': '__LINKEDIT',
                'offset': '{}'.format(lc_data_in_code['dataoff']),
                'size': '{}'.format(lc_data_in_code['datasize']),
            }
            linkedit_secs.append(functions)
        elif cmd == 0x1D:  # LC_CODE_SIGNATURE
            lc_code_signature = parse_linkedit_data(base, offset, cmd, cmd_size)
            codesign = {
                'name': 'Code Signature',
                'segname': '__LINKEDIT',
                'offset': '{}'.format(lc_code_signature['dataoff']),
                'size': '{}'.format(lc_code_signature['datasize']),
            }
            linkedit_secs.append(codesign)

        offset += cmd_size

    def sort_comparator(info):
        return int(info['offset'], 16)

    if seg_linkedit:
        linkedit_secs.sort(key=sort_comparator)
        seg_linkedit['sects'] = linkedit_secs

    macho['module_size'] = module_size


def parse_segment(base, m_offset, cmd, cmd_size):
    """Parse LC_SEGMENT(_64)."""

    if g_is_64_bit:
        seg_size = 72   # sizeof(struct segment_command_64)
        sect_size = 80  # sizeof(struct section_64)
        struct_format = g_endian + '2I16s4Q2i2I'
    else:
        seg_size = 56   # sizeof(struct segment_command)
        sect_size = 68  # sizeof(struct section)
        struct_format = g_endian + '2I16s4I2i2I'

    seg_bytes = base[m_offset: m_offset + seg_size]
    _, _, seg_name, vmaddr, vmsize, offset, segsize, maxprot, initprot, nsects, flags = \
        struct.unpack(struct_format, seg_bytes)

    seg_name = seg_name.strip(b'\x00').decode()
    output = {
        'cmd': '{:X}'.format(cmd),
        'cmd_size': '{:X}'.format(cmd_size),
        'name': seg_name,
        'vmaddr': '{:X}'.format(vmaddr),
        'vmsize': '{:X}'.format(vmsize),
        'offset': '{:X}'.format(offset),
        'segsize': '{:X}'.format(segsize),
        'nsects': '{:X}'.format(nsects),
        'sects': [],
        'lc_offset': m_offset,
        'initprot': initprot,
        'maxprot': maxprot,
    }

    for _ in range(nsects):
        output['sects'].append(parse_section(base, m_offset + seg_size))

        m_offset += sect_size

    # print(json.dumps(output, indent=2))

    return output


def parse_section(base, m_offset):
    """Parse section."""

    if g_is_64_bit:
        read_size = 76
        struct_format = g_endian + '16s16s2Q7I'
    else:
        read_size = 68
        struct_format = g_endian + '16s16s9I'

    sec_bytes = base[m_offset: m_offset + read_size]
    sec_name, seg_name, addr, size, \
    offset, align, reloff, nreloc, \
    flags, reserved1, reserved2 = struct.unpack(struct_format, sec_bytes)

    sec_name = sec_name.strip(b'\x00').decode()
    seg_name = seg_name.strip(b'\x00').decode()
    output = {
        'name': sec_name,
        'segname': seg_name,
        'addr': '{:X}'.format(addr),
        'offset': '{:X}'.format(offset),
        'size': '{:X}'.format(size),
        'flags': '{:X}'.format(flags),
        'reserved1': '{:X}'.format(reserved1),
        'lc_offset': m_offset
    }

    return output


def parse_load_dylib(base, offset, cmd, cmd_size):
    """Parse dylib load command."""
    offset += 12  # skip cmd, cmd_size and str offset
    timestamp = get_int(base, offset)
    current_version = get_int(base, offset + 4)
    compatibility_version = get_int(base, offset + 8)
    name = get_string(base, offset + 12)

    output = {
        'cmd': '{:X}'.format(cmd),
        'cmd_size': '{:X}'.format(cmd_size),
        'name': name,
        'timestamp': datetime.fromtimestamp(timestamp).strftime(
            '%Y-%m-%d %H:%M:%S'),
        'current version': make_version(current_version),
        'compatibility version': make_version(compatibility_version)
    }

    return output


def parse_dylib_linker(base, offset, cmd, cmd_size):
    """Parse dylinker command."""
    offset += 12  # skip cmd, cmd_size and str offset
    name = get_string(base, offset)

    output = {
        'cmd': '{:X}'.format(cmd),
        'cmd_size': '{:X}'.format(cmd_size),
        'name': name
    }

    return output


def parse_encryption_info(base, offset, cmd, cmd_size):
    """
    Parse LC_ENCRYPTION_INFO(_64).
    """
    offset += 8  # skip cmd and cmd_size
    cryptoff = get_int(base, offset)
    cryptsize = get_int(base, offset + 4)
    cryptid = get_int(base, offset + 8)

    output = {
        'cmd': '{:X}'.format(cmd),
        'cmd_size': '{:X}'.format(cmd_size),
        'cryptoff': '{:X}'.format(cryptoff),
        'cryptsize': '{:X}'.format(cryptsize),
        'cryptid': cryptid
    }
    # print(json.dumps(output, indent=2))

    return output


def parse_main(base, offset, cmd, cmd_size):
    """Parse LC_MAIN."""
    offset += 8  # skip cmd and cmd_size
    entryoff = get_long(base, offset)

    output = {
        'cmd': '{:X}'.format(cmd),
        'cmd_size': '{:X}'.format(cmd_size),
        'entryoff': '{:X}'.format(entryoff),
    }

    # print(json.dumps(output, indent=2))

    return output


def parse_linkedit_data(base, offset, cmd, cmd_size):
    """Parse linkedit_data_command."""

    offset += 8  # skip cmd and cmd_size
    dataoff = get_int(base, offset)
    datasize = get_int(base, offset + 4)

    output = {
        'cmd': '{:X}'.format(cmd),
        'cmd_size': '{:X}'.format(cmd_size),
        'dataoff': '{:X}'.format(dataoff),
        'datasize': '{:X}'.format(datasize),
    }

    return output


def parse_symtab(base, offset, cmd, cmd_size):
    """Parse LC_SYMTAB"""

    offset += 8  # skip cmd and cmd_size
    struct_format = g_endian + '4I'
    sec_bytes = base[offset: offset + 16]
    symoff, nsyms, stroff, strsize = struct.unpack(struct_format, sec_bytes)

    output = {
        'cmd': cmd,
        'cmd_size': cmd_size,
        'symoff': symoff,
        'nsyms': nsyms,
        'stroff': stroff,
        'strsize': strsize
    }

    return output


def parse_dysymtab(base, offset, cmd, cmd_size):
    """Parse LC_DYSYMTAB"""

    offset += 8  # skip cmd and cmd_size
    struct_format = g_endian + '18I'
    sec_bytes = base[offset: offset + 72]
    ilocalsym, nlocalsym, iextdefsym, nextdefsym, \
    iundefsym, nundefsym, tocoff, ntoc, modtaboff, \
    nmodtab, extrefsymoff, nextrefsyms, indirectsymoff, \
    nindirectsyms, extreloff, nextrel, locreloff, nlocrel = struct.unpack(struct_format, sec_bytes)

    output = {
        'cmd': cmd,
        'cmd_size': cmd_size,
        'ilocalsym': ilocalsym,
        'nlocalsym': nlocalsym,
        'iextdefsym': iextdefsym,
        'nextdefsym': nextdefsym,
        'iundefsym': iundefsym,
        'nundefsym': nundefsym,
        'tocoff': tocoff,
        'ntoc': ntoc,
        'modtaboff': modtaboff,
        'nmodtab': nmodtab,
        'extrefsymoff': extrefsymoff,
        'nextrefsyms': nextrefsyms,
        'indirectsymoff': indirectsymoff,
        'nindirectsyms': nindirectsyms,
        'extreloff': extreloff,
        'nextrel': nextrel,
        'locreloff': locreloff,
        'nlocrel': nlocrel
    }

    return output


def parse_fat(header):
    """Parses fat header in memory."""
    # number of mach-o's contained in this binary
    cursor = 4
    # fat header部分是大端
    byteorder = 'big'
    n_machos = get_int(header, cursor, byteorder)
    cursor += 4
    machos = []
    for _ in range(n_machos):
        cursor += 8     # skip cpu type and subtype

        offset = get_int(header, cursor, byteorder)
        cursor += 4
        # size = get_int(header, cursor, byteorder)
        cursor += 4

        cursor += 4     # skip align field

        macho = parse_macho(header, offset)
        machos.append(macho)

    return {'fat': {'n_machos': n_machos, 'machos': machos}}


def make_version(version):
    """Construct a version number from given bytes."""

    vx = version >> 16
    vy = (version >> 8) & 0xff
    vz = version & 0xff

    return '{}.{}.{}'.format(vx, vy, vz)