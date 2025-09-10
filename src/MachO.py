# -*- coding: UTF-8 -*-

import json
import struct
from datetime import datetime
from common import get_int, get_long, get_string
import uuid

macho_magics = {
    0xFEEDFACE: (False, False),  # 32 bit, big endian
    0xFEEDFACF: (True, False),  # 64 bit, big endian
    0xCEFAEDFE: (False, True),  # 32 bit, little endian
    0xCFFAEDFE: (True, True),  # 64 bit, little endian
}
g_is_64_bit = True
g_byteorder = 'little'
g_endian = '<'
LC_REQ_DYLD = 0x80000000


def parse_header(header, combine=True):
    """
    parse macho header in memory
    """
    is_fat = header.startswith(b'\xca\xfe\xba\xbe')
    if is_fat:
        info = parse_fat(header, combine)
    else:
        info = parse_macho(header, 0, combine)

    # print(json.dumps(info, indent=2))
    return info


def parse_macho(base, offset, combine=True):
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
    parse_lcs(base, offset, ncmds, macho, combine)
    # print(json.dumps(macho, indent=2))

    return macho


def parse_lcs(base, offset, n_cmds, macho, combine):
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

        if cmd == 0x1 or cmd == 0x19:  # 'LC_SEGMENT' or 'LC_SEGMENT_64'
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
        elif cmd in (0x21, 0x2C):  # ('LC_ENCRYPTION_INFO', 'LC_ENCRYPTION_INFO_64')
            macho['lcs'].append(parse_encryption_info(base, offset, cmd, cmd_size))
        elif cmd == 0x28 | LC_REQ_DYLD:  # LC_MAIN (0x28|LC_REQ_DYLD)
            macho['lcs'].append(parse_main(base, offset, cmd, cmd_size))
        elif cmd == 0x2:  # LC_SYMTAB
            lc_symtab = parse_symtab(base, offset, cmd, cmd_size)
            if combine:
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
            else:
                macho['lcs'].append(lc_symtab)
        elif cmd == 0xb:  # LC_DYSYMTAB
            lc_dysymtab = parse_dysymtab(base, offset, cmd, cmd_size)
            if combine:
                dysymtab = {
                    'name': 'Dynamic Symbol Table',
                    'segname': '__LINKEDIT',
                    'offset': '{:X}'.format(lc_dysymtab['indirectsymoff']),
                    'size': '{:X}'.format(lc_dysymtab['nindirectsyms'] * 4),
                }
                linkedit_secs.append(dysymtab)
            else:
                macho['lcs'].append(lc_dysymtab)
        elif cmd == 0x26:  # LC_FUNCTION_STARTS
            lc_function_starts = parse_linkedit_data(base, offset, cmd, cmd_size)
            if combine:
                functions = {
                    'name': 'Function Starts',
                    'segname': '__LINKEDIT',
                    'offset': '{}'.format(lc_function_starts['dataoff']),
                    'size': '{}'.format(lc_function_starts['datasize']),
                }
                linkedit_secs.append(functions)
            else:
                macho['lcs'].append(lc_function_starts)
        elif cmd == 0x29:  # LC_DATA_IN_CODE
            lc_data_in_code = parse_linkedit_data(base, offset, cmd, cmd_size)
            if combine:
                data_in_code = {
                    'name': 'Data In Code Entries',
                    'segname': '__LINKEDIT',
                    'offset': '{}'.format(lc_data_in_code['dataoff']),
                    'size': '{}'.format(lc_data_in_code['datasize']),
                }
                linkedit_secs.append(data_in_code)
            else:
                macho['lcs'].append(lc_data_in_code)
        elif cmd == 0x1D:  # LC_CODE_SIGNATURE
            lc_code_signature = parse_linkedit_data(base, offset, cmd, cmd_size)
            if combine:
                codesign = {
                    'name': 'Code Signature',
                    'segname': '__LINKEDIT',
                    'offset': '{}'.format(lc_code_signature['dataoff']),
                    'size': '{}'.format(lc_code_signature['datasize']),
                }
                linkedit_secs.append(codesign)
            else:
                macho['lcs'].append(lc_code_signature)
        elif cmd == 0x3:  # LC_SYMSEG
            lc_info = parse_symseg(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x4:  # LC_THREAD
            lc_info = parse_thread(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x5:  # LC_UNIXTHREAD
            lc_info = parse_thread(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x6:  # LC_LOADFVMLIB
            lc_info = parse_fvmlib(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x7:  # LC_IDFVMLIB
            lc_info = parse_fvmlib(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x8:  # LC_IDENT
            lc_info = parse_ident(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x9:  # LC_FVMFILE
            lc_info = parse_fvmfile(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0xa:  # LC_PREPAGE
            lc_info = {
                'cmd': '{:X}'.format(cmd),
                'cmd_size': '{:X}'.format(cmd_size),
                'cmd_name': 'LC_PREPAGE',
            }
            macho['lcs'].append(lc_info)
        elif cmd == 0xc:  # LC_LOAD_DYLIB
            lc_info = parse_load_dylib(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x10:  # LC_PREBOUND_DYLIB
            lc_info = parse_prebound_dylib(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x11:  # LC_ROUTINES
            lc_info = parse_routines(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x12:  # LC_SUB_FRAMEWORK
            lc_info = parse_sub_stuff(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x13:  # LC_SUB_UMBRELLA
            lc_info = parse_sub_stuff(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x14:  # LC_SUB_CLIENT
            lc_info = parse_sub_stuff(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x15:  # LC_SUB_LIBRARY
            lc_info = parse_sub_stuff(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x16:  # LC_TWOLEVEL_HINTS
            lc_info = parse_twolevel_hints(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x17:  # LC_PREBIND_CKSUM
            lc_info = parse_prebind_cksum(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x18 | LC_REQ_DYLD:  # LC_LOAD_WEAK_DYLIB
            lc_info = parse_load_dylib(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x1a:  # LC_ROUTINES_64
            lc_info = parse_routines_64(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x1b:  # LC_UUID
            lc_info = parse_uuid(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x1c | LC_REQ_DYLD:  # LC_RPATH
            lc_info = parse_sub_stuff(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x1e:  # LC_SEGMENT_SPLIT_INFO
            lc_split_info = parse_linkedit_data(base, offset, cmd, cmd_size)
            if combine:
                split_info = {
                    'name': 'SEGMENT SPLIT INFO',
                    'segname': '__SEGMENT_SPLIT_INFO',
                    'offset': '{}'.format(lc_split_info['dataoff']),
                    'size': '{}'.format(lc_split_info['datasize']),
                }
                linkedit_secs.append(split_info)
            else:
                macho['lcs'].append(lc_split_info)
        elif cmd == 0x1f | LC_REQ_DYLD:  # LC_REEXPORT_DYLIB
            lc_info = parse_load_dylib(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x22:  # LC_DYLD_INFO
            lc_info = parse_dyld_info(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x22 | LC_REQ_DYLD:  # LC_DYLD_INFO_ONLY
            lc_info = parse_dyld_info(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x23 | LC_REQ_DYLD:  # LC_LOAD_UPWARD_DYLIB
            pass
        elif cmd == 0x24:  # LC_VERSION_MIN_MACOSX
            lc_info = parse_version_min_os(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x25:  # LC_VERSION_MIN_IPHONEOS
            lc_info = parse_version_min_os(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x2A:  # LC_SOURCE_VERSION
            lc_info = parse_source_version(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x2B:  # LC_DYLIB_CODE_SIGN_DRS
            lc_code_sign_drs = parse_linkedit_data(base, offset, cmd, cmd_size)
            if combine:
                code_sign_drs = {
                    'name': 'DYLIB CODE SIGN DRS',
                    'segname': '__DYLIB_CODE_SIGN_DRS',
                    'offset': '{}'.format(lc_code_sign_drs['dataoff']),
                    'size': '{}'.format(lc_code_sign_drs['datasize']),
                }
                linkedit_secs.append(code_sign_drs)
            else:
                macho['lcs'].append(lc_code_sign_drs)
        elif cmd == 0x2D:  # LC_LINKER_OPTION
            lc_info = parse_linker_option(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x2E:  # LC_LINKER_OPTIMIZATION_HINT
            lc_opt_hint = parse_linkedit_data(base, offset, cmd, cmd_size)
            if combine:
                opt_hint = {
                    'name': 'LINKER OPTIMIZATION HINT',
                    'segname': '__LINKER_OPTIMIZATION_HINT',
                    'offset': '{}'.format(lc_opt_hint['dataoff']),
                    'size': '{}'.format(lc_opt_hint['datasize']),
                }
                linkedit_secs.append(opt_hint)
            else:
                macho['lcs'].append(lc_opt_hint)
        elif cmd == 0x2F:  # LC_VERSION_MIN_TVOS
            lc_info = parse_version_min_os(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x30:  # LC_VERSION_MIN_WATCHOS
            lc_info = parse_version_min_os(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x31:  # LC_NOTE
            lc_info = parse_note(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x32:  # LC_BUILD_VERSION
            lc_info = parse_build_version(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x33 | LC_REQ_DYLD:  # LC_DYLD_EXPORTS_TRIE
            lc_exeports_trie = parse_linkedit_data(base, offset, cmd, cmd_size)
            if combine:
                exeports_trie = {
                    'name': 'DYLD EXPORTS TRIE',
                    'segname': '__DYLD_EXPORTS_TRIE',
                    'offset': '{}'.format(lc_exeports_trie['dataoff']),
                    'size': '{}'.format(lc_exeports_trie['datasize']),
                }
                linkedit_secs.append(exeports_trie)
            else:
                macho['lcs'].append(lc_exeports_trie)
        elif cmd == 0x34 | LC_REQ_DYLD:  # LC_DYLD_CHAINED_FIXUPS
            lc_chained_fixups = parse_linkedit_data(base, offset, cmd, cmd_size)
            if combine:
                chained_fixups = {
                    'name': 'DYLD CHAINED FIXUPS',
                    'segname': '__DYLD_CHAINED_FIXUPS',
                    'offset': '{}'.format(lc_chained_fixups['dataoff']),
                    'size': '{}'.format(lc_chained_fixups['datasize']),
                }
                linkedit_secs.append(chained_fixups)
            else:
                macho['lcs'].append(lc_chained_fixups)
        elif cmd == 0x35 | LC_REQ_DYLD:  # LC_FILESET_ENTRY
            lc_info = parse_fileset_entry(base, offset, cmd, cmd_size)
            macho['lcs'].append(lc_info)
        elif cmd == 0x36:  # LC_ATOM_INFO
            lc_atom_info = parse_linkedit_data(base, offset, cmd, cmd_size)
            if combine:
                atom_info = {
                    'name': 'ATOM INFO',
                    'segname': '__ATOM_INFO',
                    'offset': '{}'.format(lc_atom_info['dataoff']),
                    'size': '{}'.format(lc_atom_info['datasize']),
                }
                linkedit_secs.append(atom_info)
            else:
                macho['lcs'].append(lc_atom_info)

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
        'cmd_name': 'LC_SEGMENT_64' if cmd == 0x19 else 'LC_SEGMENT',
        'cmd': '{:X}'.format(cmd),
        'cmd_size': '{:X}'.format(cmd_size),
        'name': seg_name,
        'vmaddr': '{:X}'.format(vmaddr),
        'vmsize': '{:X}'.format(vmsize),
        'offset': '{:X}'.format(offset),
        'segsize': '{:X}'.format(segsize),
        'initprot': initprot,
        'maxprot': maxprot,
        'nsects': '{:X}'.format(nsects),
        'sects': [],
        'lc_offset': m_offset,
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
    offset += 8  # skip cmd, cmd_size and str offset

    str_off = get_int(base, offset)
    timestamp = get_int(base, offset + 4)
    current_version = get_int(base, offset + 8)
    compatibility_version = get_int(base, offset + 12)
    name = get_string(base, offset + str_off - 8)

    cmd_name = 'unknown'
    if cmd == 0xc:
        cmd_name = 'LC_LOAD_DYLIB'
    elif cmd == 0xd:
        cmd_name = 'LC_ID_DYLIB'
    elif cmd == 0x18 | LC_REQ_DYLD:
        cmd_name = 'LC_LOAD_WEAK_DYLIB'
    elif cmd == 0x1f:
        cmd_name = 'LC_REEXPORT_DYLIB'

    output = {
        'cmd_name': cmd_name,
        'cmd': '{:X}'.format(cmd),
        'cmd_size': '{:X}'.format(cmd_size),
        'str_off': str_off,
        'timestamp': datetime.fromtimestamp(timestamp).strftime(
            '%Y-%m-%d %H:%M:%S'),
        'current version': make_version(current_version),
        'compatibility version': make_version(compatibility_version),
        'name': name,
    }

    return output


def parse_dylib_linker(base, offset, cmd, cmd_size):
    """Parse dylinker command."""
    offset += 12  # skip cmd, cmd_size and str offset
    name = get_string(base, offset)

    cmd_name = 'unknown'
    if cmd == 0xe:
        cmd_name = 'LC_LOAD_DYLINKER'
    elif cmd == 0xf:
        cmd_name = 'LC_ID_DYLINKER'
    elif cmd == 0x27:
        cmd_name = 'LC_DYLD_ENVIRONMENT'

    output = {
        'cmd_name': cmd_name,
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

    cmd_name = 'unknown'
    if cmd == 0x21:
        cmd_name = 'LC_ENCRYPTION_INFO'
    elif cmd == 0x2c:
        cmd_name = 'LC_ENCRYPTION_INFO_64'

    output = {
        'cmd_name': cmd_name,
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
        'cmd_name': 'LC_MAIN',
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

    cmd_name = 'unknown'
    if cmd == 0x1d:
        cmd_name = 'LC_CODE_SIGNATURE'
    elif cmd == 0x1e:
        cmd_name = 'LC_SEGMENT_SPLIT_INFO'
    elif cmd == 0x26:
        cmd_name = 'LC_FUNCTION_STARTS'
    elif cmd == 0x29:
        cmd_name = 'LC_DATA_IN_CODE'
    elif cmd == 0x2b:
        cmd_name = 'LC_DYLIB_CODE_SIGN_DRS'
    elif cmd == 0x2e:
        cmd_name = 'LC_LINKER_OPTIMIZATION_HINT'
    elif cmd == 0x33 | LC_REQ_DYLD:
        cmd_name = 'LC_DYLD_EXPORTS_TRIE'
    elif cmd == 0x34 | LC_REQ_DYLD:
        cmd_name = 'LC_DYLD_CHAINED_FIXUPS'
    elif cmd == 0x36:
        cmd_name = 'LC_ATOM_INFO'

    output = {
        'cmd_name': cmd_name,
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
        'cmd_name': 'LC_SYMTAB',
        'cmd': '{:X}'.format(cmd),
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
        'cmd_name': 'LC_DYSYMTAB',
        'cmd': '{:X}'.format(cmd),
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


def parse_fat(header, combine=True):
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

        macho = parse_macho(header, offset, combine)
        machos.append(macho)

    return {'fat': {'n_machos': n_machos, 'machos': machos}}


def make_version(version):
    """Construct a version number from given bytes."""

    vx = version >> 16
    vy = (version >> 8) & 0xff
    vz = version & 0xff

    return '{}.{}.{}'.format(vx, vy, vz)


def parse_symseg(base, offset, cmd, cmd_size):
    """Parse link-edit gdb symbol table info (obsolete)."""

    offset += 8  # skip cmd and cmd_size
    struct_format = g_endian + '2I'
    sec_bytes = base[offset: offset + 8]
    off, size = struct.unpack(struct_format, sec_bytes)

    output = {
        'cmd_name': 'LC_SYMSEG',
        'cmd': '{:X}'.format(cmd),
        'cmd_size': cmd_size,
        'offset': off,
        'size': size,
    }

    return output


def parse_thread(base, offset, cmd, cmd_size):
    """Parse thread load command."""

    offset += 8  # skip cmd and cmd_size
    struct_format = g_endian + '2I'
    sec_bytes = base[offset: offset + 8]
    flavor, count = struct.unpack(struct_format, sec_bytes)

    cmd_name = 'unknown'
    if cmd == 0x4:
        cmd_name = 'LC_THREAD'
    elif cmd == 0x5:
        cmd_name = 'LC_UNIXTHREAD'

    output = {
        'cmd_name': cmd_name,
        'cmd': '{:X}'.format(cmd),
        'cmd_size': cmd_size,
        'flavor': flavor,
        'count': count,
    }

    return output


def parse_fvmlib(base, offset, cmd, cmd_size):
    """Parse fvmlib load command."""

    offset += 12  # skip cmd, cmd_size and str offset
    minor_version = get_int(base, offset)
    header_addr = get_int(base, offset + 4)
    name = get_string(base, offset + 8)

    cmd_name = 'unknown'
    if cmd == 0x6:
        cmd_name = 'LC_LOADFVMLIB'
    elif cmd == 0x7:
        cmd_name = 'LC_IDFVMLIB'

    output = {
        'cmd_name': cmd_name,
        'cmd': '{:X}'.format(cmd),
        'cmd_size': '{:X}'.format(cmd_size),
        'name': name,
        'minor_version': make_version(minor_version),
        'header_addr': header_addr
    }

    return output


def parse_ident(base, offset, cmd, cmd_size):
    """Parse object identification info (obsolete)."""

    output = {
        'cmd_name': 'LC_IDENT',
        'cmd': '{:X}'.format(cmd),
        'cmd_size': cmd_size,
        'strings': []
    }

    cursor = 8
    offset += 8
    while cursor < cmd_size:
        string = get_string(base, offset)

        if string != '':
            output['strings'].append(string)
            str_len = len(string)
            cursor += str_len
            offset += str_len

    return output


def parse_fvmfile(base, offset, cmd, cmd_size):
    """Parse fixed VM file inclusion (internal use)."""

    offset += 12  # skip cmd, cmd_size and str offset
    header_addr = get_int(base, offset + 4)
    name = get_string(base, offset + 8)

    output = {
        'cmd_name': 'LC_FVMFILE',
        'cmd': '{:X}'.format(cmd),
        'cmd_size': '{:X}'.format(cmd_size),
        'name': name,
        'header_addr': header_addr
    }

    return output


def parse_prebound_dylib(base, offset, cmd, cmd_size):
    """Parse prebound dylib load command.  An executable that is prebound to
    its dynamic libraries will have one of these for each library that the
    static linker used in prebinding.
    """

    offset += 12  # skip cmd, cmd_size and name offset
    name_off = get_int(base, offset)
    nmodules = get_int(base, offset + 4)
    nmodules_off = get_int(base, offset + 8)

    name = get_string(base, offset + name_off - 12)
    linked_modules = get_string(base, offset + nmodules_off - 12)

    output = {
        'cmd_name': 'LC_PREBOUND_DYLIB',
        'cmd': '{:X}'.format(cmd),
        'cmd_size': cmd_size,
        'name': name,
        'nmodules': nmodules,
        'linked_modules': linked_modules
    }

    return output


def parse_routines(base, offset, cmd, cmd_size):
    """Parse routines load command. The routines command contains the
    address of the dynamic shared library initialization routine and an
    index into the module table for the module that defines the routine.
    """

    offset += 8  # skip cmd and cmd_size
    struct_format = g_endian + '8I'
    sec_bytes = base[offset: offset + 32]
    init_address, init_module, reserved1, reserved2, reserved3, reserved4, reserved5, reserved6 = struct.unpack(struct_format, sec_bytes)

    output = {
        'cmd_name': 'LC_ROUTINES',
        'cmd': '{:X}'.format(cmd),
        'cmd_size': cmd_size,
        'init_address': init_address,
        'init_module': init_module,
        'reserved1': reserved1,
        'reserved2': reserved2,
        'reserved3': reserved3,
        'reserved4': reserved4,
        'reserved5': reserved5,
        'reserved6': reserved6,
    }

    return output


def parse_sub_stuff(base, offset, cmd, cmd_size):
    """Parse sub_* load command."""

    offset += 12  # skip cmd, cmd_size and name offset
    name = get_string(base, offset)

    cmd_name = 'unknown'
    if cmd == 0x12:
        cmd_name = 'LC_SUB_FRAMEWORK'
    elif cmd == 0x13:
        cmd_name = 'LC_SUB_UMBRELLA'
    elif cmd == 0x14:
        cmd_name = 'LC_SUB_CLIENT'
    elif cmd == 0x15:
        cmd_name = 'LC_SUB_LIBRARY'
    elif cmd == 0x1c | LC_REQ_DYLD:
        cmd_name = 'LC_RPATH'

    output = {
        'cmd_name': cmd_name,
        'cmd': '{:X}'.format(cmd),
        'cmd_size': '{:X}'.format(cmd_size),
        'name': name,
    }

    return output


def parse_twolevel_hints(base, offset, cmd, cmd_size):
    """Parse two-level hints load command."""

    offset += 8  # skip cmd and cmd_size
    hints_offset = get_int(base, offset)
    nhints = get_int(base, offset + 4)

    output = {
        'cmd_name': 'LC_TWOLEVEL_HINTS',
        'cmd': '{:X}'.format(cmd),
        'cmd_size': cmd_size,
        'offset': hints_offset,
        'nhints': nhints
    }

    return output


def parse_prebind_cksum(base, offset, cmd, cmd_size):
    """Parse prebind checksum load command."""

    offset += 8  # skip cmd and cmd_size
    cksum = get_int(base, offset)

    output = {
        'cmd_name': 'LC_PREBIND_CKSUM',
        'cmd': '{:X}'.format(cmd),
        'cmd_size': cmd_size,
        'cksum': cksum,
    }

    return output


def parse_routines_64(base, offset, cmd, cmd_size):
    """Parse routines load command 64. The routines command contains the
    address of the dynamic shared library initialization routine and an
    index into the module table for the module that defines the routine.
    """

    offset += 8  # skip cmd and cmd_size
    struct_format = g_endian + '8Q'
    sec_bytes = base[offset: offset + 64]
    init_address, init_module, reserved1, reserved2, reserved3, reserved4, reserved5, reserved6 = struct.unpack(struct_format, sec_bytes)

    output = {
        'cmd_name': 'LC_ROUTINES_64',
        'cmd': '{:X}'.format(cmd),
        'cmd_size': cmd_size,
        'init_address': init_address,
        'init_module': init_module,
        'reserved1': reserved1,
        'reserved2': reserved2,
        'reserved3': reserved3,
        'reserved4': reserved4,
        'reserved5': reserved5,
        'reserved6': reserved6,
    }

    return output


def parse_uuid(base, offset, cmd, cmd_size):
    """Parse UUID load command."""

    offset += 8  # skip cmd and cmd_size
    uuid_bytes = base[offset: offset + 16]

    output = {
        'cmd_name': 'LC_UUID',
        'cmd': '{:X}'.format(cmd),
        'cmd_size': cmd_size,
        'uuid': str(uuid.UUID(bytes=uuid_bytes)).upper()
    }

    return output


def parse_dyld_info(base, offset, cmd, cmd_size):
    """Parse dyld info load command. contains the file offsets and sizes of
    the new compressed form of the information dyld needs to load the
    image. This information is used by dyld on Mac OS X 10.6 and later. All
    information pointed to by this command is encoded using byte streams,
    so no endian swapping is needed to interpret it.
    """

    offset += 8  # skip cmd and cmd_size
    rebase_off = get_int(base, offset)              # file offset to rebase info
    rebase_size = get_int(base, offset + 4)         # size of rebase info
    bind_off = get_int(base, offset + 8)            # file offset to binding info
    bind_size = get_int(base, offset + 12)          # size of binding info
    weak_bind_off = get_int(base, offset + 16)      # file offset to weak binding info
    weak_bind_size = get_int(base, offset + 20)     # size of weak binding info
    lazy_bind_off = get_int(base, offset + 24)      # file offset to lazy binding info
    lazy_bind_size = get_int(base, offset + 28)     # size of lazy binding info
    export_off = get_int(base, offset + 32)         # file offset to export info
    export_size = get_int(base, offset + 36)        # size of offset info

    cmd_name = 'unknown'
    if cmd == 0x22:
        cmd_name = 'LC_DYLD_INFO'
    elif cmd == 0x22 | LC_REQ_DYLD:
        cmd_name = 'LC_DYLD_INFO_ONLY'

    output = {
        'cmd_name': cmd_name,
        'cmd': '{:X}'.format(cmd),
        'cmd_size': cmd_size,
        'rebase_off': rebase_off,
        'rebase_size': rebase_size,
        'bind_off': bind_off,
        'bind_size': bind_size,
        'weak_bind_off': weak_bind_off,
        'weak_bind_size': weak_bind_size,
        'lazy_bind_off': lazy_bind_off,
        'lazy_bind_size': lazy_bind_size,
        'export_off': export_off,
        'export_size': export_size
    }

    return output


def parse_version_min_os(base, offset, cmd, cmd_size):
    """Parse minimum OS version load command."""

    offset += 8  # skip cmd and cmd_size
    version = get_int(base, offset)
    sdk = get_int(base, offset + 4)

    cmd_name = 'unknown'
    if cmd == 0x24:
        cmd_name = 'LC_VERSION_MIN_MACOSX'
    elif cmd == 0x25:
        cmd_name = 'LC_VERSION_MIN_IPHONEOS'
    elif cmd == 0x2F:
        cmd_name = 'LC_VERSION_MIN_TVOS'
    elif cmd == 0x30:
        cmd_name = 'LC_VERSION_MIN_WATCHOS'

    output = {
        'cmd_name': cmd_name,
        'cmd': '{:X}'.format(cmd),
        'cmd_size': cmd_size,
        'version': make_version(version),
        'sdk': make_version(sdk)
    }

    return output


def parse_source_version(base, offset, cmd, cmd_size):
    """Parse source version load command."""

    offset += 8  # skip cmd and cmd_size
    version = get_int(base, offset)

    mask = 0b1111111111  # 10 bit mask for B, C, D, and E

    a = version >> 40
    b = (version >> 30) & mask
    c = (version >> 20) & mask
    d = (version >> 10) & mask
    e = version & mask

    output = {
        'cmd_name': 'LC_SOURCE_VERSION',
        'cmd': '{:X}'.format(cmd),
        'cmd_size': cmd_size,
        'version': '{}.{}.{}.{}.{}'.format(a, b, c, d, e)
    }

    return output


def parse_linker_option(base, offset, cmd, cmd_size):
    """Parse linker options load command."""

    offset += 8  # skip cmd and cmd_size
    count = get_int(base, offset)

    linker_options = []

    tmp_off = offset + 4
    for _ in range(count):
        string = get_string(base, tmp_off)
        linker_options.append(string)
        tmp_off += len(string)

    output = {
        'cmd_name': 'LC_LINKER_OPTION',
        'cmd': '{:X}'.format(cmd),
        'cmd_size': cmd_size,
        'count': count,
        'linker_options': linker_options
    }

    return output


def parse_note(base, offset, cmd, cmd_size):
    """Parse note load command."""

    offset += 8  # skip cmd and cmd_size
    data_owner = get_string(base, offset)
    offset = get_long(base, offset + 16)
    size = get_long(base, offset + 24)

    output = {
        'cmd_name': 'LC_NOTE',
        'cmd': '{:X}'.format(cmd),
        'cmd_size': cmd_size,
        'data_owner': data_owner,
        'offset': offset,
        'size': size
    }

    return output


def parse_build_version(base, offset, cmd, cmd_size):
    """Parse build version load command."""

    offset += 8  # skip cmd and cmd_size
    platform = get_int(base, offset)
    minos = get_int(base, offset + 4)
    sdk = get_int(base, offset + 8)
    ntools = get_int(base, offset + 12)

    PLATFORM_MACOS = 1
    PLATFORM_IOS = 2
    PLATFORM_TVOS = 3
    PLATFORM_WATCHOS = 4
    if platform == PLATFORM_MACOS:
        platform_str = 'MacOS ({})'.format(platform)
    elif platform == PLATFORM_IOS:
        platform_str = 'iOS ({})'.format(platform)
    elif platform == PLATFORM_TVOS:
        platform_str = 'TVOS ({})'.format(platform)
    elif platform == PLATFORM_WATCHOS:
        platform_str = 'WatchOS ({})'.format(platform)
    else:
        platform_str = str(platform)

    TOOL_CLANG = 1
    TOOL_SWIFT = 2
    TOOL_LD    = 3
    tools = []

    tmp_off = offset + 16
    for _ in range(ntools):
        tool = get_int(base, tmp_off)
        version = get_int(base, tmp_off + 4)

        if tool == TOOL_CLANG:
            tool_str = 'clang (1)'
        elif tool == TOOL_SWIFT:
            tool_str = 'swift (2)'
        elif tool == TOOL_LD:
            tool_str = 'ld (3)'
        else:
            tool_str = str(tool)

        tools.append({
            'tool': tool_str,
            'version': make_version(version),
        })
        tmp_off += 8

    output = {
        'cmd_name': 'LC_BUILD_VERSION',
        'cmd': '{:X}'.format(cmd),
        'cmd_size': cmd_size,
        'platform': platform_str,
        'minos': make_version(minos),
        'sdk': make_version(sdk),
        'ntools': ntools,
        'tools': tools
    }

    return output


def parse_fileset_entry(base, offset, cmd, cmd_size):
    """Parse fileset entry load command."""

    offset += 8  # skip cmd and cmd_size
    vmaddr = get_long(base, offset)
    fileoff = get_long(base, offset + 8)
    name_off = get_int(base, offset + 16)
    reserved = get_int(base, offset + 20)
    name = get_string(base, offset + name_off - 8)

    output = {
        'cmd_name': 'LC_FILESET_ENTRY',
        'cmd': '{:X}'.format(cmd),
        'cmd_size': cmd_size,
        'vmaddr': vmaddr,
        'fileoff': fileoff,
        'name': name,
        'reserved': reserved
    }

    return output