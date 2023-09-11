# -*- coding: UTF-8 -*-

import json
import struct

macho_magics = {
    0xFEEDFACE: (False, False),  # 32 bit, big endian
    0xFEEDFACF: (True, False),  # 64 bit, big endian
    0xCEFAEDFE: (False, True),  # 32 bit, little endian
    0xCFFAEDFE: (True, True),  # 64 bit, little endian
}
g_is_64_bit = True
g_byteorder = 'big'


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
    global g_byteorder, g_is_64_bit
    magic = int.from_bytes(base[offset:offset + 4], byteorder='big')
    g_is_64_bit, is_little_endian = macho_magics[magic]

    if is_little_endian:
        endian = '<'
        g_byteorder = 'little'
        magic = int.from_bytes(base[offset:offset + 4], byteorder=g_byteorder)
    else:
        endian = '>'
        g_byteorder = 'big'

    header_bytes = base[offset + 4:offset + 24]
    cputype, subtype, filetype, ncmds, scmds = struct.unpack(endian + '2i3I', header_bytes)
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
            macho['lcs'].append(parse_segment(base, offset, cmd, cmd_size))
        elif cmd in (0x21, 0x2C):  # ('ENCRYPTION_INFO', 'ENCRYPTION_INFO_64')
            macho['lcs'].append(parse_encryption_info(base, offset, cmd, cmd_size))
        elif cmd == 0x28 | 0x80000000:  # LC_MAIN (0x28|LC_REQ_DYLD)
            macho['lcs'].append(parse_main(base, offset, cmd, cmd_size))
        elif cmd == 0x1D:  # LC_CODE_SIGNATURE
            macho['lcs'].append(parse_linkedit_data(base, offset, cmd, cmd_size))

        offset += cmd_size


def parse_segment(base, m_offset, cmd, cmd_size):
    """Parse LC_SEGMENT(_64)."""

    if g_is_64_bit:
        seg_size = 72   # sizeof(struct segment_command_64)
        sect_size = 80  # sizeof(struct section_64)
        struct_format = '<2I16s4Q2i2I'
    else:
        seg_size = 56   # sizeof(struct segment_command)
        sect_size = 68  # sizeof(struct section)
        struct_format = '<2I16s4I2i2I'

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
        'lc_offset': m_offset
    }

    for _ in range(nsects):
        output['sects'].append(parse_section(base, m_offset + seg_size))

        m_offset += sect_size

    # print(json.dumps(output, indent=2))

    return output


def parse_section(base, m_offset):
    """Parse section."""

    if g_is_64_bit:
        read_size = 52
        struct_format = '<16s16s2QI'
    else:
        read_size = 44
        struct_format = '<16s16s3I'

    sec_bytes = base[m_offset: m_offset + read_size]
    sec_name, seg_name, addr, size, offset = struct.unpack(struct_format, sec_bytes)

    sec_name = sec_name.strip(b'\x00').decode()
    seg_name = seg_name.strip(b'\x00').decode()
    output = {
        'name': sec_name,
        'segname': seg_name,
        'addr': '{:X}'.format(addr),
        'offset': '{:X}'.format(offset),
        'size': '{:X}'.format(size),
        'lc_offset': m_offset
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


def get_int(base, offset, byteorder=None):
    if byteorder:
        return int.from_bytes(base[offset:offset + 4], byteorder=byteorder)
    else:
        return int.from_bytes(base[offset:offset + 4], byteorder=g_byteorder)


def get_long(base, offset, byteorder=None):
    if byteorder:
        return int.from_bytes(base[offset:offset + 8], byteorder=byteorder)
    else:
        return int.from_bytes(base[offset:offset + 8], byteorder=g_byteorder)


def get_string(base, offset, length):
    return base[offset:offset + length].strip(b'\x00').decode()
