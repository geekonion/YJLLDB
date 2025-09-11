# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import util
import MachO
import os
import math
# import json


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "dump segments of the specified module" -f '
        'DumpSegments.dump_segments segments')


def dump_segments(debugger, command, result, internal_dict):
    """
    dump segments of the specified module
    implemented in YJLLDB/src/DumpSegments.py
    """
    # 去掉转义符
    command = command.replace('\\', '\\\\')
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command_args = shlex.split(command, posix=False)
    # 创建parser
    parser = generate_option_parser()
    # 解析参数，捕获异常
    try:
        # options是所有的选项，key-value形式，args是其余剩余所有参数，不包含options
        (options, args) = parser.parse_args(command_args)
    except Exception as error:
        print(error)
        result.SetError("\n" + parser.get_usage())
        return

    target = debugger.GetSelectedTarget()
    is_address = False
    addr_str = None
    lookup_module_name = None
    if len(args) == 1:
        is_address, name_or_addr = util.parse_arg(args[0])
        if is_address:
            addr_str = name_or_addr
        else:
            lookup_module_name = name_or_addr
    else:
        file_spec = target.GetExecutable()
        lookup_module_name = file_spec.GetFilename()
        full_path = str(file_spec)
        debug_dylib = full_path + '.debug.dylib'
        if os.path.exists(debug_dylib):
            lookup_module_name += '.debug.dylib'

    if is_address:
        header_addr = int(addr_str, 16)
        header_size  = 0x4000
        result.AppendMessage(parse_macho(target, header_addr, header_size, 0))
        return

    for module in target.module_iter():
        seg_info = ''
        module_file_spec = module.GetFileSpec()
        module_name = module_file_spec.GetFilename()

        dylib_name = lookup_module_name + '.dylib'
        if lookup_module_name == module_name or dylib_name == module_name:
            seg = module.FindSection('__TEXT')
            if not seg:
                result.AppendMessage('seg __TEXT not found in {}'.format(module_name))
                continue

            result.AppendMessage("-----parsing module %s-----" % module_name)
            header_addr = seg.GetLoadAddress(target)
            slide = header_addr - seg.GetFileAddress()

            first_sec = seg.GetSubSectionAtIndex(0)
            sec_addr = first_sec.GetLoadAddress(target)
            header_size = sec_addr - header_addr

            seg_info += parse_macho(target, header_addr, header_size, slide)

        result.AppendMessage(seg_info)


def parse_macho(target, header_addr, header_size, slide):
    error = lldb.SBError()
    header_data = target.ReadMemory(lldb.SBAddress(header_addr, target), header_size, error)
    if not error.Success():
        return 'read header failed! {}\n'.format(error.GetCString())

    info = MachO.parse_header(header_data)
    if slide == 0:
        slide = header_addr - int(info['text_vmaddr'], 16)

    lcs = info['lcs']
    # print(json.dumps(lcs, indent=2))
    seg_info = '         [start, end)\t\t\tsize\t\tname\t\t\t\tprot/flags\n'
    for lc in lcs:
        cmd = lc['cmd']
        if cmd == '19':  # LC_SEGMENT_64
            seg_start = slide + int(lc['vmaddr'], 16)
            seg_size = int(lc['vmsize'], 16)
            seg_end = seg_start + seg_size
            seg_name = lc['name']
            initprot = prot_str_from_value(lc['initprot'])
            maxprot = prot_str_from_value(lc['maxprot'])
            name_len = len(seg_name)
            num = math.ceil(name_len / 4)

            seg_info += '-' * 100 + '\n'
            seg_info += '[0x{:<9x}, 0x{:<9x})\t\t0x{:<9x} {}{}{}/{}\n'. \
                format(seg_start, seg_end, seg_size, seg_name, (6 - num) * '\t', initprot, maxprot)

            sects = lc['sects']

            if seg_name == '__LINKEDIT':
                linkedit_offset = int(lc['offset'], 16)
                linkedit_vmaddr = int(lc['vmaddr'], 16)

                for sect in sects:
                    dataoff = int(sect['offset'], 16)
                    datasize = int(sect['size'], 16)
                    data_start = linkedit_vmaddr + slide + dataoff - linkedit_offset
                    data_end = data_start + datasize
                    seg_info += '\t[0x{:<9x}, 0x{:<9x})\t0x{:<9x}   {}\n'. \
                        format(data_start, data_end, datasize, sect['name'])
            else:
                for sect in sects:
                    sec_name = sect['name']
                    sec_start = slide + int(sect['addr'], 16)
                    sec_size = int(sect['size'], 16)
                    sec_end = sec_start + sec_size
                    sec_flags = flags_str_from_value(int(sect['flags'], 16))

                    name_len = len(sec_name)
                    num = math.ceil((name_len - 1) / 4)
                    seg_info += '\t[0x{:<9x}, 0x{:<9x})\t0x{:<9x}   {}{}{}\n'. \
                        format(sec_start, sec_end, sec_size, sec_name, '\t' * (5 - num), sec_flags[:-1])

    return seg_info


def prot_str_from_value(value):
    VM_PROT_READ = 0x01  # read permission
    VM_PROT_WRITE = 0x02  # write permission
    VM_PROT_EXECUTE = 0x04  # execute permission

    des_str = ''
    if value & VM_PROT_READ == VM_PROT_READ:
        des_str += 'r'
    else:
        des_str += '-'

    if value & VM_PROT_WRITE == VM_PROT_WRITE:
        des_str += 'w'
    else:
        des_str += '-'

    if value & VM_PROT_EXECUTE == VM_PROT_EXECUTE:
        des_str += 'x'
    else:
        des_str += '-'

    return des_str


def flags_str_from_value(value):
    SECTION_TYPE = 0x000000ff

    sec_types = {
        0x0: 'S_REGULAR', # regular section
        0x1: 'S_ZEROFILL', # zero fill on demand section
        0x2: 'S_CSTRING_LITERALS', # section with only literal C strings
        0x3: 'S_4BYTE_LITERALS', # section with only 4 byte literals
        0x4: 'S_8BYTE_LITERALS', # section with only 8 byte literals
        0x5: 'S_LITERAL_POINTERS', # section with only pointers to literals

        0x6: 'S_NON_LAZY_SYMBOL_POINTERS', # section with only non-lazy symbol pointers
        0x7: 'S_LAZY_SYMBOL_POINTERS', # section with only lazy symbol pointers
        0x8: 'S_SYMBOL_STUBS', # section with only symbol stubs, byte size of stub in the reserved2 field
        0x9: 'S_MOD_INIT_FUNC_POINTERS', # section with only function pointers for initialization
        0xa: 'S_MOD_TERM_FUNC_POINTERS', # section with only function pointers for termination
        0xb: 'S_COALESCED', # section contains symbols that are to be coalesced
        0xc: 'S_GB_ZEROFILL', # zero fill on demand section (that can be larger than 4 gigabytes)
        0xd: 'S_INTERPOSING', # section with only pairs of function pointers for interposing
        0xe: 'S_16BYTE_LITERALS', # section with only 16 byte literals
        0xf: 'S_DTRACE_DOF', # section contains DTrace Object Format
        0x10: 'S_LAZY_DYLIB_SYMBOL_POINTERS', # section with only lazy symbol pointers to lazy loaded dylibs

        0x11: 'S_THREAD_LOCAL_REGULAR', # template of initial values for TLVs
        0x12: 'S_THREAD_LOCAL_ZEROFILL', # template of initial values for TLVs
        0x13: 'S_THREAD_LOCAL_VARIABLES', # TLV descriptors
        0x14: 'S_THREAD_LOCAL_VARIABLE_POINTERS', # pointers to TLV descriptors
        0x15: 'S_THREAD_LOCAL_INIT_FUNCTION_POINTERS', # functions to call to initialize TLV values
        0x16: 'S_INIT_FUNC_OFFSETS', # 32-bit offsets to initializers
    }

    S_ATTR_PURE_INSTRUCTIONS = 0x80000000  # section contains only true machine instructions
    S_ATTR_NO_TOC = 0x40000000  # section contains coalesced symbols that are not to be in a ranlib table of contents
    S_ATTR_STRIP_STATIC_SYMS = 0x20000000  # ok to strip static symbols in this section in files with the MH_DYLDLINK flag
    S_ATTR_NO_DEAD_STRIP = 0x10000000  # no dead stripping
    S_ATTR_LIVE_SUPPORT = 0x08000000  # blocks are live if they reference live blocks
    S_ATTR_SELF_MODIFYING_CODE = 0x04000000  # Used with i386 code stubs
    S_ATTR_DEBUG = 0x02000000  # a debug section
    SECTION_ATTRIBUTES_SYS = 0x00ffff00  # system setable attributes
    S_ATTR_SOME_INSTRUCTIONS = 0x00000400  # section contains some machine instructions
    S_ATTR_EXT_RELOC = 0x00000200  # section has external relocation entries
    S_ATTR_LOC_RELOC = 0x00000100  # section has local relocation entries

    des_str = ''

    # section type
    type_value = value & SECTION_TYPE
    des_str += sec_types[type_value] + ' '

    # section attributes part of the flags field
    if value & S_ATTR_PURE_INSTRUCTIONS == S_ATTR_PURE_INSTRUCTIONS:
        des_str += 'S_ATTR_PURE_INSTRUCTIONS '

    if value & S_ATTR_NO_TOC == S_ATTR_NO_TOC:
        des_str += 'S_ATTR_NO_TOC '

    if value & S_ATTR_STRIP_STATIC_SYMS == S_ATTR_STRIP_STATIC_SYMS:
        des_str += 'S_ATTR_STRIP_STATIC_SYMS '

    if value & S_ATTR_NO_DEAD_STRIP == S_ATTR_NO_DEAD_STRIP:
        des_str += 'S_ATTR_NO_DEAD_STRIP '

    if value & S_ATTR_LIVE_SUPPORT == S_ATTR_LIVE_SUPPORT:
        des_str += 'S_ATTR_LIVE_SUPPORT '

    if value & S_ATTR_SELF_MODIFYING_CODE == S_ATTR_SELF_MODIFYING_CODE:
        des_str += 'S_ATTR_SELF_MODIFYING_CODE '

    if value & S_ATTR_DEBUG == S_ATTR_DEBUG:
        des_str += 'S_ATTR_DEBUG '

    if value & SECTION_ATTRIBUTES_SYS == SECTION_ATTRIBUTES_SYS:
        des_str += 'SECTION_ATTRIBUTES_SYS '

    if value & S_ATTR_SOME_INSTRUCTIONS == S_ATTR_SOME_INSTRUCTIONS:
        des_str += 'S_ATTR_SOME_INSTRUCTIONS '

    if value & S_ATTR_EXT_RELOC == S_ATTR_EXT_RELOC:
        des_str += 'S_ATTR_EXT_RELOC '

    if value & S_ATTR_LOC_RELOC == S_ATTR_LOC_RELOC:
        des_str += 'S_ATTR_LOC_RELOC '

    return des_str


def generate_option_parser():
    usage = "usage: %prog [ModuleName]\n"

    parser = optparse.OptionParser(usage=usage, prog='segments')

    return parser
