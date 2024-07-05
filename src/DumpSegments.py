# -*- coding: UTF-8 -*-
import json

import lldb
import optparse
import shlex
import util
import MachO


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

    if is_address:
        header_addr = int(addr_str, 16)
        header_size = 0x4000
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
    seg_info = '       [start - end)\t\t\tsize\t\tname\n'
    for lc in lcs:
        cmd = lc['cmd']
        if cmd == '19':  # LC_SEGMENT_64
            seg_start = slide + int(lc['vmaddr'], 16)
            seg_size = int(lc['vmsize'], 16)
            seg_end = seg_start + seg_size
            seg_name = lc['name']
            seg_info += '-' * 60 + '\n'
            seg_info += '[0x{:<9x}-0x{:<9x})\t\t0x{:<9x} {}\n'. \
                format(seg_start, seg_end, seg_size, seg_name)

            sects = lc['sects']

            if seg_name == '__LINKEDIT':
                linkedit_offset = int(lc['offset'], 16)
                linkedit_vmaddr = int(lc['vmaddr'], 16)

                for sect in sects:
                    dataoff = int(sect['offset'], 16)
                    datasize = int(sect['size'], 16)
                    data_start = linkedit_vmaddr + slide + dataoff - linkedit_offset
                    data_end = data_start + datasize
                    seg_info += '\t[0x{:<9x}-0x{:<9x})\t0x{:<9x}   {}\n'. \
                        format(data_start, data_end, datasize, sect['name'])
            else:
                for sect in sects:
                    sec_start = slide + int(sect['addr'], 16)
                    sec_size = int(sect['size'], 16)
                    sec_end = sec_start + sec_size
                    seg_info += '\t[0x{:<9x}-0x{:<9x})\t0x{:<9x}   {}\n'. \
                        format(sec_start, sec_end, sec_size, sect['name'])

    return seg_info


def generate_option_parser():
    usage = "usage: %prog [ModuleName]\n"

    parser = optparse.OptionParser(usage=usage, prog='segments')

    return parser
