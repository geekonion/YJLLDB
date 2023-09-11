# -*- coding: UTF-8 -*-

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
    if args:
        lookup_module_name = ''.join(args)
    else:
        file_spec = target.GetExecutable()
        lookup_module_name = file_spec.GetFilename()

    for module in target.module_iter():
        seg_info = ''
        module_file_spec = module.GetFileSpec()
        module_name = module_file_spec.GetFilename()

        if lookup_module_name in module_name:
            seg = module.FindSection('__TEXT')
            if not seg:
                result.AppendMessage('seg __TEXT not found in {}'.format(module_name))
                continue

            result.AppendMessage("-----parsing module %s-----" % module_name)
            header_addr = seg.GetLoadAddress(target)
            slide = header_addr - seg.GetFileAddress()

            first_sec = seg.GetSubSectionAtIndex(0)
            sec_addr = first_sec.GetLoadAddress(target)

            error = lldb.SBError()
            header_size = sec_addr - header_addr
            header_data = target.ReadMemory(lldb.SBAddress(header_addr, target), header_size, error)
            if not error.Success():
                result.AppendMessage('read header failed! {}'.format(error.GetCString()))
                break

            info = MachO.parse_header(header_data)

            lcs = info['lcs']
            seg_info += '       [start - end)\t\t\tsize\t\tname\n'
            for lc in lcs:
                cmd = lc['cmd']
                if cmd == '19':  # LC_SEGMENT_64
                    seg_start = slide + int(lc['vmaddr'], 16)
                    seg_size = int(lc['vmsize'], 16)
                    seg_end = seg_start + seg_size
                    seg_name = lc['name']
                    seg_info += '-' * 60 + '\n'
                    seg_info += '[0x{:<9x}-0x{:<9x})\t\t0x{:<9x} {}\n'.\
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
                            seg_info += '\t[0x{:<9x}-0x{:<9x})\t0x{:<9x}   {}\n'.\
                                format(sec_start, sec_end, sec_size, sect['name'])

        result.AppendMessage(seg_info)


def generate_option_parser():
    usage = "usage: %prog ModuleName\n"

    parser = optparse.OptionParser(usage=usage, prog='segments')

    return parser
