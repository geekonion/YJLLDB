# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import util
import MachO


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "dump function starts of the specified module" -f '
        'FunctionStarts.dump_function_starts func_starts')


def dump_function_starts(debugger, command, result, internal_dict):
    """
    dump function starts of the specified module
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

    byte_order = 'little' if target.GetByteOrder() == lldb.eByteOrderLittle else 'big'
    total_count = 0
    for module in target.module_iter():
        seg_info = ''
        module_file_spec = module.GetFileSpec()
        module_name = module_file_spec.GetFilename()

        if lookup_module_name not in module_name:
            continue
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
        for lc in lcs:
            cmd = lc['cmd']
            if cmd != '19':  # LC_SEGMENT_64
                continue

            seg_name = lc['name']
            if seg_name != '__LINKEDIT':
                continue

            linkedit_offset = int(lc['offset'], 16)
            linkedit_vmaddr = int(lc['vmaddr'], 16)

            sects = lc['sects']
            for sect in sects:
                sec_name = sect['name']
                if sec_name != 'Function Starts':
                    continue

                dataoff = int(sect['offset'], 16)
                datasize = int(sect['size'], 16)
                data_start = linkedit_vmaddr + slide + dataoff - linkedit_offset

                error1 = lldb.SBError()
                data_bytes = target.ReadMemory(lldb.SBAddress(data_start, target), datasize, error1)
                if not error1.Success():
                    result.AppendMessage('read data failed! {}'.format(error1.GetCString()))
                    break

                file_offset = 0
                idx = 0
                while idx < datasize:
                    offset = 0
                    bit = 0
                    while idx < datasize:
                        byte = data_bytes[idx: idx + 1]
                        byte_value = int.from_bytes(byte, byteorder=byte_order)
                        if byte_value == 0:
                            idx += 1
                            continue

                        slice = byte_value & 0x7f

                        if bit >= 64 or slice << bit >> bit != slice:
                            pass
                        else:
                            offset |= (slice << bit)
                            bit += 7

                        idx += 1
                        if byte_value & 0x80 == 0:
                            break

                    if offset > 0:
                        file_offset += offset
                        func_start = header_addr + file_offset
                        func_addr = target.ResolveLoadAddress(func_start)
                        result.AppendMessage('address = 0x{:x} where = {}'.format(func_start, func_addr))
                        total_count += 1
                break

            break

        result.AppendMessage('{} function(s) found'.format(total_count))


def generate_option_parser():
    usage = "usage: %prog ModuleName\n"

    parser = optparse.OptionParser(usage=usage, prog='func_starts')

    return parser
