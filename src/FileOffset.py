# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "file offset for address" -f '
        'FileOffset.get_file_offset offset')


def get_file_offset(debugger, command, result, internal_dict):
    """
    file offset for address, default address is current pc
    implemented in YJLLDB/src/FileOffset.py
    """
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

    if len(args) == 0:
        process = target.GetProcess()
        thread = process.GetSelectedThread()

        frame = thread.GetSelectedFrame()
        pc = frame.GetPC()
        addresses = [pc]
    else:
        addresses = [int(arg, 16) for arg in args]

    for address in addresses:
        addr_obj = target.ResolveLoadAddress(address)
        file_offset = addr_obj.GetFileAddress()
        print('addr: {:#x} -> file offset: {:#x}'.format(address, file_offset))


def generate_option_parser():
    usage = "usage: %prog [address]\n" + \
        "   default address is current pc"

    parser = optparse.OptionParser(usage=usage, prog='offset')

    return parser