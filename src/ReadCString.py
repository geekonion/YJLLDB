# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import util


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "read memory region as c style string" -f '
        'ReadCString.read_cstring read_cstring')


def read_cstring(debugger, command, result, internal_dict):
    """
    read memory region as c style string
    implemented in YJLLDB/src/ReadCString.py
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

    if len(args) != 2:
        result.AppendMessage(parser.get_usage())
        return

    start_addr = int(args[0], 16)
    end_addr = int(args[1], 16)
    addr_size = end_addr - start_addr

    target = debugger.GetSelectedTarget()
    if options.encoding:
        ret = util.read_mem_as_cstring(target, start_addr, addr_size, options.encoding)
    else:
        ret = util.read_mem_as_cstring(target, start_addr, addr_size)
    result.AppendMessage(ret)


def generate_option_parser():
    usage = "usage: %prog start_addr end_addr"

    parser = optparse.OptionParser(usage=usage, prog='read_cstring')
    parser.add_option("-e", "--encoding",
                      action="store",
                      dest="encoding",
                      help="read memory with encoding, such as: utf-8, ISO-8859-1, ascii, gbk")

    return parser
