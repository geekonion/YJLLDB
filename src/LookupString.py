# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "lookup string between start addr and end addr" -f '
        'LookupString.lookup_string slookup')


def lookup_string(debugger, command, result, internal_dict):
    """
    lookup string between start addr and end addr
    implemented in YJLLDB/src/LookupString.py
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

    if len(args) != 3:
        result.AppendMessage(parser.get_usage())
        return

    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    error = lldb.SBError()

    arg0 = args[0]
    keyword_len = len(arg0)
    keyword = arg0.encode()
    start_addr = int(args[1], 16)
    end_addr = int(args[2], 16)
    page_size = 0x1000000

    addr = start_addr
    hits_count = 0
    while True:
        # -1防重复
        data = process.ReadMemory(addr, page_size + keyword_len - 1, error)
        if not data:
            break
        pos = data.find(keyword)
        while pos != -1:
            hits_count += 1
            hit_addr = pos + addr
            addr_obj = target.ResolveLoadAddress(hit_addr)
            if addr_obj:
                sec = addr_obj.GetSection()
                if sec:
                    print("found at 0x{:x} where = {}".format(hit_addr, sec))
                else:
                    print("found at 0x{:x} where = {}".format(hit_addr, addr_obj))
            else:
                print("found at 0x{:x}".format(hit_addr))

            pos = data.find(keyword, pos + keyword_len)

        addr += page_size
        del data
        if addr > end_addr:
            break

    result.AppendMessage("{} locations found".format(hits_count))


def generate_option_parser():
    usage = "usage: %prog string start_addr end_addr"

    parser = optparse.OptionParser(usage=usage, prog='slookup')

    return parser
