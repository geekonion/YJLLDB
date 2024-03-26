# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import os


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "symbolic uncaught exception addresses list" -f '
        'Symbolic.symbolic_uncaught_exception symbolic')


def symbolic_uncaught_exception(debugger, command, result, internal_dict):
    """
    symbolic uncaught exception addresses list
    implemented in YJLLDB/src/Symbolic.py
    """
    # 去掉转义符
    command = command.replace('\\', '\\\\')
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command = command.replace("(", "")
    command = command.replace(")", "")
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
    main_module = target.GetModuleAtIndex(0)

    backtrace = ""
    addresses = [int(x, 16) for x in args]
    for index, addr in enumerate(addresses):
        addr_obj = target.ResolveLoadAddress(addr)
        symbol = addr_obj.GetSymbol()

        module = addr_obj.GetModule()
        module_name = "unknown"
        if module:
            module_file_spec = module.GetFileSpec()
            module_name = module_file_spec.GetFilename()

        if main_module.__eq__(module):
            line_entry = addr_obj.GetLineEntry()
            file_spec = line_entry.GetFileSpec()
            file_name = file_spec.GetFilename()
            offset = "at {}:{}:{}".format(file_name, line_entry.GetLine(), line_entry.GetColumn())
        else:
            offset = addr - symbol.GetStartAddress().GetLoadAddress(target)

        symbol_str = "frame #{}: 0x{:x} {}`{} + {}\n".format(index, addr, module_name, symbol.GetName(), offset)
        backtrace += symbol_str

    result.AppendMessage("backtrace: \n{}".format(backtrace))


def generate_option_parser():
    usage = "usage: %prog addr1 addr2 ...\n"

    parser = optparse.OptionParser(usage=usage, prog='symbolic')

    return parser
