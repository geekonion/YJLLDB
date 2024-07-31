# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import util


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "print the address of main function" -f '
        'EntryPoint.get_main main')

    debugger.HandleCommand(
        'command script add -h "print the address of main function" -f '
        'EntryPoint.break_main bmain')


def get_main(debugger, command, result, internal_dict):
    """
    print the address of main function
    implemented in YJLLDB/src/EntryPoint.py
    """
    handle_command(debugger, command, result, 'print')


def break_main(debugger, command, result, internal_dict):
    """
    break the main function
    implemented in YJLLDB/src/EntryPoint.py
    """
    handle_command(debugger, command, result, 'break')


def handle_command(debugger, command, result, action):
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
    file_spec = target.GetExecutable()
    module = target.FindModule(file_spec)

    header_addr = module.GetObjectFileHeaderAddress().GetLoadAddress(target)
    main_addr_obj = module.GetObjectFileEntryPointAddress()
    main_addr = main_addr_obj.GetLoadAddress(target)
    entry_offset = main_addr - header_addr

    if action == 'print':
        result.AppendMessage("function main at 0x{:x}, fileoff: 0x{:x}".format(main_addr, entry_offset))
    else:
        brkpoint = target.BreakpointCreateBySBAddress(main_addr_obj)
        # 判断下断点是否成功
        if not brkpoint.IsValid() or brkpoint.num_locations == 0:
            result.AppendMessage("Breakpoint isn't valid or hasn't found any hits")
        else:
            result.AppendMessage("Breakpoint {}: {}, address = 0x{:x}"
                                 .format(brkpoint.GetID(), util.get_desc_for_address(main_addr_obj), main_addr)
                                 )


def generate_option_parser():
    usage = "usage: %prog\n"

    parser = optparse.OptionParser(usage=usage, prog='main')

    return parser
