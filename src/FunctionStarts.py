# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import MachOHelper


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "dump function starts of the specified module" -f '
        'FunctionStarts.dump_function_starts func_starts')


def dump_function_starts(debugger, command, result, internal_dict):
    """
    dump function starts of the specified module
    implemented in YJLLDB/src/FunctionStarts.py
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

    funcs, module_file_spec = MachOHelper.get_function_starts(lookup_module_name)
    if not funcs:
        result.AppendMessage("module {} not found".format(lookup_module_name))
    else:
        total_count = 0
        if options.sort:
            funcs = sorted(funcs, key=lambda x: x[1])

        for func_start, func_size in funcs:
            func_addr = target.ResolveLoadAddress(func_start)
            result.AppendMessage('address = 0x{:x} size = {} where = {}'.format(func_start, func_size, func_addr))
            total_count += 1

        result.AppendMessage('{} function(s) found'.format(total_count))


def generate_option_parser():
    usage = "usage: %prog ModuleName\n"

    parser = optparse.OptionParser(usage=usage, prog='func_starts')

    parser.add_option("-s", "--sort",
                      action='store_true',
                      default=False,
                      dest="sort",
                      help="sort functions by function size")

    return parser
