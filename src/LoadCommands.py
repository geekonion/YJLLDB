# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import util
import os


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "dump segments of the specified module" -f '
        'LoadCommands.dump_load_commands lcs')

    debugger.HandleCommand(
        'command script add -h "dump segments of the specified module" -f '
        'LoadCommands.dump_shared_libs libs')


def dump_load_commands(debugger, command, result, internal_dict):
    """
    dump load commands of the specified module
    implemented in YJLLDB/src/LoadCommands.py
    """
    handle_command(debugger, command, result, 'lcs')


def dump_shared_libs(debugger, command, result, internal_dict):
    """
    dump shared libs of the specified module
    implemented in YJLLDB/src/LoadCommands.py
    """
    handle_command(debugger, command, result, 'libs')


def handle_command(debugger, command, result, prog):
    # 去掉转义符
    command = command.replace('\\', '\\\\')
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command_args = shlex.split(command, posix=False)
    # 创建parser
    parser = generate_option_parser(prog)
    # 解析参数，捕获异常
    try:
        # options是所有的选项，key-value形式，args是其余剩余所有参数，不包含options
        (options, args) = parser.parse_args(command_args)
    except Exception as error:
        print(error)
        result.SetError("\n" + parser.get_usage())
        return

    n_args = len(args)
    if n_args == 0:
        target = debugger.GetSelectedTarget()
        file_spec = target.GetExecutable()
        name_or_addr = file_spec.GetFilename()
        full_path = str(file_spec)
        debug_dylib = full_path + '.debug.dylib'
        if os.path.exists(debug_dylib):
            name_or_addr += '.debug.dylib'
    elif n_args == 1:
        name_or_addr = args[0]
    else:
        result.AppendMessage(parser.get_usage())
        return

    cmd = None
    if prog == 'lcs':
        cmd = 'jtool -l {}'.format(name_or_addr)
    elif prog == 'libs':
        cmd = 'jtool -L {}'.format(name_or_addr)

    output = util.exe_command(cmd)
    result.AppendMessage(output)


def generate_option_parser(prog):
    usage = "usage: %prog [muodule name or header address]\n"

    parser = optparse.OptionParser(usage=usage, prog=prog)

    return parser
