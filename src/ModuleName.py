# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import MachO
import util


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "get module name with header addr" -f '
        'ModuleName.get_module_name_with_header_addr mname')


def get_module_name_with_header_addr(debugger, command, result, internal_dict):
    """
    get module name with header addr
    implemented in YJLLDB/src/ModuleName.py
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
    if len(args) == 1:
        arg_str = args[0]
    else:
        result.AppendMessage(parser.get_usage())
        return

    is_addr, addr_str = util.parse_arg(arg_str)
    if not is_addr:
        result.SetError("\n" + parser.get_usage())
        return

    header_addr = int(addr_str, 16)

    header_size = 0x4000

    name = None
    for module in target.module_iter():
        module_header = module.GetObjectFileHeaderAddress()
        if header_addr == module_header.GetLoadAddress(target):
            module_file_spec = module.GetFileSpec()
            name = module_file_spec.GetFilename()
            break

    if not name:
        name = parse_macho(target, header_addr, header_size, 0)

    if not name:
        name = '未找到名字'

    result.AppendMessage(name)


def parse_macho(target, header_addr, header_size, slide):
    error = lldb.SBError()
    header_data = target.ReadMemory(lldb.SBAddress(header_addr, target), header_size, error)
    if not error.Success():
        return 'read header failed! {}\n'.format(error.GetCString())

    info = MachO.parse_header(header_data)
    lcs = info['lcs']
    name = None
    for lc in lcs:
        cmd = lc['cmd']
        if cmd == 'D':  # LC_ID_DYLIB
            name = lc['name']
            break

    return name


def generate_option_parser():
    usage = "usage: %prog addr\n"

    parser = optparse.OptionParser(usage=usage, prog='mname')

    return parser
