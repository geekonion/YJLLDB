# -*- coding: UTF-8 -*-
import json

import lldb
import optparse
import shlex
import util
import MachO
import os
import math
# import json


lib_cache = {}

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "List the dependencies of a binary." -f Dependency.dependency dependency')


def dependency(debugger, command, result, internal_dict):
    """
    List the dependencies of a binary
    implemented in YJLLDB/src/Dependency.py
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
        input_arg = args[0]
    elif len(args) == 0:
        file_spec = target.GetExecutable()
        input_arg = file_spec.GetFilename()
    else:
        result.SetError("\n" + parser.get_usage())
        return

    app_name = None
    app_path = target.GetExecutable().GetDirectory()
    last_slash_pos = app_path.rfind('/')
    if last_slash_pos > 0:
        app_name = app_path[last_slash_pos:] + os.path.sep

    dep_info = parse_dependency_with(target, app_name, input_arg)
    lib_cache.clear()

    result.AppendMessage(json.dumps(dep_info, indent=2))


def parse_dependency_with(target, app_name, input_arg):
    addr_str = None
    lookup_module_name = None
    is_address, name_or_addr = util.parse_arg(input_arg)
    if is_address:
        addr_str = name_or_addr
    else:
        lookup_module_name = name_or_addr

    dependencies = None
    target_header_addr = 0
    if is_address:
        target_header_addr = int(addr_str, 16)

    for module in target.module_iter():
        module_file_spec = module.GetFileSpec()
        mod_path = str(module_file_spec)
        pos = mod_path.rfind(app_name)
        if pos == -1:
            continue

        module_name = module_file_spec.GetFilename()
        header_addr_obj = module.GetObjectFileHeaderAddress()
        header_addr = header_addr_obj.GetLoadAddress(target)

        if ((is_address and header_addr == target_header_addr)
                or lookup_module_name == module_name):
            seg = module.FindSection('__TEXT')
            if not seg:
                print('seg __TEXT not found in {}'.format(module_name))
                continue

            header_addr = seg.GetLoadAddress(target)

            first_sec = seg.GetSubSectionAtIndex(0)
            sec_addr = first_sec.GetLoadAddress(target)
            header_size = sec_addr - header_addr

            dependencies = parse_macho(target, app_name, header_addr, header_size)
            break

    if not dependencies:
        dependencies = []

    return dependencies


def parse_macho(target, app_name, header_addr, header_size):
    error = lldb.SBError()
    header_data = target.ReadMemory(lldb.SBAddress(header_addr, target), header_size, error)
    if not error.Success():
        return 'read header failed! {}\n'.format(error.GetCString())

    info = MachO.parse_header(header_data)

    lcs = info['lcs']
    # print(json.dumps(lcs, indent=2))
    deps = []
    for lc in lcs:
        cmd = lc['cmd']
        if cmd == 'C':  # LC_LOAD_DYLIB
            path = lc['name']
            if not lib_cache.get(path):
                deps.append({path: parse_dependency_with(target, app_name, os.path.basename(path))})
                lib_cache[path] = True
            else:
                deps.append({path: []})
        elif cmd == '80000018':  # LC_LOAD_WEAK_DYLIB
            path = lc['name']
            if not lib_cache.get(path):
                deps.append({path + ' (weak)': parse_dependency_with(target, app_name, os.path.basename(path))})
                lib_cache[path] = True
            else:
                deps.append({path: []})

    return deps


def generate_option_parser():
    usage = "usage: %prog [ModuleName]\n"

    parser = optparse.OptionParser(usage=usage, prog='dependency')

    return parser
