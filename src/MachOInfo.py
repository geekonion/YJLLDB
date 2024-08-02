# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import util
import MachO
import json
import MachOHelper
import os


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -h "print codesign entitlements of the specified module if any."'
                           ' -f MachOInfo.show_entitlements entitlements')

    debugger.HandleCommand('command script add -h "print group id in codesign entitlements of the specified '
                           'module if any." -f MachOInfo.show_group_id group_id')

    debugger.HandleCommand('command script add -h "print bundle id in codesign entitlements of the specified '
                           'module if any." -f MachOInfo.show_bundle_id bundle_id')

    debugger.HandleCommand('command script add -h "print team id in codesign entitlements of the specified '
                           'module if any." -f MachOInfo.show_team_id team_id')

    debugger.HandleCommand(
        'command script add -h "print executable name."'
        ' -f MachOInfo.show_executable_name executable')

    debugger.HandleCommand('command script add -h "parse mach-o of user modules." -f MachOInfo.parse_macho macho')


def show_entitlements(debugger, command, result, internal_dict):
    """
    print codesign entitlements of the specified module if any.
    implemented in YJLLDB/src/MachOInfo.py
    """
    result.AppendMessage(parse_entitlements(debugger, command, result, 'entitlements'))


def show_group_id(debugger, command, result, internal_dict):
    """
    print group id in codesign entitlements of the specified module if any.
    implemented in YJLLDB/src/MachOInfo.py
    """
    result.AppendMessage(parse_entitlements(debugger, command, result, 'group_id'))


def show_bundle_id(debugger, command, result, internal_dict):
    """
    print bundle id in codesign entitlements of the specified module if any.
    implemented in YJLLDB/src/MachOInfo.py
    """
    result.AppendMessage(parse_entitlements(debugger, command, result, 'bundle_id'))


def show_team_id(debugger, command, result, internal_dict):
    """
    print team id in codesign entitlements of the specified module if any.
    implemented in YJLLDB/src/MachOInfo.py
    """
    result.AppendMessage(parse_entitlements(debugger, command, result, 'team_id'))


def parse_entitlements(debugger, command, result, field):
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
    if field != 'entitlements' and target.GetTriple().find('apple-macosx') > 0:
        print('MacOSX not supported')
        return

    if args:
        module_name = ''.join(args)
    else:
        file_spec = target.GetExecutable()
        module_name = file_spec.GetFilename()

    module_name = module_name.replace("'", "")
    entitlements = MachOHelper.get_entitlements(module_name)
    # entitlements = get_entitlements(debugger, module_name)
    if not entitlements:
        return entitlements
    elif 'does not contain' in entitlements:
        return entitlements

    if field == 'entitlements':
        return entitlements
    elif field == 'group_id':
        ent_dict = util.parse_info_plist(entitlements)
        group_ids = ent_dict.get('com.apple.security.application-groups')
        if group_ids:
            return '{}'.format(group_ids)
        else:
            return 'group id not found'
    elif field == 'bundle_id':
        ent_dict = util.parse_info_plist(entitlements)
        return '{}'.format(ent_dict.get('application-identifier'))
    elif field == 'team_id':
        ent_dict = util.parse_info_plist(entitlements)
        return '{}'.format(ent_dict.get('com.apple.developer.team-identifier'))


def show_executable_name(debugger, command, result, internal_dict):
    """
    print executable name
    implemented in YJLLDB/src/MachOInfo.py
    """
    target = debugger.GetSelectedTarget()
    result.AppendMessage(target.GetExecutable().GetFilename())


def parse_macho(debugger, command, result, internal_dict):
    """
    parse mach-o of user modules.
    implemented in YJLLDB/src/MachOInfo.py
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

    is_address = False
    addr_str = None
    lookup_module_name = None
    if len(args) == 1:
        is_address, name_or_addr = util.parse_arg(args[0])
        if is_address:
            addr_str = name_or_addr
        else:
            lookup_module_name = name_or_addr
    else:
        file_spec = target.GetExecutable()
        lookup_module_name = file_spec.GetFilename()
        full_path = str(file_spec)
        debug_dylib = full_path + '.debug.dylib'
        if os.path.exists(debug_dylib):
            lookup_module_name += '.debug.dylib'

    header_data = None
    if is_address:
        header_addr = int(addr_str, 16)
        header_size = 0x4000

        error = lldb.SBError()
        header_data = target.ReadMemory(lldb.SBAddress(header_addr, target), header_size, error)
        if not error.Success():
            result.AppendMessage('read header failed! {}'.format(error.GetCString()))
            return
    else:
        bundle_path = target.GetExecutable().GetDirectory()
        for module in target.module_iter():
            module_file_spec = module.GetFileSpec()
            module_dir = module_file_spec.GetDirectory()
            module_name = module_file_spec.GetFilename()

            if len(lookup_module_name):
                lib_name = lookup_module_name + '.dylib'
                if lookup_module_name != module_name and lib_name != module_name:
                    continue
            else:
                if bundle_path not in module_dir:
                    continue

            print("-----parsing module %s-----" % module_name)
            seg = module.FindSection('__TEXT')
            if not seg:
                result.AppendMessage('seg __TEXT not found')
                continue

            header_addr = seg.GetLoadAddress(target)
            first_sec = seg.GetSubSectionAtIndex(0)
            sec_addr = first_sec.GetLoadAddress(target)

            error = lldb.SBError()
            header_size = sec_addr - header_addr
            header_data = target.ReadMemory(lldb.SBAddress(header_addr, target), header_size, error)
            if not error.Success():
                result.AppendMessage('read header failed! {}'.format(error.GetCString()))
                continue

    info = MachO.parse_header(header_data)
    print(json.dumps(info, indent=2))


def generate_option_parser():
    usage = "usage: %prog [module name]\n"

    parser = optparse.OptionParser(usage=usage, prog='entitlements')

    return parser
