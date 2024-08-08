# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import os
import util
import FileOperations

g_file_path = os.path.realpath(__file__)
g_dir_name = os.path.dirname(os.path.dirname(g_file_path))
g_framework_name = 'DebugKit.framework'
g_frameworks_dir = os.path.join(g_dir_name, 'Frameworks')


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -h "load DebugKit." -f DebugKit.begin_debug debugkit')
    debugger.HandleCommand('command script add -h "show vm map info." -f DebugKit.vmmap vmmap')


def begin_debug(debugger, command, result, field):
    """
    load DebugKit.
    implemented in YJLLDB/src/DebugKit.py
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
    process = target.GetProcess()

    debug_kit_module = target.module['DebugKit']
    if debug_kit_module:
        debug_kit_uuid = debug_kit_module.GetUUIDString()
    else:
        debug_kit_uuid = None

    is_Mac = target.GetTriple().find('apple-macosx') > 0

    if is_Mac:
        platform_name = 'MacOSX'
    else:
        platform_name = 'iOS'

    src_framework_path = os.path.join(g_frameworks_dir, platform_name, g_framework_name)
    src_framework_exe = os.path.join(src_framework_path, 'DebugKit')
    code, output, err = util.exe_shell_command("dwarfdump --uuid '{}'".format(src_framework_exe))
    if err:
        result.SetError('Failed to obtain the uuid of DebugKit, {}'.format(err))
        return

    if code != 0:
        result.SetError('Failed to obtain the uuid of DebugKit')
        return

    if debug_kit_uuid and debug_kit_uuid in output:
        result.AppendMessage('DebugKit loaded')
        return

    if is_Mac:
        framework_exe = src_framework_exe
    else:
        print('loading DebugKit, this may take a while')
        doc_path = util.exe_command('doc_dir')
        upload_dir(src_framework_path, doc_path, g_framework_name)

        framework_exe = os.path.join(doc_path, g_framework_name, 'DebugKit')

    file_spec = lldb.SBFileSpec(framework_exe)
    error = lldb.SBError()
    process.LoadImage(file_spec, error)
    if error.Success():
        result.AppendMessage('DebugKit loaded')
    else:
        result.SetError(error.GetCString())


def upload_dir(src, dst, framework_name):
    for root, dirs, files in os.walk(src):
        for file in files:
            if file == '.DS_Store':
                continue

            # 处理文件
            file_path = os.path.join(root, file)
            rel_path = file_path.replace(src + os.path.sep, '')
            dst_path = os.path.join(dst, framework_name, rel_path)
            FileOperations.do_upload_file(file_path, dst_path)


def vmmap(debugger, command, result, field):
    """
    show vm map info.
    implemented in YJLLDB/src/DebugKit.py
    """

    # 去掉转义符
    command = command.replace('\\', '\\\\')
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command_args = shlex.split(command, posix=False)
    # 创建parser
    parser = generate_option_parser_vmmap()
    # 解析参数，捕获异常
    try:
        # options是所有的选项，key-value形式，args是其余剩余所有参数，不包含options
        (options, args) = parser.parse_args(command_args)
    except Exception as error:
        print(error)
        result.SetError("\n" + parser.get_usage())
        return

    target = debugger.GetSelectedTarget()
    is_Mac = target.GetTriple().find('apple-macosx') > 0
    if is_Mac:
        print('unsupported')
        return

    module = target.module['DebugKit']
    if not module:
        print('DebugKit not loaded, Please run the "debugkit" command to load it.')
        return

    nargs = len(args)

    target_address = 0
    if nargs == 0:
        pass
    elif nargs == 1:
        arg_str = args[0]
        is_addr, addr_str = util.parse_arg(arg_str)
        if not is_addr:
            print('input argument is neither an address nor a variable that refers to an address.')
            result.SetError("\n" + parser.get_usage())
            return

        target_address = int(addr_str, 16)
    else:
        print('unsupported')
        result.SetError("\n" + parser.get_usage())
        return

    if options.introspect:
        introspect = 'YES'
    else:
        introspect = 'NO'

    if options.verbose:
        verbose = 'YES'
    else:
        verbose = 'NO'

    info = util.exe_command('po [objc_getClass("DKVMMap") vmmapWithAddress:{} introspect:{} verbose:{}]'.
                            format(target_address, introspect, verbose))
    result.AppendMessage(info)


def generate_option_parser():
    usage = "usage: %prog\n"

    parser = optparse.OptionParser(usage=usage, prog='debugkit')

    return parser


def generate_option_parser_vmmap():
    usage = "usage: %prog [address]\n"

    parser = optparse.OptionParser(usage=usage, prog='vmmap')
    parser.add_option("-i", "--introspect",
                      action='store_false',
                      default=True,
                      dest="introspect",
                      help="perform module introspection")

    parser.add_option("-v", "--verbose",
                      action='store_true',
                      default=False,
                      dest="verbose",
                      help="verbose output")

    return parser
