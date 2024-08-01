# -*- coding: UTF-8 -*-
import os.path

import lldb
import optparse
import shlex
import util


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -h "print contents of Info.plist."'
                           ' -f InfoPlist.show_info_plist info_plist')


def show_info_plist(debugger, command, result, field):
    """
    print contents of Info.plist.
    implemented in YJLLDB/src/InfoPlist.py
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
        lookup_module_name = args[0]
    else:
        lookup_module_name = target.GetExecutable().GetFilename()

    lookup_module_name = lookup_module_name.replace("'", "")

    for module in target.module_iter():
        module_file_spec = module.GetFileSpec()
        module_name = module_file_spec.GetFilename()

        if lookup_module_name == module_name or lookup_module_name + '.dylib' == module_name:
            print("-----parsing module %s-----" % module_name)
            bundle_path = module_file_spec.GetDirectory()
            if bundle_path.endswith('/MacOS'):
                bundle_path = bundle_path[:-6]

            info_plist_path = bundle_path + os.path.sep + "Info.plist"
            if not os.path.exists(info_plist_path):
                print("Info.plist not found")
                continue

            cmd_str = "/usr/local/bin/plistutil -i '{}' -f xml".format(info_plist_path)
            code, out, err = util.exe_shell_command(cmd_str)
            if code == 0:
                print(out)
            else:
                print(err)


def generate_option_parser():
    usage = "usage: %prog [module name]\n"

    parser = optparse.OptionParser(usage=usage, prog='info_plist')

    return parser
