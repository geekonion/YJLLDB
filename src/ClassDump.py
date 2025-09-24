# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import util
import json

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -h "dump class info" -f ClassDump.class_dump cdump')


def class_dump(debugger, command, result, internal_dict):
    """
    dump class info
    implemented in YJLLDB/src/ClassDump.py
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

    n_args = len(args)
    if n_args == 1:
        class_name = args[0]
    else:
        result.AppendMessage(parser.get_usage())
        return

    target = debugger.GetSelectedTarget()

    types = target.FindTypes(class_name)
    for tmp_type in types:
        if tmp_type.GetTypeClass() != lldb.eTypeClassObjCInterface:
            continue

        class_info = str(tmp_type)

        func_info = ''
        nfunc = tmp_type.GetNumberOfMemberFunctions()
        for i in range(nfunc):
            func = tmp_type.GetMemberFunctionAtIndex(i)
            kind = func.GetKind()
            if kind == lldb.eMemberFunctionKindInstanceMethod:
                func_info += '-[{} {}]\n'.format(class_name, func.GetName())
            elif kind == lldb.eMemberFunctionKindStaticMethod:
                func_info += '+[{} {}]\n'.format(class_name, func.GetName())

        class_info = class_info.replace('@end', func_info + '@end')
        print(class_info)


def generate_option_parser():
    usage = "usage: %prog <class name>\n"

    parser = optparse.OptionParser(usage=usage, prog='cdump')

    return parser
