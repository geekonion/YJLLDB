# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex


class BreakPointInfo:
    id = 0
    loc = 0


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "disable breakpoint(s) at the specified module" -f '
        'BreakpointDisableAtModule.disable_breakpoint_at bdm')


def disable_breakpoint_at(debugger, command, result, internal_dict):
    """
    disable breakpoint(s) at the specified module
    implemented in YJLLDB/src/BreakpointDisableAtModule.py
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
    bkpts_to_disable = []
    for bkpt in target.breakpoint_iter():
        for loc in bkpt:
            address = loc.GetAddress()
            module = address.GetModule()
            module_file_spec = module.GetFileSpec()
            module_name = module_file_spec.GetFilename()

            if module_name in args:
                bkpt_info = BreakPointInfo()
                bkpt_info.id = bkpt.GetID()
                bkpt_info.loc = loc.GetID()

                bkpts_to_disable.append(bkpt_info)

    for bkpt_info in bkpts_to_disable:
        bkpt = target.FindBreakpointByID(bkpt_info.id)
        loc = bkpt.FindLocationByID(bkpt_info.loc)
        loc.SetEnabled(False)

        print("disable breakpoint {}".format(loc))


def generate_option_parser():
    usage = "usage: %prog module_name\n" + \
            "for example:\n" + \
            "   %prog UIKit"

    parser = optparse.OptionParser(usage=usage, prog='bdm')

    return parser
