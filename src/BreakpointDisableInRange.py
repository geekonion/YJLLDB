# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex


class BreakPointInfo:
    id = 0
    loc = 0


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "disable breakpoint(s) in the specified range" -f '
        'BreakpointDisableInRange.disable_breakpoint_in_range bdr')


def disable_breakpoint_in_range(debugger, command, result, internal_dict):
    """
    disable breakpoint(s) in the specified range
    implemented in YJLLDB/src/BreakpointDisableInRange.py
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

    if len(args) != 1:
        result.AppendMessage(parser.get_usage())
        return

    range_str = args[0]
    comps = None
    if '-' in range_str:
        comps = range_str.split('-')
    elif '~' in range_str:
        comps = range_str.split('~')

    if not comps or len(comps) != 2:
        result.AppendMessage(parser.get_usage())
        return

    start_id = int(comps[0])
    end_id = int(comps[1]) + 1

    target_range = range(start_id, end_id)

    target = debugger.GetSelectedTarget()
    bkpts_to_disable = []
    for bkpt in target.breakpoint_iter():
        brk_id = bkpt.GetID()
        if brk_id not in target_range:
            continue

        for loc in bkpt:
            bkpt_info = BreakPointInfo()
            bkpt_info.id = brk_id
            bkpt_info.loc = loc.GetID()

            bkpts_to_disable.append(bkpt_info)

    for bkpt_info in bkpts_to_disable:
        bkpt = target.FindBreakpointByID(bkpt_info.id)
        loc = bkpt.FindLocationByID(bkpt_info.loc)
        loc.SetEnabled(False)

        print("disable breakpoint {}".format(loc))


def generate_option_parser():
    usage = "usage: %prog [options] range\n" + \
            "for example:\n" + \
            "   %prog 100-150\n" + \
            "   or\n" + \
            "   %prog 100~150\n"

    parser = optparse.OptionParser(usage=usage, prog='bdr')

    return parser
