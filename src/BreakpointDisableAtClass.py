# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex


class BreakPointInfo:
    id = 0
    loc = 0


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "disable breakpoint(s) at the specified class" -f '
        'BreakpointDisableAtClass.disable_breakpoint_at bda')


def disable_breakpoint_at(debugger, command, result, internal_dict):
    """
    disable breakpoint(s) at the specified class
    implemented in YJLLDB/src/BreakpointDisableAtClass.py
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

    class_name = args[0]
    if options.class_method:
        prefix = '+[' + class_name + ' '
    elif options.instance_method:
        prefix = '-[' + class_name + ' '
    else:
        prefix = '[' + class_name + ' '

    target = debugger.GetSelectedTarget()
    bkpts_to_disable = []
    for bkpt in target.breakpoint_iter():
        for loc in bkpt:
            address = loc.GetAddress()
            symbol = address.GetSymbol()
            sym_name = symbol.GetName()

            if prefix in sym_name:
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
    usage = "usage: %prog [options] class_name\n" + \
            "for example:\n" + \
            "   %prog -i ViewController\n" + \
            "   or\n" + \
            "   %prog -i ViewController(extension_name)"

    parser = optparse.OptionParser(usage=usage, prog='bda')
    parser.add_option("-c", "--class_method",
                      action="store_true",
                      default=False,
                      dest="class_method",
                      help="only disable class method")
    parser.add_option("-i", "--instance_method",
                      action="store_true",
                      default=False,
                      dest="instance_method",
                      help="only disable instance method")

    return parser
