# -*- coding: UTF-8 -*-

import lldb
import os
import optparse
import shlex
import util


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "find dead lock" -f DeadLock.find_dead_lock deadlock')


def find_dead_lock(debugger, command, result, internal_dict):
    """
    find dead lock
    implemented in YJLLDB/src/DeadLock.py
    """
    # 去掉转义符
    command = command.replace('\\', '\\\\')
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command = command.replace("(", "")
    command = command.replace(")", "")
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

    addr_list = [int(x, 16) for x in args]

    for thread in process:
        frame0 = thread.GetFrameAtIndex(0)
        func_name = frame0.GetFunctionName()
        if not func_name or 'wait' not in func_name:
            continue

        for frame in thread:
            GPRs = util.get_GPRs(frame)
            found = False
            for register in GPRs:
                reg_value = register.GetValue()
                if reg_value in args:
                    print('found {}, thread {} frame #{}: {}'.
                          format(reg_value, thread.GetIndexID(), frame.GetFrameID(), frame.GetFunctionName()))
                    found = True
                    break

            if not found:
                symbol = frame.GetSymbol()
                inst_list = symbol.GetInstructions(target)

                adrp_ins = None
                adrp_addr = None
                adrp_op_list = None
                for inst in inst_list:
                    if inst.GetMnemonic(target) == 'adrp':
                        adrp_ins = inst
                        adrp_addr = adrp_ins.GetAddress().GetLoadAddress(target)
                        adrp_ins_ops = adrp_ins.GetOperands(target).replace(' ', '')
                        adrp_op_list = adrp_ins_ops.split(',')
                    elif adrp_ins and inst.GetMnemonic(target) == 'add':
                        add_ins_ops = inst.GetOperands(target).replace(' ', '')
                        add_op_list = add_ins_ops.split(',')
                        if len(add_op_list) != 3:
                            continue

                        if '#' not in add_op_list[2]:
                            continue

                        adrp_offset = int(add_op_list[2].replace('#', ''), 16)
                        target_addr = (adrp_addr & 0xFFFFFFFFFFFFF000) + (int(adrp_op_list[-1]) * 4096) + adrp_offset

                        adrp_ins = None
                        if target_addr in addr_list:
                            print('found {}, thread {} frame #{}: {}'.
                                  format(target_addr, thread.GetIndexID(), frame.GetFrameID(), frame.GetFunctionName()))
                            break


def generate_option_parser():
    usage = "usage: \n%prog lock_obj_addr"

    parser = optparse.OptionParser(usage=usage, prog='deadlock')

    return parser
