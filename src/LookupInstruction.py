# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "lookup the specified instruction in user modules" -f '
        'LookupInstruction.lookup_instructions ilookup')


def lookup_instructions(debugger, command, result, internal_dict):
    """
    lookup the specified instruction in user modules
    implemented in YJLLDB/src/LookupInstruction.py
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

    if len(args) == 0:
        result.AppendMessage(parser.get_usage())
        return

    input_args = ''.join(args)
    input_args = input_args.replace("'", "")
    input_args = input_args.replace("\"", "")
    input_args = input_args.replace("\\x", "")
    instruction = input_args

    lookup_module = options.module

    print('lookup instructions, this may take a while')
    target = debugger.GetSelectedTarget()
    bundle_path = target.GetExecutable().GetDirectory()
    total_count = 0
    for module in target.module_iter():
        module_file_spec = module.GetFileSpec()

        name = module_file_spec.GetFilename()
        if lookup_module:
            if lookup_module not in name:
                continue
        else:
            module_dir = module_file_spec.GetDirectory()
            if bundle_path not in module_dir:
                continue

            if name.startswith('libswift'):
                continue

        hits_count = 0
        print("-----try to lookup instructions in %s-----" % name)
        for symbol in module:
            # 2为Code，5为Trampoline，即调用的系统函数
            if symbol.GetType() != 2:
                continue

            insts = symbol.GetInstructions(target)
            for next_ins in insts:
                if next_ins.GetMnemonic(target) == instruction:
                    print(next_ins)
                    hits_count += 1

        if hits_count == 0:
            print("input instruction not found in {}".format(name))
        else:
            total_count += hits_count

    result.AppendMessage("{} locations found".format(total_count))


def generate_option_parser():
    usage = "usage: %prog instruction\n" + \
            "for example:\n" + \
            "\t%prog svc"

    parser = optparse.OptionParser(usage=usage, prog='ilookup')
    parser.add_option("-m", "--module",
                      action="store",
                      dest="module",
                      help="lookup bytes in the specified module")

    return parser
