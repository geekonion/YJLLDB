# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import os
import re

extra_offset = 0
base_num_frames = 0
base_frame = None
last_frame = None
last_offset = 0
last_thread = None
call_num = 0
oneshot = False


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "find oc methods with the same name" -f '
        'FindOverriddenMethod.find_overridden_method overridden_method')


def find_overridden_method(debugger, command, result, internal_dict):
    """
    find oc methods with the same name
    implemented in YJLLDB/src/FindOverriddenMethod.py
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

    app_name = None
    if not options.all:
        app_path = target.GetExecutable().GetDirectory()
        last_slash_pos = app_path.rfind('/')
        if last_slash_pos > 0:
            app_name = app_path[last_slash_pos:] + os.path.sep

    methods_dict = dict()
    for module in target.module_iter():
        module_file_spec = module.GetFileSpec()

        if not options.all:
            module_path = str(module_file_spec)
            pos = module_path.rfind(app_name)

            if pos == -1:
                continue

        name = module_file_spec.GetFilename()
        oc_methods = find_oc_methods(target, module, options.exclude)
        methods_dict[name] = oc_methods

    all_names = []
    for mod_name in methods_dict:
        # print('methods in {}'.format(mod_name))
        names = methods_dict[mod_name].values()
        # print(names)
        all_names.append(names)

    overridden_methods_set = set()
    n_names = len(all_names)
    for i in range(n_names):
        for j in range(i + 1, n_names):
            tmp = find_duplicates(all_names[i], all_names[j])
            overridden_methods_set.update(tmp)

    # print('overridden_methods_set {}'.format(overridden_methods_set))
    for method_name in overridden_methods_set:
        methods = []
        for mod_name in methods_dict:
            oc_methods = methods_dict[mod_name]
            for address in oc_methods:
                sym_name = oc_methods[address]
                if method_name != sym_name:
                    continue

                suffix = ''
                addr_obj = target.ResolveLoadAddress(address)
                sym = addr_obj.GetSymbol()
                insts = sym.GetInstructions(target)
                n_insts = insts.GetSize()
                if n_insts == 1:
                    inst_0 = insts.GetInstructionAtIndex(0)
                    if inst_0.GetMnemonic(target) == 'b':
                        suffix = ' (has only one b instruction and nothing else)'
                # elif n_insts > 3:
                #     inst_0 = insts.GetInstructionAtIndex(0)
                #     inst_1 = insts.GetInstructionAtIndex(1)
                #     inst_2 = insts.GetInstructionAtIndex(2)
                #     if inst_0.GetMnemonic(target) == 'adrp' and \
                #         inst_1.GetMnemonic(target) == 'add' and \
                #         inst_2.GetMnemonic(target) == 'br':
                #         pass

                real_name = sym.GetName()
                if sym_name != real_name:
                    if len(suffix) > 0:
                        methods.append('{}`{:#x} {} {}'.format(mod_name, address, real_name, suffix))
                    else:
                        methods.append('{}`{:#x} {}'.format(mod_name, address, real_name))
                else:
                    methods.append('{}`{:#x}{}'.format(mod_name, address, suffix))

        print('{}: {}'.format(method_name, methods))


def find_duplicates(list1, list2):
    # 将两个列表转换成集合，并计算它们的差集
    set1 = set(list1)
    set2 = set(list2)
    # 使用对称差集（并集减去两个集合的并集）找出重复元素
    duplicates = set1.intersection(set2)
    return duplicates


def find_oc_methods(target, module, exclude):
    oc_methods = {}
    for symbol in module:
        # 2为Code
        if symbol.GetType() != 2:
            continue

        sym_name = symbol.GetName()

        if not sym_name.endswith(']'):
            continue

        if not exclude: # 移除category名
            sym_name = re.sub(r'\([^)]*\)', '', sym_name)

        start_addr = symbol.GetStartAddress().GetLoadAddress(target)
        oc_methods[start_addr] = sym_name

    return oc_methods


def generate_option_parser():
    usage = "usage: %prog"

    parser = optparse.OptionParser(usage=usage, prog='overridden_method')
    parser.add_option("-a", "--all",
                      action="store_true",
                      default=False,
                      dest="all",
                      help="search all modules")
    parser.add_option("-e", "--exclude",
                      action="store_true",
                      default=False,
                      dest="exclude",
                      help="exclude overridden methods by category")

    return parser
