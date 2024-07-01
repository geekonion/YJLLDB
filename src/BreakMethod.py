# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import os
import util


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "break method in user modules" -f '
        'BreakMethod.break_method bmethod')


def break_method(debugger, command, result, internal_dict):
    """
    break method in user modules
    implemented in YJLLDB/src/BreakMethod.py
    """
    # 去掉转义符
    command = command.replace('\\', '\\\\')
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command_args = shlex.split(command, posix=False)
    # 创建parser
    parser = generate_option_parser('bmethod')
    # 解析参数，捕获异常
    try:
        # options是所有的选项，key-value形式，args是其余剩余所有参数，不包含options
        (options, args) = parser.parse_args(command_args)
    except Exception as error:
        print(error)
        result.SetError("\n" + parser.get_usage())
        return

    sel_names = []
    for arg in args:
        sel_names.append(' ' + arg + ']')
        sel_names.append('.' + arg + '(')

    target = debugger.GetSelectedTarget()

    bundle_path = target.GetExecutable().GetDirectory()
    total_count = 0

    for module in target.module_iter():
        module_file_spec = module.GetFileSpec()

        module_dir = module_file_spec.GetDirectory()
        if bundle_path not in module_dir:
            continue

        module_name = module_file_spec.GetFilename()
        if module_name.startswith('libswift'):
            continue

        print("-----try to method in %s-----" % module_name)
        for symbol in module:
            # 2为Code，5为Trampoline，即调用的系统函数
            if symbol.GetType() != 2:
                continue

            sym_name = symbol.GetName()
            
            if '___lldb_unnamed_symbol' in sym_name:
                continue
            # 过滤析构函数
            if "::~" in sym_name:
                continue
            # 过滤objc_msgSend stubs
            if sym_name.startswith("objc_msgSend$"):
                continue

            # 过滤block
            if "_block_invoke" in sym_name:
                continue
            """
            调用系统库c++函数和operator也会在__TEXT.__text产生一个函数
            (lldb) br list 13293.1
            13293: address = demo[0x00000001000774d8], locations = 1, resolved = 1, hit count = 1
              13293.1: where = demo`std::__1::vector<unsigned char, std::__1::allocator<unsigned char> >::operator[]
              [abi:v15006](unsigned long) at vector:1455, address = 0x00000001004a74d8, resolved, hit count = 1 

            (lldb) image lookup -a 0x00000001004a74d8
                  Address: demo[0x00000001000774d8] (demo.__TEXT.__text + 463104)
                  Summary: demo`std::__1::vector<unsigned char, std::__1::allocator<unsigned char> >::operator[]
                  [abi:v15006](unsigned long) at vector:1455
            """

            sym_start_addr = symbol.GetStartAddress()
            # 使用符号路径过滤系统库函数
            if ".platform/Developer/SDKs/" in str(sym_start_addr.GetLineEntry().GetFileSpec()):
                continue

            should_continue = True
            for sel_name in sel_names:
                if sel_name in sym_name:
                    should_continue = False
                    break
            if should_continue:
                continue

            brkpoint = target.BreakpointCreateBySBAddress(sym_start_addr)
            # 判断下断点是否成功
            if not brkpoint.IsValid() or brkpoint.num_locations == 0:
                print("Breakpoint isn't valid or hasn't found any hits")
            else:
                total_count += 1
                method_addr = sym_start_addr.GetLoadAddress(target)
                print("Breakpoint {}: {}, address = 0x{:x}"
                      .format(brkpoint.GetID(), util.get_desc_for_address(sym_start_addr), method_addr)
                      )

    result.AppendMessage("set {} breakpoints".format(total_count))


def generate_option_parser(proc, args=''):
    usage = "usage: %prog{} sel_name sel_name\n".format(args)

    parser = optparse.OptionParser(usage=usage, prog=proc)

    return parser
