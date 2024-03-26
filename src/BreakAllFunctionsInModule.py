# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import os


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "set breakpoints to break all functions in the specified module" -f '
        'BreakAllFunctionsInModule.break_all_functions_in_module baf')


def break_all_functions_in_module(debugger, command, result, internal_dict):
    """
    set breakpoints to break all functions in the specified module
    functions in system sdks, objc_msgSend stubs and c++ destructors are ignored
    implemented in YJLLDB/src/BreakAllFunctionsInModule.py
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

    if args:
        lookup_module_name = ''.join(args)
    else:
        lookup_module_name = None

    if not lookup_module_name:
        result.AppendMessage(parser.get_usage())
        return

    lookup_module_name = lookup_module_name.replace("'", "")
    target = debugger.GetSelectedTarget()

    total_count = 0
    module_found = False

    for module in target.module_iter():
        module_file_spec = module.GetFileSpec()
        name = module_file_spec.GetFilename()

        lib_name = lookup_module_name + '.dylib'
        if lookup_module_name != name and lib_name != name:
            continue

        module_found = True
        print("-----break functions in %s-----" % name)
        func_names = set()
        module_list = lldb.SBFileSpecList()
        module_list.Append(module_file_spec)
        comp_unit_list = lldb.SBFileSpecList()
        # for comp_unit in module.compile_unit_iter():
        #     comp_unit_list.Append(comp_unit.GetFileSpec())

        for symbol in module:
            # 2为Code，5为Trampoline，即调用的系统函数
            if symbol.GetType() != 2:
                continue

            sym_name = symbol.GetName()
            if not options.individual and not sym_name:
                continue
            # 过滤析构函数
            if "::~" in sym_name:
                continue
            # 过滤objc_msgSend stubs
            if sym_name.startswith("objc_msgSend$"):
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
                if options.verbose:
                    print(f"ignore function {sym_name} at {sym_start_addr.GetLineEntry()}")
                continue
            if options.verbose:
                print(sym_start_addr.GetLineEntry())

            if options.individual:
                brkpoint = target.BreakpointCreateBySBAddress(sym_start_addr)
                # 判断下断点是否成功
                if not brkpoint.IsValid() or brkpoint.num_locations == 0:
                    result.AppendWarning("Breakpoint isn't valid or hasn't found any hits")
                else:
                    total_count += 1
                    addr = sym_start_addr.GetLoadAddress(target)
                    result.AppendMessage("Breakpoint {}: where = {}`{}, address = 0x{:x}"
                                         .format(brkpoint.GetID(), name, sym_name, addr))
            else:
                func_names.add(sym_name)

        if not options.individual:
            # BreakpointCreateByNames(SBTarget self, char const ** symbol_name, uint32_t num_symbol,
            # uint32_t name_type_mask, SBFileSpecList module_list, SBFileSpecList comp_unit_list) -> SBBreakpoint...
            n_func_names = len(func_names)
            print(f"will set breakpoint for {n_func_names} names")
            if n_func_names > 0:
                brkpoint = target.BreakpointCreateByNames(list(func_names),
                                                          n_func_names,
                                                          lldb.eFunctionNameTypeFull,
                                                          module_list,
                                                          comp_unit_list)
                # 判断下断点是否成功
                if not brkpoint.IsValid() or brkpoint.num_locations == 0:
                    result.AppendWarning("Breakpoint isn't valid or hasn't found any hits")
                else:
                    result.AppendMessage("Breakpoint {}: {} locations"
                                         .format(brkpoint.GetID(), brkpoint.GetNumLocations()))
        break

    if module_found:
        if options.individual:
            result.AppendMessage("set {} breakpoints".format(total_count))
    else:
        result.AppendMessage("module {} not found".format(lookup_module_name))


def generate_option_parser():
    usage = "usage: %prog [options] ModuleName\n"

    parser = optparse.OptionParser(usage=usage, prog='baf')

    parser.add_option("-v", "--verbose",
                      action="store_true",
                      default=False,
                      dest="verbose",
                      help="verbose output")

    parser.add_option("-i", "--individual",
                      action="store_true",
                      default=False,
                      dest="individual",
                      help="create breakpoints with individual mode")

    return parser
