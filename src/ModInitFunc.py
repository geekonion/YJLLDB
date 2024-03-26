# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import os.path
import util


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "dump module init function(s) in user modules" -f '
        'ModInitFunc.dump_mod_init_func initfunc')

    debugger.HandleCommand(
        'command script add -h "break module init function(s) in user modules" -f '
        'ModInitFunc.break_mod_init_func binitfunc')


def dump_mod_init_func(debugger, command, result, internal_dict):
    """
    dump module init function(s) in user modules
    implemented in YJLLDB/src/ModInitFunc.py
    """
    parse_mod_init_func(debugger, command, result, 'initfunc')


def break_mod_init_func(debugger, command, result, internal_dict):
    """
    break module init function(s) in user modules
    implemented in YJLLDB/src/ModInitFunc.py
    """
    parse_mod_init_func(debugger, command, result, 'binitfunc')


def parse_mod_init_func(debugger, command, result, name):
    # 去掉转义符
    command = command.replace('\\', '\\\\')
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command_args = shlex.split(command, posix=False)
    # 创建parser
    parser = generate_option_parser(name)
    # 解析参数，捕获异常
    try:
        # options是所有的选项，key-value形式，args是其余剩余所有参数，不包含options
        (options, args) = parser.parse_args(command_args)
    except Exception as error:
        print(error)
        result.SetError("\n" + parser.get_usage())
        return

    target = debugger.GetSelectedTarget()
    if args:
        lookup_module_name = ''.join(args)
        lookup_module_name = lookup_module_name.replace("'", "")
    else:
        lookup_module_name = None

    process = target.GetProcess()
    total_count = 0
    sec_mod_init_func_not_found = True
    module_name = None
    bundle_path = target.GetExecutable().GetDirectory()
    for module in target.module_iter():
        module_file_spec = module.GetFileSpec()
        module_name = module_file_spec.GetFilename()
        module_dir = module_file_spec.GetDirectory()
        if bundle_path not in module_dir:
            continue

        if module_name.startswith('libswift'):
            continue

        if lookup_module_name and lookup_module_name not in module_name:
            continue

        print("-----try to lookup init function in %s-----" % module_name)
        for seg in module.section_iter():
            seg_name = seg.GetName()
            if seg_name != '__DATA':
                continue

            nsec = seg.GetNumSubSections()
            for i in range(nsec):
                sec = seg.GetSubSectionAtIndex(i)
                sec_name = sec.GetName()
                if sec_name == '__mod_init_func':
                    sec_mod_init_func_not_found = False
                    sec_addr = sec.GetLoadAddress(target)
                    error = lldb.SBError()
                    sec_size = sec.GetByteSize()

                    ptr_size = process.GetAddressByteSize()
                    ptr_count = int(sec_size / ptr_size)
                    for idx in range(ptr_count):
                        func_ptr = process.ReadPointerFromMemory(sec_addr + idx * ptr_size, error)
                        if error.Success():
                            func_addr = target.ResolveLoadAddress(func_ptr)
                            if name == 'initfunc':
                                print('address = 0x{:x} {}'.
                                      format(func_ptr, util.get_desc_for_address(func_addr)))
                            elif name == 'binitfunc':
                                brkpoint = target.BreakpointCreateBySBAddress(func_addr)
                                # 判断下断点是否成功
                                if not brkpoint.IsValid() or brkpoint.num_locations == 0:
                                    print("Breakpoint isn't valid or hasn't found any hits")
                                else:
                                    total_count += 1
                                    print("Breakpoint {}: {}, address = 0x{:x}"
                                          .format(brkpoint.GetID(), util.get_desc_for_address(func_addr), func_ptr)
                                          )

                    # __mod_init_func
                    break
            # segments
            break
        # modules
        break

    if sec_mod_init_func_not_found:
        result.AppendMessage('{} apparently does not contain __mod_init_func'.format(module_name))
        return

    if name == 'binitfunc':
        result.AppendMessage("set {} breakpoints".format(total_count))


def generate_option_parser(prog):
    usage = "usage: %prog"

    parser = optparse.OptionParser(usage=usage, prog=prog)

    return parser
