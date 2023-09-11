# -*- coding: UTF-8 -*-
import json

import lldb
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
    """
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    parse_mod_init_func(result, target, process, 'print')


def break_mod_init_func(debugger, command, result, internal_dict):
    """
    break module init function(s) in user modules
    """
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    parse_mod_init_func(result, target, process, 'break')


def parse_mod_init_func(result, target, process, action):
    total_count = 0
    bundle_path = target.GetExecutable().GetDirectory()
    for module in target.module_iter():
        module_file_spec = module.GetFileSpec()
        module_name = module_file_spec.GetFilename()
        module_dir = module_file_spec.GetDirectory()
        if bundle_path not in module_dir:
            continue

        if module_name.startswith('libswift'):
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
                    sec_addr = sec.GetLoadAddress(target)
                    error = lldb.SBError()
                    sec_size = sec.GetByteSize()

                    ptr_size = process.GetAddressByteSize()
                    ptr_count = int(sec_size / ptr_size)
                    for idx in range(ptr_count):
                        func_ptr = process.ReadPointerFromMemory(sec_addr + idx * ptr_size, error)
                        if error.Success():
                            func_addr = target.ResolveLoadAddress(func_ptr)
                            if action == 'print':
                                print('address = 0x{:x} {}'.
                                      format(func_ptr, util.get_desc_for_address(func_addr)))
                            elif action == 'break':
                                brkpoint = target.BreakpointCreateBySBAddress(func_addr)
                                # 判断下断点是否成功
                                if not brkpoint.IsValid() or brkpoint.num_locations == 0:
                                    print("Breakpoint isn't valid or hasn't found any hits")
                                else:
                                    total_count += 1
                                    print("Breakpoint {}: {}, address = 0x{:x}"
                                          .format(brkpoint.GetID(), util.get_desc_for_address(func_addr), func_ptr)
                                          )

                    break

    if action == 'break':
        result.AppendMessage("set {} breakpoints".format(total_count))