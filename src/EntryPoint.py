# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import util


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "print the address of main function" -f '
        'EntryPoint.get_main main')

    debugger.HandleCommand(
        'command script add -h "print the address of main function" -f '
        'EntryPoint.break_main bmain')


def get_main(debugger, command, result, internal_dict):
    """
    print the address of main function
    implemented in YJLLDB/src/EntryPoint.py
    """
    handle_command(debugger, command, result, 'print')


def break_main(debugger, command, result, internal_dict):
    """
    break the main function
    implemented in YJLLDB/src/EntryPoint.py
    """
    handle_command(debugger, command, result, 'break')


def handle_command(debugger, command, result, action):
    target = debugger.GetSelectedTarget()
    file_spec = target.GetExecutable()
    module = target.FindModule(file_spec)

    exe_name = file_spec.GetFilename()
    debug_dylib_module = target.module[exe_name + '.debug.dylib']
    real_main = None
    if debug_dylib_module:
        real_main = debug_dylib_module.FindSymbol('main', lldb.eSymbolTypeCode)

    header_addr = module.GetObjectFileHeaderAddress().GetLoadAddress(target)
    main_addr_obj = module.GetObjectFileEntryPointAddress()
    main_addr = main_addr_obj.GetLoadAddress(target)
    entry_offset = main_addr - header_addr

    if action == 'print':
        result.AppendMessage("function main at 0x{:x} {}, fileoff: 0x{:x}".
                             format(main_addr, main_addr_obj, entry_offset))

        if real_main:
            real_main_addr_obj = real_main.GetStartAddress()
            real_main_addr = real_main_addr_obj.GetLoadAddress(target)
            debug_dylib_header_addr = debug_dylib_module.GetObjectFileHeaderAddress().GetLoadAddress(target)
            real_entry_offset = real_main_addr - debug_dylib_header_addr
            result.AppendMessage("original main at 0x{:x} {}, fileoff: 0x{:x}".
                                 format(real_main_addr, real_main_addr_obj, real_entry_offset))
    else:
        brkpoint = target.BreakpointCreateBySBAddress(main_addr_obj)
        # 判断下断点是否成功
        if not brkpoint.IsValid() or brkpoint.num_locations == 0:
            result.AppendMessage("Breakpoint isn't valid or hasn't found any hits")
        else:
            result.AppendMessage("Breakpoint {}: {}, address = 0x{:x}"
                                 .format(brkpoint.GetID(), util.get_desc_for_address(main_addr_obj), main_addr)
                                 )
