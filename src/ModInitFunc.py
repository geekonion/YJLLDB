# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import util
import MachO


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
    module_name = None
    bundle_path = target.GetExecutable().GetDirectory()
    target_module = None
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

        target_module = module
        # modules
        break

    if target_module:
        print("-----try to lookup init function in %s-----" % module_name)

        header_addr = target_module.GetObjectFileHeaderAddress().GetLoadAddress(target)
        seg = target_module.FindSection('__TEXT')
        if seg:
            slide = header_addr - seg.GetFileAddress()
            first_sec = seg.GetSubSectionAtIndex(0)
            sec_addr = first_sec.GetLoadAddress(target)
            header_size = sec_addr - header_addr
        else:
            slide = 0
            header_size = 0x4000

        error = lldb.SBError()
        header_data = target.ReadMemory(lldb.SBAddress(header_addr, target), header_size, error)
        if not error.Success():
            result.AppendMessage('read header failed! {}\n'.format(error.GetCString()))
            return

        init_func_not_found = True
        info = MachO.parse_header(header_data)
        if slide == 0:
            slide = header_addr - int(info['text_vmaddr'], 16)

        lcs = info['lcs']
        for lc in lcs:
            cmd = lc['cmd']
            if cmd != '19':  # LC_SEGMENT_64
                continue

            sects = lc['sects']
            for sect in sects:
                set_flags_str = sect.get('flags')
                if not set_flags_str:
                    continue

                sec_flags = int(set_flags_str, 16)

                # define SECTION_TYPE		 0x000000ff
                # #define S_MOD_INIT_FUNC_POINTERS 0x9
                is_mod_init = sec_flags & 0x000000ff == 0x9

                # #define S_INIT_FUNC_OFFSETS 0x16  /* 32-bit offsets to initializers
                is_init_offsets = sec_flags & 0x000000ff == 0x16
                if not is_mod_init and not is_init_offsets:
                    continue

                sec_addr = slide + int(sect['addr'], 16)
                sec_size = int(sect['size'], 16)
                if is_mod_init:
                    unit_size = process.GetAddressByteSize()
                    unit_count = int(sec_size / unit_size)
                    print('mod init func pointers found: {},{}'.format(lc['name'], sect['name']))
                elif is_init_offsets:
                    unit_size = 4  # offset is 32-bit
                    unit_count = int(sec_size / unit_size)
                    print('init func offsets found: {},{}'.format(lc['name'], sect['name']))
                else:
                    unit_size = 8
                    unit_count = 0

                init_func_not_found = False
                for idx in range(unit_count):
                    error = lldb.SBError()
                    if is_mod_init:
                        func_ptr = process.ReadPointerFromMemory(sec_addr + idx * unit_size, error)
                    elif is_init_offsets:
                        offset = process.ReadUnsignedFromMemory(sec_addr + idx * unit_size, unit_size, error)
                        func_ptr = header_addr + offset
                    else:
                        continue

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

                # for sects
                break

        if init_func_not_found:
            result.AppendMessage('{} apparently does not contain init_func'.format(module_name))
            return
    else:
        result.AppendMessage('module {} not found'.format(module_name))
        return

    if name == 'binitfunc':
        result.AppendMessage("{} breakpoints have been set".format(total_count))


def generate_option_parser(prog):
    usage = "usage: %prog"

    parser = optparse.OptionParser(usage=usage, prog=prog)

    return parser
