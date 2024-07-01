# -*- coding: UTF-8 -*-
import json

import lldb
import optparse
import shlex
import util
import MachO
import common


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "find function by string" -f '
        'FindFunc.find_func ffunc')


def find_func(debugger, command, result, internal_dict):
    """
    dump segments of the specified module
    implemented in YJLLDB/src/FindFunc.py
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
    if len(args) == 1:
        lookup_module_name = args[0]
    else:
        lookup_module_name = target.GetExecutable().GetFilename()

    if options.min_size < 0 or options.max_size < 0:
        print('function size must be a positive integer')
        result.SetError("\n" + parser.get_usage())
        return

    find_func_by_options(target, result, lookup_module_name, options)


def find_func_by_options(target, result, lookup_module_name, options):
    for module in target.module_iter():
        message = ''
        module_file_spec = module.GetFileSpec()
        module_name = module_file_spec.GetFilename()

        if lookup_module_name in module_name:
            print("-----parsing module %s-----" % module_name)

            if options.address or options.name:
                message += find_func_by_callee_func_addr_or_name(target, module, options.address, options.name, options.min_size, options.max_size)
            elif options.keyword:
                message += find_func_by_c_string(target, module, options.keyword, options.min_size, options.max_size)

        result.AppendMessage(message)


def find_func_by_callee_func_addr_or_name(target, module, address, name, min_size, max_size):
    seg = module.FindSection('__TEXT')
    if not seg:
        return '\tseg __TEXT not found'

    header_addr = seg.GetLoadAddress(target)
    slide = header_addr - seg.GetFileAddress()

    first_sec = seg.GetSubSectionAtIndex(0)
    sec_addr = first_sec.GetLoadAddress(target)
    header_size = sec_addr - header_addr

    error = lldb.SBError()
    header_data = target.ReadMemory(lldb.SBAddress(header_addr, target), header_size, error)
    if not error.Success():
        return '\tread header failed! {}\n'.format(error.GetCString())

    info = MachO.parse_header(header_data)
    if slide == 0:
        slide = header_addr - int(info['text_vmaddr'], 16)

    lcs = info['lcs']
    # print(json.dumps(lcs, indent=2))
    stubs_addr = 0
    stubs_end = 0
    for lc in lcs:
        cmd = lc['cmd']
        if cmd == '19':  # LC_SEGMENT_64
            seg_name = lc['name']
            sects = lc['sects']

            if seg_name == '__TEXT':
                for sect in sects:
                    sec_name = sect['name']
                    if sec_name == '__stubs':
                        stubs_addr = slide + int(sect['addr'], 16)
                        stubs_size = int(sect['size'], 16)
                        stubs_end = stubs_addr + stubs_size
                        break

    message = ''
    for symbol in module:
        # 2为Code，5为Trampoline，即调用的系统函数
        if symbol.GetType() != 2:
            continue

        sym_start_addr = symbol.GetStartAddress().GetLoadAddress(target)
        sym_end_addr = symbol.GetEndAddress().GetLoadAddress(target)
        func_size = sym_end_addr - sym_start_addr

        if min_size == 0 and max_size == 0:  # 查找全部函数
            # print("\tcheck all functions")
            pass
        elif min_size > 0 and max_size == 0:  # 查找size大于min_size的函数
            if func_size < min_size:
                continue
            else:
                # print("\tcheck functions whose size is greater than or equal to {}".format(min_size))
                pass
        elif min_size == 0 and max_size > 0:  # 查找size小于max_size的函数
            if func_size > max_size:
                continue
            else:
                # print("\tcheck functions whose size is less than or equal to {}".format(max_size))
                pass
        elif min_size < func_size < max_size:  # 查找size位于min_size和max_size之间的函数
            # print("\tcheck functions whose size is between {} and {}".format(min_size, max_size))
            pass
        else:
            continue

        insts = symbol.GetInstructions(target)

        for next_ins in insts:
            mnemonic = next_ins.GetMnemonic(target)
            if mnemonic == 'bl' or mnemonic == 'blr':
                b_ins = next_ins
                b_ins_ops = b_ins.GetOperands(target).replace(' ', '')
                b_op_list = b_ins_ops.split(',')

                addr_or_reg = b_op_list[0]
                if not addr_or_reg.startswith('0x'):
                    continue

                jump_addr = int(addr_or_reg, 16)

                # 本MachO文件中的符号
                if address and address == jump_addr:
                    adrp_addr_obj = b_ins.GetAddress()
                    message += '\tfunction call found at: 0x{:x}, where = {}\n'.\
                        format(adrp_addr_obj.GetLoadAddress(target), adrp_addr_obj)
                elif name:
                    addr_obj = target.ResolveLoadAddress(jump_addr)
                    symbol = addr_obj.GetSymbol()
                    if symbol.GetName() == name:
                        adrp_addr_obj = b_ins.GetAddress()
                        # 动态链接的符号
                        if stubs_addr <= jump_addr < stubs_end:
                            message += '\tfunction call found at: 0x{:x}, where = {}\n'. \
                                format(adrp_addr_obj.GetLoadAddress(target), adrp_addr_obj)
                        # 本MachO文件中的符号
                        else:
                            message += '\tfunction call found at: 0x{:x}, where = {}\n'. \
                                format(adrp_addr_obj.GetLoadAddress(target), adrp_addr_obj)

    return message


def find_func_by_c_string(target, module, keyword, min_size, max_size):
    seg = module.FindSection('__TEXT')
    if not seg:
        return '\tseg __TEXT not found'

    header_addr = seg.GetLoadAddress(target)
    slide = header_addr - seg.GetFileAddress()

    first_sec = seg.GetSubSectionAtIndex(0)
    sec_addr = first_sec.GetLoadAddress(target)
    header_size = sec_addr - header_addr

    error = lldb.SBError()
    header_data = target.ReadMemory(lldb.SBAddress(header_addr, target), header_size, error)
    if not error.Success():
        return '\tread header failed! {}\n'.format(error.GetCString())

    info = MachO.parse_header(header_data)
    if slide == 0:
        slide = header_addr - int(info['text_vmaddr'], 16)

    lcs = info['lcs']
    # print(json.dumps(lcs, indent=2))
    keyword_addr = 0
    for lc in lcs:
        cmd = lc['cmd']
        if cmd == '19':  # LC_SEGMENT_64
            seg_name = lc['name']
            sects = lc['sects']

            if seg_name == '__TEXT':
                for sect in sects:
                    sec_name = sect['name']
                    if sec_name == '__cstring':
                        sec_addr = slide + int(sect['addr'], 16)
                        sec_size = int(sect['size'], 16)
                        keyword_addr = util.find_c_string_from_mem_region(target, sec_addr, sec_size, keyword)
                        break

    if keyword_addr > 0:
        print('\tkeyword {} found at 0x{:x}\n'.format(keyword, keyword_addr))
    else:
        print('\tkeyword {} not found'.format(keyword))

    message = ''
    for symbol in module:
        # 2为Code，5为Trampoline，即调用的系统函数
        if symbol.GetType() != 2:
            continue

        sym_start_addr = symbol.GetStartAddress().GetLoadAddress(target)
        sym_end_addr = symbol.GetEndAddress().GetLoadAddress(target)
        func_size = sym_end_addr - sym_start_addr

        if min_size == 0 and max_size == 0:  # 查找全部函数
            # print("\tcheck all functions")
            pass
        elif min_size > 0 and max_size == 0:  # 查找size大于min_size的函数
            if func_size < min_size:
                continue
            else:
                # print("\tcheck functions whose size is greater than or equal to {}".format(min_size))
                pass
        elif min_size == 0 and max_size > 0:  # 查找size小于max_size的函数
            if func_size > max_size:
                continue
            else:
                # print("\tcheck functions whose size is less than or equal to {}".format(max_size))
                pass
        elif min_size < func_size < max_size:  # 查找size位于min_size和max_size之间的函数
            # print("\tcheck functions whose size is between {} and {}".format(min_size, max_size))
            pass
        else:
            continue

        insts = symbol.GetInstructions(target)

        adrp_ins = None
        adrp_add_ins = None
        adrp_addr = None
        adrp_op_list = None
        mem_addr = 0
        for next_ins in insts:
            if next_ins.GetMnemonic(target) == 'adrp':
                adrp_ins = next_ins
                adrp_addr = adrp_ins.GetAddress().GetLoadAddress(target)
                adrp_ins_ops = adrp_ins.GetOperands(target).replace(' ', '')
                adrp_op_list = adrp_ins_ops.split(',')
            elif adrp_ins and next_ins.GetMnemonic(target) == 'add':
                ldr_ins_ops = next_ins.GetOperands(target).replace(' ', '')
                # print('0x{:x}: add {}'.format(next_ins.GetAddress().GetLoadAddress(target), next_ins_ops))
                ldr_op_list = ldr_ins_ops.split(',')
                if len(ldr_op_list) != 3:
                    continue
                if '#' not in ldr_op_list[2]:
                    continue

                adr_offset = int(ldr_op_list[2].replace('#', ''), 16)
                target_addr = (adrp_addr & 0xFFFFFFFFFFFFF000) + (int(adrp_op_list[-1]) * 4096) + adr_offset

                if target_addr == keyword_addr:
                    message += '\tkeyword address found: {}\n'.format(next_ins.GetAddress())

                adrp_ins = None
                adrp_add_ins = next_ins
                mem_addr = target_addr
            elif adrp_add_ins and next_ins.GetMnemonic(target) == 'ldr':
                # char *数组
                # ldr    q0, [x8]
                ldr_ins_ops = next_ins.GetOperands(target).replace(' ', '')
                ldr_op_list = ldr_ins_ops.split(',')
                if len(ldr_op_list) == 2:
                    reg = ldr_op_list[0]
                    if reg.startswith('q'):
                        vector = target.ReadMemory(lldb.SBAddress(mem_addr, target), 16, error)
                        addr1 = common.get_long(vector, 0)
                        addr2 = common.get_long(vector, 8)

                        if keyword_addr == addr1 or keyword_addr == addr2:
                            message += '\tkeyword address found: {}\n'.format(next_ins.GetAddress())

                adrp_add_ins = None
                mem_addr = 0
            else:
                adrp_ins = None

    return message


def generate_option_parser():
    usage = "usage: " \
            "%prog -k keyword [-i min_size] [-a max_size] [ModuleName]\n" \
            "%prog -a addr [ModuleName]\n"

    parser = optparse.OptionParser(usage=usage, prog='ffunc')
    parser.add_option("-k", "--keyword",
                      dest="keyword",
                      help="keyword")

    parser.add_option("-a", "--address",
                      type=int,
                      dest="address",
                      help="function address, to be used for functions in the executable file itself")

    parser.add_option("-n", "--name",
                      dest="name",
                      help="function name, to be used for functions in dynamic libraries")

    parser.add_option("-i", "--min_size",
                      default=0,
                      type=int,
                      dest="min_size",
                      help="min size of function")

    parser.add_option("-x", "--max_size",
                      default=0,
                      type=int,
                      dest="max_size",
                      help="max size of function")

    return parser
