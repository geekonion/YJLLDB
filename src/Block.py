# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import os
import re
import json
import util


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "find blocks in user modules and save block symbols to block_symbol.json" -f '
        'Block.find_all_blocks blocks')

    debugger.HandleCommand(
        'command script add -h "find the specified block(s) in user modules" -f '
        'Block.find_blocks fblock')

    debugger.HandleCommand(
        'command script add -h "break blocks in user modules" -f '
        'Block.break_blocks bblocks')


def find_all_blocks(debugger, command, result, internal_dict):
    """
    find blocks in user modules and save block symbols to block_symbol.json
    implemented in YJLLDB/src/Block.py
    """
    # 去掉转义符
    command = command.replace('\\', '\\\\')
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command_args = shlex.split(command, posix=False)
    # 创建parser
    parser = generate_option_parser('blocks')
    # 解析参数，捕获异常
    try:
        # options是所有的选项，key-value形式，args是其余剩余所有参数，不包含options
        (options, args) = parser.parse_args(command_args)
    except Exception as error:
        print(error)
        result.SetError("\n" + parser.get_usage())
        return

    module_list = args

    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    bundle_path = target.GetExecutable().GetDirectory()
    total_count = 0
    block_symbols = []
    block_dict = {}
    global_block_var_index = 0
    for module in target.module_iter():
        module_file_spec = module.GetFileSpec()
        module_name = module_file_spec.GetFilename()
        module_dir = module_file_spec.GetDirectory()
        if not module_dir:
            print('unexpected module: {}'.format(module))
            continue

        if len(module_list) > 0:
            if module_name not in module_list:
                continue
        else:
            if bundle_path not in module_dir:
                continue

        module_name = module_file_spec.GetFilename()
        if module_name.startswith('libswift'):
            continue

        print("-----try to lookup block in %s-----" % module_name)
        blocks_info_str = get_blocks_info(module_name)
        if not blocks_info_str:
            continue

        blocks_info = json.loads(blocks_info_str)
        error = blocks_info['error']
        if len(error):
            print(error)
            continue

        global_blocks_str = blocks_info['globalBlocks']
        if len(global_blocks_str):
            blocks_info_list = global_blocks_str.split(';')
        else:
            blocks_info_list = []

        stack_block_addr_str = blocks_info['stackBlockAddr']
        if len(stack_block_addr_str):
            stack_block_addr = int(stack_block_addr_str, 16)
        else:
            stack_block_addr = 0

        stack_block_isa = int(blocks_info['_NSConcreteStackBlock'], 16)
        global_block_isa = int(blocks_info['_NSConcreteGlobalBlock'], 16)
        module_slide = int(blocks_info['slide'])

        global_blocks = []
        block_addrs = []
        block_funcs = []
        for block_info in blocks_info_list:
            # print("block_info: {}".format(block_info))
            comps = block_info.split(':')
            block_addrs.append(int(comps[0], 16))
            block_funcs.append(int(comps[1], 16))

        hits_count = 0
        output_block_addrs = []
        global_block_var_addrs = []
        for symbol in module:
            # 2为Code，5为Trampoline，即调用的系统函数
            if symbol.GetType() != 2:
                continue

            sym_name = symbol.GetName()
            sym_start_addr = symbol.GetStartAddress()

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

            # 使用符号路径过滤系统库函数
            if ".platform/Developer/SDKs/" in str(sym_start_addr.GetLineEntry().GetFileSpec()):
                continue

            # 如果是已定位的block，sym_name使用block_name
            if '___lldb_unnamed_symbol' in sym_name:
                sym_addr = sym_start_addr.GetLoadAddress(target)
                block_name = block_dict.get(sym_addr)
                # print('find 0x{:x} {}'.format(sym_addr, block_name))
                if block_name:
                    sym_name = block_name

            insts = symbol.GetInstructions(target)

            # debug block作为函数参数
            # adrp   x6, 4
            # add    x6, x6, #0x188

            # release block作为函数参数
            # adr    x2,  # 0x2c14

            # deubg 全局block变量被使用
            # adrp   x8, 5
            # ldr    x0, [x8, #0x7e8]
            # ldr    x8, [x0, #0x10]
            # blr    x8

            # deubg 全局block变量，在一个函数中被多次使用
            # adrp   x8, 5
            # str    x8, [sp, #0x30]
            # ldr    x0, [x8, #0x7e8]
            # ldr    x8, [x0, #0x10]
            # blr    x8

            # release 全局block变量被使用
            # nop
            # ldr    x0, #0x4468
            # ldr    x8, [x0, #0x10]
            # blr    x8
            # 或
            # adrp   x22, 4
            # ldr    x0, [x22, #0x9e8]
            # ldr    x8, [x0, #0x10]
            # blr    x8

            # debug StackBlock
            # adrp   x9, 4
            # ldr    x9, [x9, #0x38]
            # str    x9, [sp, #0x48]    ; store block to stack
            # mov    w9, #-0x3e000000
            # str    w9, [sp, #0x50]
            # str    wzr, [sp, #0x54]
            # adrp   x9, 0
            # add    x9, x9, #0xf48            ; __41-[ViewController touchesBegan:withEvent:]_block_invoke_4
            #                                   at ViewController.m:75
            # str    x9, [sp, #0x58]    ; store block func to stack

            # release StackBlock
            # nop
            # ldr    x8, #0x29a4               ; (void *)0x00000001b57dee88: _NSConcreteStackBlock
            # str    x8, [sp, #0x8]         ; store block to stack
            # nop
            # ldr    d0, 0x10436a270
            # adr    x8, #0x5c                 ; ___lldb_unnamed_symbol83
            # nop
            # str    d0, [sp, #0x10]
            # adr    x9, #0x2b50
            # nop
            # stp    x8, x9, [sp, #0x18]    ; store block func to stack

            adrp_ins = None
            stack_block_found = False
            adrp_addr = None
            adrp_op_list = None
            for next_ins in insts:
                if next_ins.GetMnemonic(target) == 'adr':
                    ldr_ins_ops = next_ins.GetOperands(target).replace(' ', '')
                    # print('0x{:x}: adr {}'.format(next_ins.GetAddress().GetLoadAddress(target), adr_ins_ops))
                    ldr_op_list = ldr_ins_ops.split(',')
                    if len(ldr_op_list) != 2:
                        continue

                    if '#' not in ldr_op_list[1]:
                        continue

                    adr_addr = next_ins.GetAddress().GetLoadAddress(target)
                    try:
                        adr_offset = int(ldr_op_list[1].replace('#', ''), 16)
                    except Exception as error:
                        print(error)
                        continue

                    target_addr = adr_addr + adr_offset
                    if stack_block_found:
                        print('\tstack block func addr 0x{:x} {}'.
                              format(target_addr, util.get_desc_for_address(target.ResolveLoadAddress(target_addr))))
                        output_block_addrs.append(target_addr)
                        stack_block_found = False
                    else:
                        next_ins_addr = next_ins.GetAddress()
                        # print('target_addr: 0x{:x} {}'.format(target_addr, next_ins_addr))
                        try:
                            idx = block_addrs.index(target_addr)
                            print('find a block: 0x{:x} in {}'.
                                  format(target_addr, util.get_desc_for_address(next_ins_addr)))
                            block_addrs.remove(target_addr)
                            block_func_ptr = block_funcs[idx]
                            block_funcs.remove(block_func_ptr)
                            output_block_addrs.append(block_func_ptr)
                            hits_count += 1
                            total_count += 1
                        except Exception as error:
                            pass
                elif next_ins.GetMnemonic(target) == 'adrp':
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

                    if stack_block_found:
                        print('\tstack block func addr 0x{:x} {}'.
                              format(target_addr, util.get_desc_for_address(target.ResolveLoadAddress(target_addr))))
                        output_block_addrs.append(target_addr)
                        stack_block_found = False
                    else:
                        next_ins_addr = next_ins.GetAddress()
                        # print('target_addr: 0x{:x} {}'.format(target_addr, next_ins_addr))
                        try:
                            idx = block_addrs.index(target_addr)
                            print('find a block: 0x{:x} in {}'.
                                  format(target_addr, util.get_desc_for_address(next_ins_addr)))
                            block_addrs.remove(target_addr)
                            block_func_ptr = block_funcs[idx]
                            block_funcs.remove(block_func_ptr)
                            output_block_addrs.append(block_func_ptr)
                            hits_count += 1
                            total_count += 1
                        except Exception as error:
                            pass

                    adrp_ins = None
                elif next_ins.GetMnemonic(target) == 'ldr':
                    ldr_ins_ops = next_ins.GetOperands(target).replace(' ', '')
                    if adrp_ins:
                        # print('0x{:x}: ldr {}'.format(next_ins.GetAddress().GetLoadAddress(target), ldr_ins_ops))
                        ldr_op_list = ldr_ins_ops.split(',')
                        if len(ldr_op_list) != 3:
                            continue

                        operand = ldr_op_list[2]
                        if ']' not in operand:
                            continue

                        if ']!' in operand:
                            continue

                        if '#' not in operand:
                            continue

                        operand = operand.replace('#', '')
                        operand = operand.replace(']', '')

                        try:
                            adr_offset = int(operand, 16)
                        except Exception as error:
                            print(error)
                            adrp_ins = None
                            continue

                        ldr_addr = (adrp_addr & 0xFFFFFFFFFFFFF000) + (int(adrp_op_list[-1]) * 4096) + adr_offset

                        error = lldb.SBError()
                        target_addr = process.ReadPointerFromMemory(ldr_addr, error)
                        if error.Success():
                            next_ins_addr = next_ins.GetAddress()
                            # print('target_addr: 0x{:x} {}'.format(target_addr, next_ins_addr))
                            if target_addr == stack_block_isa:
                                print('find a stack block @0x{:x} in {}'.
                                      format(next_ins_addr.GetLoadAddress(target),
                                             util.get_desc_for_address(next_ins_addr, sym_name)))
                                hits_count += 1
                                total_count += 1
                                stack_block_found = True
                            else:
                                try:
                                    idx = block_addrs.index(target_addr)
                                    print('* using global block var: 0x{:x} in {}'.
                                          format(target_addr, util.get_desc_for_address(next_ins_addr)))

                                    if global_blocks.count(target_addr) == 0:
                                        hits_count += 1
                                        total_count += 1
                                        global_blocks.append(target_addr)
                                        block_func_ptr = block_funcs[idx]
                                        global_block_var_addrs.append(block_func_ptr)
                                except Exception as error:
                                    pass

                        adrp_ins = None
                    else:
                        # ldr x0,#0x5330
                        ret = re.match('^x\\d{1,2},#0x\\d+', ldr_ins_ops)
                        # print('0x{:x}: ldr {} {}'.
                        #       format(next_ins.GetAddress().GetLoadAddress(target), ldr_ins_ops, ret))
                        if ret:
                            ldr_op_list = ldr_ins_ops.split(',')
                            ldr_offset = int(ldr_op_list[1].replace('#', ''), 16)
                            next_ins_addr = next_ins.GetAddress()
                            next_ins_loadaddr = next_ins_addr.GetLoadAddress(target)
                            addr = next_ins_loadaddr + ldr_offset
                            if addr == stack_block_addr:
                                print('find a stack block @0x{:x} in {}'.
                                      format(next_ins_loadaddr, util.get_desc_for_address(next_ins_addr, sym_name)))
                                hits_count += 1
                                total_count += 1
                                stack_block_found = True
                            else:
                                error = lldb.SBError()
                                maybe_block = process.ReadPointerFromMemory(addr, error)
                                if error.Success():
                                    addr_value = process.ReadPointerFromMemory(maybe_block, error)
                                    if addr_value == global_block_isa:
                                        print('+ using global block var: 0x{:x} in {}'.
                                              format(maybe_block, util.get_desc_for_address(next_ins_addr)))
                                        if global_blocks.count(maybe_block) == 0:
                                            hits_count += 1
                                            total_count += 1
                                            global_blocks.append(maybe_block)
                                            block_func_ptr = process.ReadPointerFromMemory(maybe_block + 0x10, error)
                                            if error.Success():
                                                global_block_var_addrs.append(block_func_ptr)
                            continue

                elif adrp_ins and next_ins.GetMnemonic(target) == 'str':
                    ldr_ins_ops = next_ins.GetOperands(target).replace(' ', '')
                    ldr_op_list = ldr_ins_ops.split(',')
                    if ldr_op_list[0] != adrp_op_list[0]:
                        adrp_ins = None
                else:
                    adrp_ins = None

            for index, block_addr in enumerate(output_block_addrs):
                func_addr = target.ResolveLoadAddress(block_addr)
                block_name = util.get_desc_for_address(func_addr, False)
                # 有符号的block不记录，保持原符号
                if '___lldb_unnamed_symbol' not in block_name:
                    # print(block_name)
                    continue

                if index == 0:
                    index_str = ''
                else:
                    index_str = '_{}'.format(index + 1)

                block_name = sym_name + '_block_invoke' + index_str
                block_symbol = {
                    "address": '0x{:x}'.format(block_addr - module_slide),
                    "name": block_name
                }
                block_symbols.append(block_symbol)
                block_dict[block_addr] = block_name
                # print('cache 0x{:x} {}'.format(block_addr, block_name))

            for block_addr in global_block_var_addrs:
                func_addr = target.ResolveLoadAddress(block_addr)
                block_name = util.get_desc_for_address(func_addr, False)
                # 有符号的block不记录，保持原符号
                if '___lldb_unnamed_symbol' not in block_name:
                    # print(block_name)
                    continue

                block_name = 'global_block_var_{}_block_invoke'.format(global_block_var_index + 1)
                block_symbol = {
                    "address": '0x{:x}'.format(block_addr - module_slide),
                    "name": block_name
                }
                block_symbols.append(block_symbol)
                block_dict[block_addr] = block_name
                global_block_var_index += 1
                # print('cache 0x{:x} {}'.format(block_addr, block_name))

            output_block_addrs.clear()
            global_block_var_addrs.clear()

        for index, block_addr in enumerate(block_addrs):
            if global_blocks.count(block_addr) > 0:
                continue
            block_func = block_funcs[index]
            func_addr = target.ResolveLoadAddress(block_func)
            print('unresolved block: 0x{:x} in {}'.format(block_addr, util.get_desc_for_address(func_addr)))

        if hits_count == 0:
            print("no block resolved")

        file_dir = os.path.join(os.path.expanduser('~'), 'block_symbols', module_name)
        file_path = os.path.join(file_dir, 'block_symbol.json')
        if len(block_symbols) > 0:
            util.try_mkdir(file_dir)

            with open(file_path, 'w') as json_file:
                json.dump(block_symbols, json_file, indent=2)
                json_file.close()
                print("block symbols have been written to {}".format(file_path))
        else:
            if os.path.exists(file_path):
                os.remove(file_path)

        block_symbols.clear()

    result.AppendMessage("{} block(s) resolved.".format(total_count))


def find_blocks(debugger, command, result, internal_dict):
    """
    find the specified block(s) in user modules
    implemented in YJLLDB/src/Block.py
    """
    # 去掉转义符
    command = command.replace('\\', '\\\\')
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command_args = shlex.split(command, posix=False)
    # 创建parser
    parser = generate_find_parser('fblock')
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
    else:
        all_addr_list = []
        for arg in args:
            value = int(arg, 16)
            # if value % 8:
            #     print('0x{:x} could not be a block object'.format(value))
            #     continue

            all_addr_list.append(value)

    if len(all_addr_list) == 0:
        return

    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    bundle_path = target.GetExecutable().GetDirectory()
    total_count = 0

    block_found = False
    for module in target.module_iter():
        module_file_spec = module.GetFileSpec()
        module_dir = module_file_spec.GetDirectory()
        if bundle_path not in module_dir:
            continue

        name = module_file_spec.GetFilename()
        if name.startswith('libswift'):
            continue

        print("-----try to lookup block in %s-----" % name)
        blocks_info_str = get_blocks_info(name)
        if not blocks_info_str:
            continue

        blocks_info = json.loads(blocks_info_str)
        error = blocks_info['error']
        if len(error):
            print(error)
            continue

        global_blocks_str = blocks_info['globalBlocks']
        if len(global_blocks_str):
            blocks_info_list = global_blocks_str.split(';')
        else:
            blocks_info_list = []

        stack_block_addr_str = blocks_info['stackBlockAddr']
        if len(stack_block_addr_str):
            stack_block_addr = int(stack_block_addr_str, 16)
        else:
            stack_block_addr = 0

        stack_block_isa = int(blocks_info['_NSConcreteStackBlock'], 16)
        global_block_isa = int(blocks_info['_NSConcreteGlobalBlock'], 16)

        global_blocks = []
        stack_blocks = []
        addr_list = []
        for block_info in blocks_info_list:
            # print("block_info: {}".format(block_info))
            comps = block_info.split(':')
            block_addr = int(comps[0], 16)
            if block_addr in all_addr_list:
                addr_list.append(block_addr)
                all_addr_list.remove(block_addr)

        use_func_addr = False
        if len(addr_list) == 0:
            use_func_addr = True

        global_block_var_found = False
        for symbol in module:
            # 2为Code，5为Trampoline，即调用的系统函数
            if symbol.GetType() != 2:
                continue

            sym_name = symbol.GetName()
            sym_start_addr = symbol.GetStartAddress()

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

            # 使用符号路径过滤系统库函数
            if ".platform/Developer/SDKs/" in str(sym_start_addr.GetLineEntry().GetFileSpec()):
                continue

            insts = symbol.GetInstructions(target)

            adrp_addr = 0
            adrp_op_list = None
            adrp_ins = None
            stack_block_found = False
            stack_block_des = ''
            for next_ins in insts:
                if next_ins.GetMnemonic(target) == 'adr':
                    ldr_ins_ops = next_ins.GetOperands(target).replace(' ', '')
                    # print('0x{:x}: adr {}'.format(next_ins.GetAddress().GetLoadAddress(target), adr_ins_ops))
                    ldr_op_list = ldr_ins_ops.split(',')
                    if len(ldr_op_list) != 2:
                        continue

                    if '#' not in ldr_op_list[1]:
                        continue

                    adr_addr = next_ins.GetAddress().GetLoadAddress(target)
                    try:
                        adr_offset = int(ldr_op_list[1].replace('#', ''), 16)
                    except Exception as error:
                        print(error)
                        continue

                    target_addr = adr_addr + adr_offset
                    if stack_block_found:
                        if target_addr in all_addr_list:
                            print('{}, block func addr 0x{:x}'.format(stack_block_des, target_addr))

                            if target_addr not in stack_blocks:
                                total_count += 1

                            stack_blocks.append(target_addr)
                            all_addr_list.remove(target_addr)
                            block_found = True

                        stack_block_found = False
                    else:
                        next_ins_addr = next_ins.GetAddress()
                        # print('target_addr: 0x{:x} {}'.format(target_addr, next_ins_addr))
                        try:
                            idx = addr_list.index(target_addr)
                            print('find a block: 0x{:x} in {}'.
                                  format(target_addr, util.get_desc_for_address(next_ins_addr)))
                            addr_list.remove(target_addr)
                            total_count += 1
                            block_found = True
                        except Exception as error:
                            pass
                elif next_ins.GetMnemonic(target) == 'adrp':
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

                    if stack_block_found:
                        if target_addr in all_addr_list:
                            print('{}, block func addr 0x{:x}'.format(stack_block_des, target_addr))

                            if target_addr not in stack_blocks:
                                total_count += 1

                            stack_blocks.append(target_addr)
                            all_addr_list.remove(target_addr)
                            block_found = True
                        stack_block_found = False
                    else:
                        next_ins_addr = next_ins.GetAddress()
                        # print('target_addr: 0x{:x} {}'.format(target_addr, next_ins_addr))
                        try:
                            idx = addr_list.index(target_addr)
                            print('find a block: 0x{:x} in {}'.
                                  format(target_addr, util.get_desc_for_address(next_ins_addr)))
                            addr_list.remove(target_addr)
                            total_count += 1
                            block_found = True
                        except Exception as error:
                            pass

                    adrp_ins = None
                elif next_ins.GetMnemonic(target) == 'ldr':
                    ldr_ins_ops = next_ins.GetOperands(target).replace(' ', '')
                    if adrp_ins:
                        # print('0x{:x}: ldr {}'.format(next_ins.GetAddress().GetLoadAddress(target), ldr_ins_ops))
                        ldr_op_list = ldr_ins_ops.split(',')
                        if len(ldr_op_list) != 3:
                            continue

                        operand = ldr_op_list[2]
                        if ']' not in operand:
                            continue

                        if ']!' in operand:
                            continue

                        if '#' not in operand:
                            continue

                        operand = operand.replace('#', '')
                        operand = operand.replace(']', '')

                        try:
                            adr_offset = int(operand, 16)
                        except Exception as error:
                            print(error)
                            adrp_ins = None
                            continue

                        ldr_addr = (adrp_addr & 0xFFFFFFFFFFFFF000) + (int(adrp_op_list[-1]) * 4096) + adr_offset

                        error = lldb.SBError()
                        target_addr = process.ReadPointerFromMemory(ldr_addr, error)
                        if error.Success():
                            next_ins_addr = next_ins.GetAddress()
                            # print('target_addr: 0x{:x} {}'.format(target_addr, next_ins_addr))
                            if target_addr == stack_block_isa:
                                stack_block_des = 'find a stack block @0x{:x} in {}'.\
                                    format(next_ins_addr.GetLoadAddress(target),
                                           util.get_desc_for_address(next_ins_addr))
                                # print(stack_block_des)
                                stack_block_found = True
                            else:
                                try:
                                    idx = addr_list.index(target_addr)
                                    print('* using global block var: 0x{:x} in {}'.
                                          format(target_addr, util.get_desc_for_address(next_ins_addr)))

                                    if global_blocks.count(target_addr) == 0:
                                        total_count += 1
                                        global_blocks.append(target_addr)
                                    global_block_var_found = True
                                except Exception as error:
                                    pass

                        adrp_ins = None
                    else:
                        # ldr x0,#0x5330
                        ret = re.match('^x\\d{1,2},#0x\\d+', ldr_ins_ops)
                        # print('0x{:x}: ldr {} {}'.
                        #       format(next_ins.GetAddress().GetLoadAddress(target), ldr_ins_ops, ret))
                        if ret:
                            ldr_op_list = ldr_ins_ops.split(',')
                            ldr_offset = int(ldr_op_list[1].replace('#', ''), 16)
                            next_ins_addr = next_ins.GetAddress()
                            next_ins_loadaddr = next_ins_addr.GetLoadAddress(target)
                            addr = next_ins_loadaddr + ldr_offset
                            if addr == stack_block_addr:
                                stack_block_des = 'find a stack block @0x{:x} in {}'. \
                                    format(next_ins_addr.GetLoadAddress(target),
                                           util.get_desc_for_address(next_ins_addr))
                                # print(stack_block_des)
                                stack_block_found = True
                            else:
                                error = lldb.SBError()
                                maybe_block = process.ReadPointerFromMemory(addr, error)
                                if error.Success():
                                    addr_value = process.ReadPointerFromMemory(maybe_block, error)
                                    if addr_value == global_block_isa and maybe_block in all_addr_list:
                                        print('+ using global block var: 0x{:x} in {}'.
                                              format(maybe_block, util.get_desc_for_address(next_ins_addr)))
                                        if global_blocks.count(maybe_block) == 0:
                                            total_count += 1
                                            global_blocks.append(maybe_block)
                                        global_block_var_found = True
                            continue

                elif adrp_ins and next_ins.GetMnemonic(target) == 'str':
                    ldr_ins_ops = next_ins.GetOperands(target).replace(' ', '')
                    ldr_op_list = ldr_ins_ops.split(',')
                    if ldr_op_list[0] != adrp_op_list[0]:
                        adrp_ins = None
                else:
                    adrp_ins = None

                if not use_func_addr and len(addr_list) == 0:
                    break

            if not use_func_addr and len(addr_list) == 0:
                break

            if block_found:
                break

        if block_found or global_block_var_found:
            break

    for block_addr in all_addr_list:
        print('block: 0x{:x} not found'.format(block_addr))

    result.AppendMessage("{} location(s) found".format(total_count))


def break_blocks(debugger, command, result, internal_dict):
    """
    break blocks in user modules
    implemented in YJLLDB/src/Block.py
    """
    # 去掉转义符
    command = command.replace('\\', '\\\\')
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command_args = shlex.split(command, posix=False)
    # 创建parser
    parser = generate_option_parser('bblocks')
    # 解析参数，捕获异常
    try:
        # options是所有的选项，key-value形式，args是其余剩余所有参数，不包含options
        (options, args) = parser.parse_args(command_args)
    except Exception as error:
        print(error)
        result.SetError("\n" + parser.get_usage())
        return

    module_list = args

    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    bundle_path = target.GetExecutable().GetDirectory()
    total_count = 0

    stack_blocks = []
    for module in target.module_iter():
        module_file_spec = module.GetFileSpec()
        module_dir = module_file_spec.GetDirectory()
        name = module_file_spec.GetFilename()
        if name.startswith('libswift'):
            continue

        if len(module_list):
            if name not in module_list:
                continue
        else:
            if bundle_path not in module_dir:
                continue

        print("-----try to lookup block in %s-----" % name)
        blocks_info_str = get_blocks_info(name)
        if not blocks_info_str:
            continue

        blocks_info = json.loads(blocks_info_str)
        error = blocks_info['error']
        if len(error):
            print(error)
            continue

        global_blocks_str = blocks_info['globalBlocks']
        if len(global_blocks_str):
            blocks_info_list = global_blocks_str.split(';')
        else:
            blocks_info_list = []

        stack_block_addr_str = blocks_info['stackBlockAddr']
        if len(stack_block_addr_str):
            stack_block_addr = int(stack_block_addr_str, 16)
        else:
            stack_block_addr = 0

        stack_block_isa = int(blocks_info['_NSConcreteStackBlock'], 16)

        for block_info in blocks_info_list:
            # print("block_info: {}".format(block_info))
            comps = block_info.split(':')
            block_addr = int(comps[0], 16)
            block_func = int(comps[1], 16)

            block_func_addr = target.ResolveLoadAddress(block_func)
            brkpoint = target.BreakpointCreateBySBAddress(block_func_addr)
            # 判断下断点是否成功
            if not brkpoint.IsValid() or brkpoint.num_locations == 0:
                print("Breakpoint isn't valid or hasn't found any hits")
            else:
                total_count += 1
                print("break block: 0x{:x} with Breakpoint {}: {}, address = 0x{:x}"
                      .format(block_addr, brkpoint.GetID(), util.get_desc_for_address(block_func_addr), block_func)
                      )

        for symbol in module:
            # 2为Code，5为Trampoline，即调用的系统函数
            if symbol.GetType() != 2:
                continue

            sym_name = symbol.GetName()
            sym_start_addr = symbol.GetStartAddress()

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

            # 使用符号路径过滤系统库函数
            if ".platform/Developer/SDKs/" in str(sym_start_addr.GetLineEntry().GetFileSpec()):
                continue

            insts = symbol.GetInstructions(target)

            adrp_addr = 0
            adrp_op_list = None
            adrp_ins = None
            stack_block_found = False
            for next_ins in insts:
                if next_ins.GetMnemonic(target) == 'adr':
                    ldr_ins_ops = next_ins.GetOperands(target).replace(' ', '')
                    # print('0x{:x}: adr {}'.format(next_ins.GetAddress().GetLoadAddress(target), adr_ins_ops))
                    ldr_op_list = ldr_ins_ops.split(',')
                    if len(ldr_op_list) != 2:
                        continue

                    if '#' not in ldr_op_list[1]:
                        continue

                    adr_addr = next_ins.GetAddress().GetLoadAddress(target)
                    try:
                        adr_offset = int(ldr_op_list[1].replace('#', ''), 16)
                    except Exception as error:
                        print(error)
                        continue

                    target_addr = adr_addr + adr_offset
                    if stack_block_found:
                        # print('\tstack block func addr 0x{:x} {}'.
                        #       format(target_addr, util.get_desc_for_address(target.ResolveLoadAddress(target_addr))))
                        stack_block_found = False
                        if target_addr in stack_blocks:
                            print("ignore stack block 0x{:x}".format(target_addr))
                            continue

                        block_func_addr = target.ResolveLoadAddress(target_addr)
                        brkpoint = target.BreakpointCreateBySBAddress(block_func_addr)
                        # 判断下断点是否成功
                        if not brkpoint.IsValid() or brkpoint.num_locations == 0:
                            print("Breakpoint isn't valid or hasn't found any hits")
                        else:
                            total_count += 1
                            print("break stack block with Breakpoint {}: {}, address = 0x{:x}"
                                  .format(brkpoint.GetID(), util.get_desc_for_address(block_func_addr), target_addr)
                                  )
                            stack_blocks.append(target_addr)
                elif next_ins.GetMnemonic(target) == 'adrp':
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

                    if stack_block_found:
                        # print('\tstack block func addr 0x{:x} {}'.
                        #       format(target_addr, util.get_desc_for_address(target.ResolveLoadAddress(target_addr))))
                        stack_block_found = False
                        if target_addr in stack_blocks:
                            print("ignore stack block 0x{:x}".format(target_addr))
                            continue

                        block_func_addr = target.ResolveLoadAddress(target_addr)
                        brkpoint = target.BreakpointCreateBySBAddress(block_func_addr)
                        # 判断下断点是否成功
                        if not brkpoint.IsValid() or brkpoint.num_locations == 0:
                            print("Breakpoint isn't valid or hasn't found any hits")
                        else:
                            total_count += 1
                            print("break stack block with Breakpoint {}: {}, address = 0x{:x}"
                                  .format(brkpoint.GetID(), util.get_desc_for_address(block_func_addr), target_addr)
                                  )
                            stack_blocks.append(target_addr)

                    adrp_ins = None
                elif next_ins.GetMnemonic(target) == 'ldr':
                    ldr_ins_ops = next_ins.GetOperands(target).replace(' ', '')
                    if adrp_ins:
                        # print('0x{:x}: ldr {}'.format(next_ins.GetAddress().GetLoadAddress(target), ldr_ins_ops))
                        ldr_op_list = ldr_ins_ops.split(',')
                        if len(ldr_op_list) != 3:
                            continue

                        operand = ldr_op_list[2]
                        if ']' not in operand:
                            continue

                        if ']!' in operand:
                            continue

                        if '#' not in operand:
                            continue

                        operand = operand.replace('#', '')
                        operand = operand.replace(']', '')

                        try:
                            adr_offset = int(operand, 16)
                        except Exception as error:
                            print(error)
                            adrp_ins = None
                            continue

                        ldr_addr = (adrp_addr & 0xFFFFFFFFFFFFF000) + (int(adrp_op_list[-1]) * 4096) + adr_offset

                        error = lldb.SBError()
                        target_addr = process.ReadPointerFromMemory(ldr_addr, error)
                        if error.Success():
                            next_ins_addr = next_ins.GetAddress()
                            # print('target_addr: 0x{:x} {}'.format(target_addr, next_ins_addr))
                            if target_addr == stack_block_isa:
                                print('find a stack block @0x{:x} in {}'.
                                      format(next_ins_addr.GetLoadAddress(target),
                                             util.get_desc_for_address(next_ins_addr)))
                                stack_block_found = True

                        adrp_ins = None
                    else:
                        # ldr x0,#0x5330
                        ret = re.match('^x\\d{1,2},#0x\\d+', ldr_ins_ops)
                        # print('0x{:x}: ldr {} {}'.
                        #       format(next_ins.GetAddress().GetLoadAddress(target), ldr_ins_ops, ret))
                        if ret:
                            ldr_op_list = ldr_ins_ops.split(',')
                            ldr_offset = int(ldr_op_list[1].replace('#', ''), 16)
                            next_ins_addr = next_ins.GetAddress()
                            next_ins_loadaddr = next_ins_addr.GetLoadAddress(target)
                            addr = next_ins_loadaddr + ldr_offset
                            if addr == stack_block_addr:
                                print('find a stack block @0x{:x} in {}'.
                                      format(next_ins_loadaddr, util.get_desc_for_address(next_ins_addr)))
                                stack_block_found = True

                elif adrp_ins and next_ins.GetMnemonic(target) == 'str':
                    ldr_ins_ops = next_ins.GetOperands(target).replace(' ', '')
                    ldr_op_list = ldr_ins_ops.split(',')
                    if ldr_op_list[0] != adrp_op_list[0]:
                        adrp_ins = None
                else:
                    adrp_ins = None

    result.AppendMessage("set {} breakpoints".format(total_count))


def get_blocks_info(module):
    command_script = '@import Foundation;'
    command_script += r'''
    struct mach_header_64 {
        uint32_t    magic;        /* mach magic number identifier */
        int32_t        cputype;    /* cpu specifier */
        int32_t        cpusubtype;    /* machine specifier */
        uint32_t    filetype;    /* type of file */
        uint32_t    ncmds;        /* number of load commands */
        uint32_t    sizeofcmds;    /* the size of all the load commands */
        uint32_t    flags;        /* flags */
        uint32_t    reserved;    /* reserved */
    };

    struct segment_command_64 { /* for 64-bit architectures */
        uint32_t    cmd;        /* LC_SEGMENT_64 */
        uint32_t    cmdsize;    /* includes sizeof section_64 structs */
        char        segname[16];    /* segment name */
        uint64_t    vmaddr;        /* memory address of this segment */
        uint64_t    vmsize;        /* memory size of this segment */
        uint64_t    fileoff;    /* file offset of this segment */
        uint64_t    filesize;    /* amount to map from the file */
        int32_t        maxprot;    /* maximum VM protection */
        int32_t        initprot;    /* initial VM protection */
        uint32_t    nsects;        /* number of sections in segment */
        uint32_t    flags;        /* flags */
    };
    struct section_64 { /* for 64-bit architectures */
        char		sectname[16];	/* name of this section */
        char		segname[16];	/* segment this section goes in */
        uint64_t	addr;		/* memory address of this section */
        uint64_t	size;		/* size in bytes of this section */
        uint32_t	offset;		/* file offset of this section */
        uint32_t	align;		/* section alignment (power of 2) */
        uint32_t	reloff;		/* file offset of relocation entries */
        uint32_t	nreloc;		/* number of relocation entries */
        uint32_t	flags;		/* flags (section type and attributes)*/
        uint32_t	reserved1;	/* reserved (for offset or index) */
        uint32_t	reserved2;	/* reserved (for count or sizeof) */
        uint32_t	reserved3;	/* reserved */
    };
    #define __LP64__ 1
    #ifdef __LP64__
    typedef struct mach_header_64 mach_header_t;
    #else
    typedef struct mach_header mach_header_t;
    #endif
    struct load_command {
        uint32_t cmd;		/* type of load command */
        uint32_t cmdsize;	/* total size of command in bytes */
    };
    '''
    command_script += 'NSString *x_module_name = @"' + module + '";'
    command_script += r'''
    if (!x_module_name) {
        x_module_name = [[[NSBundle mainBundle] executablePath] lastPathComponent];
    }
    
    const mach_header_t *x_mach_header = NULL;
    intptr_t slide = 0;
    uint32_t image_count = (uint32_t)_dyld_image_count();
    for (uint32_t i = 0; i < image_count; i++) {
        const char *name = (const char *)_dyld_get_image_name(i);
        if (!name) {
            continue;
        }
        const mach_header_t *mach_header = (const mach_header_t *)_dyld_get_image_header(i);
        
        NSString *module_name = [[NSString stringWithUTF8String:name] lastPathComponent];
        if ([module_name isEqualToString:x_module_name]) {
            x_mach_header = mach_header;
            slide = (intptr_t)_dyld_get_image_vmaddr_slide(i);
            break;
        }
    }
    
    void *globalBlock = &_NSConcreteGlobalBlock;
    void *stackBlock = &_NSConcreteStackBlock;
    NSMutableString *globalBlocks = [NSMutableString string];
    NSMutableString *stackBlockAddr = [NSMutableString string];
    
    void (^parse_g_block)(struct section_64 *) = ^(struct section_64 *data_const_sec){
        uint64_t sec_size = data_const_sec->size;
        int pointer_size = sizeof(void *);
        uint64_t count = sec_size / pointer_size;
        void **ptr = (void **)(slide + data_const_sec->addr);
        for (uint64_t i = 0; i < count; i++) {
            void *tmp = ptr[i];
            if (tmp == globalBlock) {
                [globalBlocks appendFormat:@"%p:%p;", &ptr[i], ptr[i + 2]];
            }
        }
    };
    
    void (^parse_s_block)(struct section_64 *) = ^(struct section_64 *data_got_sec){
        uint64_t sec_size = data_got_sec->size;
        int pointer_size = sizeof(void *);
        uint64_t count = sec_size / pointer_size;
        void **ptr = (void **)(slide + data_got_sec->addr);
        for (uint64_t i = 0; i < count; i++) {
            void *tmp = ptr[i];
            if (tmp == stackBlock) {
                [stackBlockAddr appendFormat:@"%p;", &ptr[i]];
            }
        }
    };
    
    if (x_mach_header) {
        uint32_t magic = x_mach_header->magic;
        if (magic == 0xfeedfacf) { // MH_MAGIC_64
            uint32_t ncmds = x_mach_header->ncmds;
            if (ncmds > 0) {
                uintptr_t cur = (uintptr_t)x_mach_header + sizeof(mach_header_t);
                struct load_command *sc = NULL;
                for (uint i = 0; i < ncmds; i++, cur += sc->cmdsize) {
                    sc = (struct load_command *)cur;
                    if (sc->cmd == 0x19) { // LC_SEGMENT_64
                        struct segment_command_64 *seg = (struct segment_command_64 *)sc;
                        BOOL isSegData = strcmp(seg->segname, "__DATA") == 0;
                        BOOL isSegDataConst = strcmp(seg->segname, "__DATA_CONST") == 0;
                        if (isSegData || isSegDataConst) { //SEG_DATA
                            
                            int index = 0;
                            if (isSegData) {
                                index = 0;
                            } else if (isSegDataConst) {
                                index = 1;
                            }
                            uint32_t nsects = seg->nsects;
                            char *sec_start = (char *)seg + sizeof(struct segment_command_64);
                            size_t sec_size = sizeof(struct section_64);
                            for (uint32_t idx = 0; idx < nsects; idx++) {
                                struct section_64 *sec = (struct section_64 *)sec_start;
                                char *sec_name = strndup(sec->sectname, 16);
                                if (strcmp(sec_name + strlen(sec_name) - 5, "const") == 0
                                    && strcmp(sec_name + strlen(sec_name) - 11, "_objc_const") != 0) {
                                    parse_g_block(sec);
                                } else if (strcmp(sec_name, "__got") == 0) {
                                    parse_s_block(sec);
                                }
                                
                                sec_start += sec_size;
                                if (sec_name) {
                                    free(sec_name);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    NSUInteger len = [globalBlocks length];
    if (len > 0) {
        [globalBlocks replaceCharactersInRange:NSMakeRange(len - 1, 1) withString:@""];
    }
    
    len = [stackBlockAddr length];
    if (len > 0) {
        [stackBlockAddr replaceCharactersInRange:NSMakeRange(len - 1, 1) withString:@""];
    }
    
    NSDictionary *block_info = @{
        @"_NSConcreteGlobalBlock": [NSString stringWithFormat:@"%p", globalBlock],
        @"_NSConcreteStackBlock": [NSString stringWithFormat:@"%p", stackBlock],
        @"globalBlocks": globalBlocks,
        @"stackBlockAddr": stackBlockAddr,
        @"slide": @(slide),
        @"error": !x_mach_header ? @"module not found" : @""
    };
    
    NSData *json_data = [NSJSONSerialization dataWithJSONObject:block_info options:kNilOptions error:nil];
    // 4 NSUTF8StringEncoding
    NSString *json_str = [[NSString alloc] initWithData:json_data encoding:4];
    json_str;
    '''

    ret_str = util.exe_script(command_script)

    return ret_str


def generate_option_parser(proc, args=''):
    usage = "usage: %prog{}\n".format(args)

    parser = optparse.OptionParser(usage=usage, prog=proc)

    return parser


def generate_find_parser(proc):
    usage = "usage: %prog <block addr> or <block func ptr>\n" + \
        "Use block func ptr for stack block, Use block addr for global block"

    parser = optparse.OptionParser(usage=usage, prog=proc)

    return parser
