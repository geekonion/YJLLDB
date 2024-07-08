# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import util
import MachO
import common


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "dump NON_LAZY_SYMBOL_POINTERS of the specified module" -f '
        'SymbolPointers.dump_got got')

    debugger.HandleCommand(
        'command script add -h "dump LAZY_SYMBOL_POINTERS of the specified module" -f '
        'SymbolPointers.dump_lazy_symbol_ptr lazy_sym')


def dump_got(debugger, command, result, internal_dict):
    """
    dump NON_LAZY_SYMBOL_POINTERS of the specified module
    implemented in YJLLDB/src/SymbolPointers.py
    """
    handle_command(debugger, command, result, 'got')


def dump_lazy_symbol_ptr(debugger, command, result, internal_dict):
    """
    dump LAZY_SYMBOL_POINTERS of the specified module
    implemented in YJLLDB/src/SymbolPointers.py
    """
    handle_command(debugger, command, result, 'lazy_sym')


def handle_command(debugger, command, result, name):
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

    if name == 'got':
        mask = 0x6  # S_NON_LAZY_SYMBOL_POINTERS 0x6
    elif name == 'lazy_sym':
        mask = 0x7  # S_LAZY_SYMBOL_POINTERS 0x7
    else:
        result.SetError("\n" + parser.get_usage())
        return

    is_address = False
    addr_str = None
    lookup_module_name = None
    if len(args) == 1:
        input_arg = args[0]
        is_address = input_arg.startswith('0x')
        if is_address:
            addr_str = input_arg
        else:
            lookup_module_name = input_arg
    else:
        file_spec = target.GetExecutable()
        lookup_module_name = file_spec.GetFilename()

    total_count = 0
    if is_address:
        header_addr = int(addr_str, 16)
        header_size = 0x4000
        message, count = parse_macho(target, header_addr, header_size, 0, mask)
        total_count += count

        result.AppendMessage(message)
    else:
        for module in target.module_iter():
            module_file_spec = module.GetFileSpec()
            module_name = module_file_spec.GetFilename()

            if lookup_module_name != module_name and lookup_module_name + '.dylib' != module_name:
                continue
            seg = module.FindSection('__TEXT')
            if not seg:
                result.AppendMessage('seg __TEXT not found in {}'.format(module_name))
                continue

            result.AppendMessage("-----parsing module %s-----" % module_name)
            header_addr = seg.GetLoadAddress(target)
            slide = header_addr - seg.GetFileAddress()

            first_sec = seg.GetSubSectionAtIndex(0)
            sec_addr = first_sec.GetLoadAddress(target)
            header_size = sec_addr - header_addr
            message, count = parse_macho(target, header_addr, header_size, slide, mask)
            total_count += count

            result.AppendMessage(message)

    result.AppendMessage('{} location(s) found'.format(total_count))


def parse_macho(target, header_addr, header_size, slide, mask):
    message = ''
    total_count = 0
    error = lldb.SBError()
    header_data = target.ReadMemory(lldb.SBAddress(header_addr, target), header_size, error)
    if not error.Success():
        message += 'read header failed! {}\n'.format(error.GetCString())
        return message, total_count

    info = MachO.parse_header(header_data)
    if slide == 0:
        slide = header_addr - int(info['text_vmaddr'], 16)

    target_sym_sec = None
    linkedit_seg = None
    lcs = info['lcs']
    for lc in lcs:
        cmd = lc['cmd']

        if cmd != '19':  # LC_SEGMENT_64
            continue

        if lc['name'] == '__LINKEDIT':
            linkedit_seg = lc
            continue

        sects = lc['sects']
        for sect in sects:
            flags_str = sect.get('flags')
            if not flags_str:
                continue

            # SECTION_TYPE 0x000000ff
            is_lazy_sym = int(flags_str, 16) & 0x000000ff == mask
            if not is_lazy_sym:
                continue

            target_sym_sec = sect

    if target_sym_sec:
        message, count = get_lazy_sym_name(target, slide, target_sym_sec, linkedit_seg)
        total_count += count
    else:
        message = 'section not found'

    return message, total_count


def get_lazy_sym_name(target, slide, target_sym_sec, linkedit_seg):
    message = ''
    total_count = 0

    byte_order = 'little' if target.GetByteOrder() == lldb.eByteOrderLittle else 'big'

    addr = int(target_sym_sec['addr'], 16)
    size = int(target_sym_sec['size'], 16)
    reserved1 = int(target_sym_sec['reserved1'], 16)
    sec_start = addr + slide

    error1 = lldb.SBError()
    sec_data = target.ReadMemory(lldb.SBAddress(sec_start, target), size, error1)
    if not error1.Success():
        message += 'read lazy symbol section failed! {}\n'.format(error1.GetCString())
        return message, total_count

    linkedit_vmaddr = 0
    linkedit_offset = 0
    symtab_offset = 0
    symtab_size = 0
    strtab_offset = 0
    strtab_size = 0
    indirect_symtab_offset = 0
    indirect_symtab_size = 0
    if linkedit_seg:
        linkedit_vmaddr = int(linkedit_seg['vmaddr'], 16)
        linkedit_offset = int(linkedit_seg['offset'], 16)

        sects = linkedit_seg['sects']
        for sect in sects:
            sec_name = sect['name']

            if sec_name == 'Symbol Table':
                symtab_offset = int(sect['offset'], 16)
                symtab_size = int(sect['size'], 16)
            if sec_name == 'String Table':
                strtab_offset = int(sect['offset'], 16)
                strtab_size = int(sect['size'], 16)
            elif sec_name == 'Dynamic Symbol Table':
                indirect_symtab_offset = int(sect['offset'], 16)
                indirect_symtab_size = int(sect['size'], 16)

    linkedit_base = slide + linkedit_vmaddr - linkedit_offset
    symtab = linkedit_base + symtab_offset
    strtab = linkedit_base + strtab_offset
    indirect_symtab = linkedit_base + indirect_symtab_offset
    indirect_symbol_indices_addr = indirect_symtab + reserved1 * 4

    error2 = lldb.SBError()
    indirect_symbol_indices_data = target.ReadMemory(
        lldb.SBAddress(indirect_symbol_indices_addr, target), indirect_symtab_size, error2)
    if not error2.Success():
        message += 'read indirect symbol indices failed! {}\n'.format(error2.GetCString())
        return message, total_count

    error3 = lldb.SBError()
    symtab_data = target.ReadMemory(lldb.SBAddress(symtab, target), symtab_size, error3)
    if not error3.Success():
        message += 'read symtab failed! {}\n'.format(error3.GetCString())
        return message, total_count

    error4 = lldb.SBError()
    strtab_data = target.ReadMemory(lldb.SBAddress(strtab, target), strtab_size, error4)
    if not error4.Success():
        message += 'read strtab failed! {}\n'.format(error4.GetCString())
        return message, total_count

    ptr_size = target.GetAddressByteSize()
    count = int(size / ptr_size)
    for i in range(0, count):
        addr = common.get_long(sec_data, i * ptr_size, byte_order)
        addr_obj = target.ResolveLoadAddress(addr)
        desc = '{}'.format(addr_obj)
        if not desc:
            desc = util.try_macho_address(addr_obj, target, False, True)

        symtab_index = common.get_int(indirect_symbol_indices_data, i * 4)

        # INDIRECT_SYMBOL_ABS	0x40000000
        # INDIRECT_SYMBOL_LOCAL	0x80000000
        if symtab_index & 0x40000000 == 0 and symtab_index & 0x80000000 == 0:
            # 16 sizeof(struct nlist_64)
            strtab_offset = common.get_int(symtab_data, symtab_index * 16)
            symbol_name = common.get_string(strtab_data, strtab_offset)
            # print(symtab_index, strtab_offset, symbol_name)
            pos = 0
            if symbol_name.startswith('_'):
                pos = 1
            desc += ' -> ' + symbol_name[pos:]

        message += 'address = 0x{:x} where = {}\n'.format(addr, desc)
        total_count += 1

    return message, total_count


def generate_option_parser(prog):
    usage = "usage: %prog ModuleName\n"

    parser = optparse.OptionParser(usage=usage, prog=prog)

    return parser
