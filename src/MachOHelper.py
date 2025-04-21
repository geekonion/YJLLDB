# -*- coding: UTF-8 -*-

import lldb
import MachO
import util
# import json
from common import get_cs_super_blob, get_cs_blob_index, get_cs_blob, get_string


def get_function_starts(lookup_module_name_or_addr):
    target = lldb.debugger.GetSelectedTarget()
    module_file_spec, header_addr, slide, segment_info, module_name = \
        get_segment_info(target, lookup_module_name_or_addr, '__LINKEDIT')
    if not module_file_spec:
        print('module {} not found in image list'.format(module_name))
        # 兼容注入的库，这里不返回
        # return None, module_file_spec
        if segment_info:
            print('please wait')

    return get_function_starts_with_args(target, module_file_spec, header_addr, slide, segment_info)


def get_function_starts_with_module(module):
    target = lldb.debugger.GetSelectedTarget()
    module_file_spec, header_addr, slide, segment_info, module_name = \
        get_segment_info_in_module(target, module, '__LINKEDIT')
    if not module_file_spec:
        print('module {} not found in image list'.format(module_name))
        # return None, module_file_spec

    return get_function_starts_with_args(target, module_file_spec, header_addr, slide, segment_info)


def get_function_starts_with_args(target, module_file_spec, header_addr, slide, segment_info):
    funcs = []
    func_starts = []
    func_size_list = []
    byte_order = 'little' if target.GetByteOrder() == lldb.eByteOrderLittle else 'big'
    linkedit_offset = int(segment_info['offset'], 16)
    linkedit_vmaddr = int(segment_info['vmaddr'], 16)

    sects = segment_info['sects']
    func_starts_found = False
    for sect in sects:
        sec_name = sect['name']
        if sec_name != 'Function Starts':
            continue

        func_starts_found = True
        dataoff = int(sect['offset'], 16)
        datasize = int(sect['size'], 16)
        data_start = linkedit_vmaddr + slide + dataoff - linkedit_offset

        error1 = lldb.SBError()
        data_bytes = target.ReadMemory(lldb.SBAddress(data_start, target), datasize, error1)
        if not error1.Success():
            print('read data failed! {}'.format(error1.GetCString()))
            break

        file_offset = 0
        idx = 0
        func_size = 0
        while idx < datasize:
            offset = 0
            bit = 0
            while idx < datasize:
                byte = data_bytes[idx: idx + 1]
                byte_value = int.from_bytes(byte, byteorder=byte_order)
                if byte_value == 0:
                    idx += 1
                    continue

                tmp_slice = byte_value & 0x7f

                if bit >= 64 or tmp_slice << bit >> bit != tmp_slice:
                    pass
                else:
                    offset |= (tmp_slice << bit)
                    bit += 7

                idx += 1
                if byte_value & 0x80 == 0:
                    break

            if offset > 0:
                if file_offset != 0:
                    func_size = offset
                file_offset += offset
                func_start = header_addr + file_offset
                func_starts.append(func_start)
                if func_size > 0:
                    func_size_list.append(func_size)

        max_idx = len(func_starts) - 1
        for index, func_start in enumerate(func_starts):
            if index < max_idx:
                funcs.append((func_start, func_size_list[index]))
            else:
                func_addr_obj = target.ResolveLoadAddress(func_start)
                symbol = func_addr_obj.GetSymbol()
                end_addr = symbol.GetEndAddress().GetLoadAddress(target)
                func_size = end_addr - func_start

                funcs.append((func_start, func_size))
        # sects
        break

    return funcs, module_file_spec, func_starts_found


def get_entitlements(lookup_module_name):
    entitlements = None
    target = lldb.debugger.GetSelectedTarget()
    module_file_spec, header_addr, slide, segment_info, module_name = \
        get_segment_info(target, lookup_module_name, '__LINKEDIT')
    if not module_file_spec:
        print('module {} not found in image list'.format(module_name))
        # return entitlements

    if not segment_info:
        print('segment __LINKEDIT not found')
        return entitlements

    byte_order = 'little' if target.GetByteOrder() == lldb.eByteOrderLittle else 'big'
    linkedit_offset = int(segment_info['offset'], 16)
    linkedit_vmaddr = int(segment_info['vmaddr'], 16)

    code_signature_not_found = True
    ent_not_found = True
    sects = segment_info['sects']
    for sect in sects:
        sec_name = sect['name']
        if sec_name != 'Code Signature':
            continue

        code_signature_not_found = False
        dataoff = int(sect['offset'], 16)
        datasize = int(sect['size'], 16)
        data_start = linkedit_vmaddr + slide + dataoff - linkedit_offset

        error = lldb.SBError()
        sign_data = target.ReadMemory(lldb.SBAddress(data_start, target), datasize, error)
        if not error.Success():
            print('read header failed! {}'.format(error.GetCString()))
            break

        magic, length, cnt = get_cs_super_blob(sign_data, 0, byte_order)
        if magic == 0xfade0cc0:  # CSMAGIC_EMBEDDED_SIGNATURE
            size_of_cs_blob_index = 8  # size of struct CS_BlobIndex
            for idx in range(cnt):
                offset = idx * size_of_cs_blob_index
                data_type, data_offset = get_cs_blob_index(sign_data, 12 + offset, byte_order)
                # print("data_type {}, data_offset {}".format(data_type, data_offset))
                magic, length = get_cs_blob(sign_data, data_offset, byte_order)
                # print("magic {}, length {}".format(magic, length))
                if magic == 0xfade7171:  # kSecCodeMagicEntitlement
                    ent_not_found = False
                    header_len = 8
                    ent_len = length - header_len
                    if ent_len > 0:
                        entitlements = get_string(sign_data, data_offset + header_len, ent_len)
                        # print("ent {}".format(entitlements))

                    break

    if module_file_spec:
        module_name = module_file_spec.GetFilename()
    else:
        module_name = module_name

    if code_signature_not_found:
        entitlements = '{} apparently does not contain code signature'.format(module_name)
    elif ent_not_found:
        entitlements = '{} apparently does not contain any entitlements'.format(module_name)

    return entitlements


def get_segment_info(target, module_name_or_addr, target_seg_name):
    target_module = None

    is_addr, lookup_module_name_or_addr = util.parse_arg(module_name_or_addr)

    module_addr = 0
    if is_addr:
        module_addr = int(lookup_module_name_or_addr, 16)

    for module in target.module_iter():
        module_file_spec = module.GetFileSpec()
        module_name = module_file_spec.GetFilename()

        if is_addr:
            header_addr = 0
            for seg in module.section_iter():
                seg_name = seg.GetName()
                if seg_name == '__PAGEZERO':
                    continue
                elif seg_name == '__TEXT':
                    header_addr = seg.GetLoadAddress(target)
                    break

            if header_addr != module_addr:
                continue
        else:
            lib_name = lookup_module_name_or_addr + '.dylib'
            if lookup_module_name_or_addr != module_name and lib_name != module_name:
                continue

        target_module = module
        # modules
        break

    return get_segment_info_in_module(target, target_module, target_seg_name, is_addr, module_addr)


def get_segment_info_in_module(target, module, target_seg_name, is_addr, module_addr):
    header_addr = 0
    slide = 0
    segment_info = None
    header_size = 0
    module_file_spec = None
    module_name = None

    if module:
        module_file_spec = module.GetFileSpec()

        seg = module.FindSection('__TEXT')
        module_name = module_file_spec.GetFilename()
        if not seg:
            print('seg __TEXT not found in {}'.format(module_name))
            return module_file_spec, header_addr, slide, segment_info, module_name

        header_addr = seg.GetLoadAddress(target)
        slide = header_addr - seg.GetFileAddress()

        first_sec = seg.GetSubSectionAtIndex(0)
        sec_addr = first_sec.GetLoadAddress(target)

        header_size = sec_addr - header_addr

    if not module and is_addr:
        header_addr = module_addr
        header_size = 0x4000

    error = lldb.SBError()
    header_data = target.ReadMemory(lldb.SBAddress(header_addr, target), header_size, error)
    if not error.Success():
        print('read header failed! {}'.format(error.GetCString()))
        return module_file_spec, header_addr, slide, segment_info

    info = MachO.parse_header(header_data)
    # print(json.dumps(info, indent=2))

    lcs = info['lcs']
    for lc in lcs:
        cmd = lc['cmd']
        if cmd != '19':  # LC_SEGMENT_64
            continue

        seg_name = lc['name']
        if seg_name != target_seg_name:
            continue

        segment_info = lc
        # lcs
        break

    if not module:
        module_file_spec = None

    if slide == 0:
        slide = header_addr - int(info['text_vmaddr'], 16)
        module_name = info.get('name')

    return module_file_spec, header_addr, slide, segment_info, module_name
