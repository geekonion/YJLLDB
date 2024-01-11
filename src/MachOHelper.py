# -*- coding: UTF-8 -*-

import lldb
import MachO


def get_function_starts(result, target, lookup_module_name):
    funcs = None
    module_file_spec, header_addr, slide, segment_info = get_segment_info(result, target, lookup_module_name, '__LINKEDIT')
    if not module_file_spec:
        return funcs, module_file_spec

    funcs = []
    byte_order = 'little' if target.GetByteOrder() == lldb.eByteOrderLittle else 'big'
    linkedit_offset = int(segment_info['offset'], 16)
    linkedit_vmaddr = int(segment_info['vmaddr'], 16)

    sects = segment_info['sects']
    for sect in sects:
        sec_name = sect['name']
        if sec_name != 'Function Starts':
            continue

        dataoff = int(sect['offset'], 16)
        datasize = int(sect['size'], 16)
        data_start = linkedit_vmaddr + slide + dataoff - linkedit_offset

        error1 = lldb.SBError()
        data_bytes = target.ReadMemory(lldb.SBAddress(data_start, target), datasize, error1)
        if not error1.Success():
            result.AppendWarning('read data failed! {}'.format(error1.GetCString()))
            break

        file_offset = 0
        idx = 0
        while idx < datasize:
            offset = 0
            bit = 0
            while idx < datasize:
                byte = data_bytes[idx: idx + 1]
                byte_value = int.from_bytes(byte, byteorder=byte_order)
                if byte_value == 0:
                    idx += 1
                    continue

                slice = byte_value & 0x7f

                if bit >= 64 or slice << bit >> bit != slice:
                    pass
                else:
                    offset |= (slice << bit)
                    bit += 7

                idx += 1
                if byte_value & 0x80 == 0:
                    break

            if offset > 0:
                file_offset += offset
                func_start = header_addr + file_offset
                funcs.append(func_start)
        # sects
        break

    return funcs, module_file_spec


def get_segment_info(result, target, lookup_module_name, target_seg_name):
    module_file_spec = None
    header_addr = 0
    slide = 0
    segment_info = None

    for module in target.module_iter():
        module_file_spec = module.GetFileSpec()
        module_name = module_file_spec.GetFilename()

        if lookup_module_name not in module_name:
            continue

        seg = module.FindSection('__TEXT')
        if not seg:
            result.AppendWarning('seg __TEXT not found in {}'.format(module_name))
            continue

        result.AppendMessage("-----parsing module %s-----" % module_name)
        header_addr = seg.GetLoadAddress(target)
        slide = header_addr - seg.GetFileAddress()

        first_sec = seg.GetSubSectionAtIndex(0)
        sec_addr = first_sec.GetLoadAddress(target)

        error = lldb.SBError()
        header_size = sec_addr - header_addr
        header_data = target.ReadMemory(lldb.SBAddress(header_addr, target), header_size, error)
        if not error.Success():
            result.AppendWarning('read header failed! {}'.format(error.GetCString()))
            break

        info = MachO.parse_header(header_data)

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
        # modules
        break

    return module_file_spec, header_addr, slide, segment_info
