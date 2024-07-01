# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import os


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "lookup the specified bytes in user modules" -f '
        'LookupBytes.lookup_bytes blookup')


def lookup_bytes(debugger, command, result, internal_dict):
    """
    lookup the specified bytes in user modules
    implemented in YJLLDB/src/LookupBytes.py
    """
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

    if len(args) == 0:
        result.AppendMessage(parser.get_usage())
        return

    input_args = ''.join(args)
    input_args = input_args.replace("'", "")
    input_args = input_args.replace("\"", "")
    input_args = input_args.replace("\\x", "")
    input_bytes = bytes.fromhex(input_args)

    bytes_len = len(input_bytes)

    lookup_module = options.module
    if options.count:
        count = int(options.count)
    else:
        count = 0

    print('lookup bytes, this may take a while')
    target = debugger.GetSelectedTarget()
    bundle_path = target.GetExecutable().GetDirectory()
    total_count = 0
    for module in target.module_iter():
        module_file_spec = module.GetFileSpec()

        name = module_file_spec.GetFilename()
        if lookup_module:
            if lookup_module not in name:
                continue
        else:
            module_dir = module_file_spec.GetDirectory()
            if bundle_path not in module_dir:
                continue

            if name.startswith('libswift'):
                continue

        hits_count = 0
        result.AppendMessage("-----try to lookup bytes in %s-----" % name)
        for seg in module.section_iter():
            seg_name = seg.GetName()
            search_all = options.all
            if search_all:
                if seg_name == '__PAGEZERO':
                    continue
            else:
                if seg_name != "__TEXT":
                    continue

            def match_seg(in_seg, in_seg_name, in_sec_name, count):
                matched_count = 0
                sec_addr = in_seg.GetLoadAddress(target)
                error = lldb.SBError()
                sec_size = in_seg.GetByteSize()
                if sec_size == 0:
                    if len(in_sec_name):
                        result.AppendMessage('ignore empty sec {}.{}'.format(in_seg_name, in_sec_name))
                    else:
                        result.AppendMessage('ignore empty seg {}'.format(in_seg_name))
                    return 0

                # 砸壳应用读取不到
                # sec_data = sec.GetSectionData().ReadRawData(error, 0, sec_size)
                sec_data = target.ReadMemory(lldb.SBAddress(sec_addr, target), sec_size, error)
                if not error.Success():
                    result.AppendMessage(
                        'read section {}:0x{:x} failed! {}'.format(in_sec_name, sec_addr, error.GetCString()))
                    return 0

                pos = 0
                while True:
                    pos = sec_data.find(input_bytes, pos)
                    if pos == -1:
                        break

                    matched_count += 1
                    bytes_addr = pos + sec_addr
                    inst_addr = target.ResolveLoadAddress(bytes_addr)
                    addr_info = '{}'.format(inst_addr)
                    if addr_info:
                        result.AppendMessage('address = 0x{:x} where = {}'.format(bytes_addr, inst_addr))
                    else:
                        result.AppendMessage('address = 0x{:x} where = {}'.format(bytes_addr, seg_name))

                    if 0 < count <= matched_count:
                        break

                    pos += bytes_len

                return matched_count

            if search_all:
                matched_count = match_seg(seg, seg_name, '', count)
                total_count += matched_count
                hits_count += matched_count
            else:
                for sec in seg:
                    sec_name = sec.GetName()

                    if "_stub" in sec_name or \
                            "__objc_methname" == sec_name or \
                            "__objc_classname" == sec_name or \
                            "__objc_methtype" == sec_name or \
                            "__cstring" == sec_name or \
                            "__ustring" == sec_name or \
                            "__gcc_except_tab" == sec_name or \
                            "__const" == sec_name or \
                            "__unwind_info" == sec_name:
                        continue

                    matched_count = match_seg(sec, seg_name, sec_name, count)
                    total_count += matched_count
                    hits_count += matched_count

            if 0 < count <= total_count:
                break

        if hits_count == 0:
            result.AppendMessage("input bytes not found in {}".format(name))

        if 0 < count <= total_count:
            break

    result.AppendMessage("{} locations found".format(total_count))


def generate_option_parser():
    usage = "usage: %prog bytes\n" + \
            "for example:\n" + \
            "\t%prog \\xc0\\x03\\x5f\\xd6\n" + \
            "\t%prog c0 03 5f d6\n" + \
            "\t%prog c0035fd6"

    parser = optparse.OptionParser(usage=usage, prog='blookup')
    parser.add_option("-a", "--all",
                      action="store_true",
                      default=False,
                      dest="all",
                      help="lookup bytes in all segments, default in __TEXT")
    parser.add_option("-m", "--module",
                      action="store",
                      dest="module",
                      help="lookup bytes in the specified module")
    parser.add_option("-c", "--count",
                      action="store",
                      dest="count",
                      help="lookup bytes in the specified module")

    return parser
