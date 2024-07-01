# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import os


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "set breakpoints at the specified bytes in user modules" -f '
        'BreakAtBytes.break_at_bytes bab')


def break_at_bytes(debugger, command, result, internal_dict):
    """
    set breakpoints at the specified bytes in user modules
    implemented in YJLLDB/src/BreakAtBytes.py
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

    print('lookup bytes, this may take a while')
    target = debugger.GetSelectedTarget()
    bundle_path = target.GetExecutable().GetDirectory()
    brkpoint_count = 0
    for module in target.module_iter():
        module_file_spec = module.GetFileSpec()

        module_dir = module_file_spec.GetDirectory()
        if bundle_path not in module_dir:
            continue

        name = module_file_spec.GetFilename()
        if name.startswith('libswift'):
            continue

        hits_count = 0
        result.AppendMessage("-----try to set breakpoint at %s-----" % name)
        for seg in module.section_iter():
            seg_name = seg.GetName()
            if seg_name != "__TEXT":
                continue

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

                sec_addr = sec.GetLoadAddress(target)
                error = lldb.SBError()
                sec_size = sec.GetByteSize()

                if options.verbose:
                    print("{} {:x}-{:x}".format(sec_name, sec_addr, sec_size))

                # 砸壳应用读取不到
                # sec_data = sec.GetSectionData().ReadRawData(error, 0, sec_size)
                sec_data = target.ReadMemory(lldb.SBAddress(sec_addr, target), sec_size, error)
                if not error.Success():
                    print('read section {} data failed!'.format(sec_name))
                    continue

                pos = 0
                while True:
                    pos = sec_data.find(input_bytes, pos)
                    if pos == -1:
                        break

                    hits_count += 1
                    
                    bytes_addr = pos + sec_addr
                    inst_addr = target.ResolveLoadAddress(bytes_addr)
                    brkpoint = target.BreakpointCreateBySBAddress(inst_addr)
                    # 判断下断点是否成功
                    if not brkpoint.IsValid() or brkpoint.num_locations == 0:
                        result.AppendWarning("Breakpoint isn't valid or hasn't found any hits")
                    else:
                        brkpoint_count += 1
                        addr = inst_addr.GetLoadAddress(target)
                        result.AppendMessage("Breakpoint {}: where = {}, address = 0x{:x}"
                                             .format(brkpoint.GetID(), inst_addr, addr))

                    pos += bytes_len

        if hits_count == 0:
            result.AppendMessage("input bytes not found")

    result.AppendMessage("set {} breakpoints".format(brkpoint_count))


def generate_option_parser():
    usage = "usage: %prog bytes\n" + \
            "for example:\n" + \
            "\t%prog \\xc0\\x03\\x5f\\xd6\n" + \
            "\t%prog c0 03 5f d6\n" + \
            "\t%prog c0035fd6"

    parser = optparse.OptionParser(usage=usage, prog='bab')

    parser.add_option("-v", "--verbose",
                      action="store_true",
                      default=False,
                      dest="verbose",
                      help="verbose output")

    return parser
