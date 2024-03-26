# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import util


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "patch bytes in user modules" -f PatchBytes.patch patch')


def patch(debugger, command, result, internal_dict):
    """
    patch bytes in user modules
    implemented in YJLLDB/src/PatchBytes.py
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

    if len(args) == 0 and not options.size:
        result.AppendMessage(parser.get_usage())
        return
    elif len(args) == 1:
        input_arg = args[0].replace("'", "")
        comps = input_arg.split('\\x')
        bytes_list = [int(x, 16) for x in comps if len(x) > 0]
    else:
        bytes_list = [int(x, 16) for x in args]

    if options.address:
        if options.size:
            size = int(options.size)
        else:
            size = len(bytes_list)

        address_str = options.address
        if address_str.startswith('0x'):
            address = int(address_str, 16)
        else:
            address = int(address_str)

        patch_addr_with_bytes(debugger, result, address, size, bytes_list)
    else:
        patch_all_matched_bytes_with_nop(debugger, result, bytes_list)


def patch_all_matched_bytes_with_nop(debugger, result, bytes_list):
    bytes_len = len(bytes_list)
    if not util.is_x64() and bytes_len % 4 != 0:
        result.SetError("The number of bytes must be a multiple of 4")
        return

    input_bytes = bytes(bytes_list)

    print('lookup bytes, this may take a while')
    new_bytes = util.gen_nop(bytes_len)
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    bundle_path = target.GetExecutable().GetDirectory()
    total_count = 0
    for module in target.module_iter():
        module_file_spec = module.GetFileSpec()

        module_dir = module_file_spec.GetDirectory()
        if bundle_path not in module_dir:
            continue

        name = module_file_spec.GetFilename()
        if name.startswith('libswift'):
            continue

        hits_count = 0
        result.AppendMessage("-----try to patch bytes in %s-----" % name)
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
                error1 = lldb.SBError()
                sec_size = sec.GetByteSize()

                # 砸壳应用读取不到
                # sec_data = sec.GetSectionData().ReadRawData(error, 0, sec_size)
                sec_data = target.ReadMemory(lldb.SBAddress(sec_addr, target), sec_size, error1)
                if not error1.Success():
                    result.AppendMessage('read section {}:0x{:x} failed! {}'.format(sec_name, sec_addr, error1.GetCString()))
                    continue

                pos = 0
                while True:
                    pos = sec_data.find(input_bytes, pos)
                    if pos == -1:
                        break

                    hits_count += 1
                    total_count += 1
                    bytes_addr = pos + sec_addr

                    error2 = lldb.SBError()
                    process.WriteMemory(bytes_addr, new_bytes, error2)
                    if not error2.Success():
                        result.AppendMessage('patch bytes at 0x{:x} failed! {}'.format(bytes_addr, error2.GetCString()))
                        continue

                    pos += bytes_len

        if hits_count == 0:
            result.AppendMessage("input bytes not found")

    result.AppendMessage("patch {} locations".format(total_count))


def patch_addr_with_bytes(debugger, result, addr, size, bytes_list):
    bytes_len = len(bytes_list)
    if bytes_len > 0 and bytes_len != size:
        result.SetError("arguments error")
        return
    elif bytes_len == 0 and not util.is_x64() and size % 4 != 0:
        result.SetError("The number of bytes must be a multiple of 4")
        return

    if bytes_len:
        new_bytes = bytes(bytes_list)
    else:
        new_bytes = util.gen_nop(size)

    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    error = lldb.SBError()
    process.WriteMemory(addr, new_bytes, error)
    if error.Success():
        result.AppendMessage('patch {} bytes at 0x{:x} success'.format(len(new_bytes), addr))
    else:
        result.AppendMessage('patch bytes at 0x{:x} failed!, {}'.format(addr, error.GetCString()))


def generate_option_parser():
    usage = "usage: %prog bytes\n" + \
            "examples:\n" + \
            "\t1. %prog \\xc0\\x03\\x5f\\xd6                    # patch the specified bytes with nop\n" + \
            "\t2. %prog c0 03 5f d6                         # patch the specified bytes with nop\n" + \
            "\t3. %prog -a 0x12345678 \\x1f\\x20\\x03\\xd5      # patch bytes at address with the specified bytes\n" + \
            "\t4. %prog -a 0x12345678 1f 20 03 d5           # patch bytes at address with the specified bytes\n" + \
            "\t5. %prog -a 0x12345678 -s 4                  # patch bytes at address with nop"

    parser = optparse.OptionParser(usage=usage, prog='patch')
    parser.add_option("-a", "--address",
                      action="store",
                      dest="address",
                      help="address to path")
    parser.add_option("-s", "--size",
                      action="store",
                      dest="size",
                      help="size to path")

    return parser
