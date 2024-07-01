# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex


class Module:
    path = ''
    load_address = 0
    slide = 0
    size = 0
    uuid = ''
    arch = ''


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "List current executable and dependent shared library images, '
        'sorted by load address." -f ImageList.image_list image_list')


def image_list(debugger, command, result, internal_dict):
    """
    List current executable and dependent shared library images, sorted by load address.
    implemented in YJLLDB/src/ImageList.py
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

    if options.count:
        input_count = int(options.count)
    else:
        input_count = 0

    n_modules = len(args)
    target = debugger.GetSelectedTarget()
    modules = []
    symbol_comp = ')/Symbols/'
    symbol_comp_len = len(symbol_comp)

    for module in target.module_iter():
        if n_modules > 0:
            mod_spec = module.GetFileSpec()
            module_name = mod_spec.GetFilename()
            if module_name not in args:
                continue

        slide = 0
        header_addr = 0
        module_size = 0
        for seg in module.section_iter():
            seg_name = seg.GetName()
            if seg_name == '__PAGEZERO':
                continue
            elif seg_name == '__TEXT':
                header_addr = seg.GetLoadAddress(target)
                slide = header_addr - seg.GetFileAddress()

            module_size += seg.GetByteSize()

        platform_file_path = str(module.GetPlatformFileSpec())
        pos = platform_file_path.find(symbol_comp)
        if pos == -1:
            module_path = platform_file_path
        else:
            path_start = pos + symbol_comp_len - 1
            module_path = platform_file_path[path_start:]
        mod = Module()
        mod.path = module_path
        mod.load_address = header_addr
        mod.slide = slide
        mod.size = module_size
        mod.uuid = module.GetUUIDString()
        triple = module.GetTriple()
        pos = triple.find('-')
        mod.arch = triple[:pos]
        modules.append(mod)

    sorted_modules = sorted(modules, key=lambda tmp_module: tmp_module.load_address)

    if options.verbose:
        print("index    load addr - end addr(slide)         vmsize arch  uuid   path")
    else:
        print("index     load addr(slide)     vmsize path")

    print('-' * 60)
    for idx, module in enumerate(sorted_modules):
        mod_size = module.size
        KB = 1000
        MB = KB * KB
        GB = MB * KB
        if mod_size < KB:
            size_str = '{:5}B'.format(mod_size)
        elif mod_size < MB:
            size_str = '{:5.1f}K'.format(mod_size / KB)
        elif mod_size < GB:
            size_str = '{:5.1f}M'.format(mod_size / MB)
        else:
            size_str = '{:5.1f}G'.format(mod_size / GB)

        if options.verbose:
            mod_start = module.load_address
            mod_end = mod_start + mod_size
            print("[{:>3}] 0x{:x} - 0x{:x}(0x{:09x}) {} {} {} {}".
                  format(idx, mod_start, mod_end, module.slide, size_str, module.arch, module.uuid, module.path))
        else:
            print("[{:>3}] 0x{:x}(0x{:09x}) {} {}".
                  format(idx, module.load_address, module.slide, size_str, module.path))

        if input_count > 0 and idx == input_count - 1:
            break


def generate_option_parser():
    usage = "usage: %prog [-c count]\n"

    parser = optparse.OptionParser(usage=usage, prog='image_list')
    parser.add_option("-c", "--count",
                      dest="count",
                      help="image count")
    parser.add_option("-v", "--verbose",
                      action='store_true',
                      default=False,
                      dest="verbose",
                      help="verbose output")

    return parser
