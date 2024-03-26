# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import os
import util
import MachO
import json


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "dump the specified module, see also dmodule_before_load" -f '
        'DumpModule.dump_module dmodule')


def dump_module(debugger, command, result, internal_dict):
    """
    dump the specified module, see also dmodule_before_load
    implemented in YJLLDB/src/DumpModule.py
    """
    # 去掉转义符
    command = command.replace('\\', '\\\\')
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command_args = shlex.split(command, posix=False)
    # 创建parser
    parser = generate_option_parser('dmodule')
    # 解析参数，捕获异常
    try:
        # options是所有的选项，key-value形式，args是其余剩余所有参数，不包含options
        (options, args) = parser.parse_args(command_args)
    except Exception as error:
        print(error)
        result.SetError("\n" + parser.get_usage())
        return

    if args:
        lookup_module_name = ''.join(args)
    else:
        lookup_module_name = None

    if not lookup_module_name:
        result.AppendMessage(parser.get_usage())
        return

    lookup_module_name = lookup_module_name.replace("'", "")

    target = debugger.GetSelectedTarget()
    target_module = None
    module_name = None
    for module in target.module_iter():
        module_file_spec = module.GetFileSpec()
        module_name = module_file_spec.GetFilename()

        lib_name = lookup_module_name + '.dylib'
        if lookup_module_name == module_name or lib_name == module_name:
            target_module = module
            break

    if not target_module:
        result.AppendMessage('module {} not found'.format(lookup_module_name))
        return

    seg = target_module.FindSection('__TEXT')
    if not seg:
        result.AppendMessage('seg __TEXT not found')
        return

    header_addr = seg.GetLoadAddress(target)
    slide = header_addr - seg.GetFileAddress()
    first_sec = seg.GetSubSectionAtIndex(0)
    sec_addr = first_sec.GetLoadAddress(target)

    error = lldb.SBError()
    header_size = sec_addr - header_addr
    header_data = target.ReadMemory(lldb.SBAddress(header_addr, target), header_size, error)
    if not error.Success():
        result.AppendMessage('read header failed! {}'.format(error.GetCString()))
        return

    output_dir = os.path.expanduser('~') + '/lldb_dump_macho'
    util.try_mkdir(output_dir)

    info = MachO.parse_header(header_data)
    # print(json.dumps(info, indent=2))
    if info:
        print('dumping {}, this may take a while'.format(lookup_module_name))
        dump_message = dump_module_with_info(header_addr, header_size, info, module_name, slide, output_dir)

        result.AppendMessage("{}".format(dump_message))


def dump_segment(module_name, slide, segment, output_dir):
    addr = int(segment['vmaddr'], 16) + slide
    size = int(segment['segsize'], 16)
    name = segment['name']
    offset = int(segment['offset'], 16)

    return dump_region(module_name, addr, size, name, offset, output_dir)


def dump_section(module_name, slide, section, output_dir):
    addr = int(section['addr'], 16) + slide
    size = int(section['size'], 16)
    name = section['segname'] + '.' + section['name']
    offset = int(section['offset'], 16)

    return dump_region(module_name, addr, size, name, offset, output_dir)


def dump_region(module_name, addr, size, name, file_offset, output_dir):
    res = lldb.SBCommandReturnObject()
    interpreter = lldb.debugger.GetCommandInterpreter()
    cmd = 'memory read --force --outfile {}/{}/{} --binary --count {} {}' \
        .format(output_dir, module_name, name, size, addr)
    interpreter.HandleCommand(cmd, res)

    return {"offset": file_offset, "name": name}


def dump_module_with_info(header_addr, header_size, module_info, module_name, slide, output_dir):
    module_name = module_name.replace(' ', '_')
    module_name = module_name.replace('.', '_')

    module_regions = module_info['lcs']
    module_size = 0

    module_dir = '{}/{}'.format(output_dir, module_name)
    util.try_mkdir(module_dir)

    module_info_write_to_file(module_info, module_name, module_dir)

    outputs = []

    # dump macho header
    info = dump_region(module_name, header_addr, header_size, 'header', 0, output_dir)
    outputs.append(info)

    for idx, region_info in enumerate(module_regions):
        cmd = region_info['cmd']
        if cmd != "19":  # LC_SEGMENT_64
            continue

        if region_info['name'] == "__PAGEZERO":
            continue

        # print('{} {}'.format(idx, region_info))
        sections = region_info.get("sects")
        if sections and len(sections):
            for section in sections:
                info = dump_section(module_name, slide, section, output_dir)
                outputs.append(info)
        else:
            info = dump_segment(module_name, slide, region_info, output_dir)
            outputs.append(info)
        module_size += int(region_info['segsize'], 16)

    output_path = module_dir + '/macho_' + module_name
    with open(output_path, 'wb+') as x_file:
        header_done = False
        for info in outputs:
            name = info['name']
            offset = info['offset']
            if offset == 0:
                if header_done:
                    print('ignore {}'.format(name))
                    continue
                else:
                    header_done = True

            x_file.seek(offset)
            region_file_path = module_dir + '/' + name
            with open(region_file_path, 'rb') as region_file:
                x_file.write(region_file.read())
                x_file.flush()

                region_file.close()

        x_file.close()

    return '{} bytes dump to {}'.format(module_size, output_path)


def module_info_write_to_file(module_info, module_name, module_dir):
    json_file_path = module_dir + '/' + module_name + '.json'
    json_fp = open(json_file_path, 'w')
    json.dump(module_info, json_fp, indent=2)
    json_fp.close()


def generate_option_parser(prog):
    usage = "usage: %prog ModuleName\n"

    parser = optparse.OptionParser(usage=usage, prog=prog)

    return parser
