# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import util
import os
import MachO
import json
import math
from DumpSegments import flags_str_from_value


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "dump segments of the specified module" -f '
        'LoadCommands.dump_load_commands lcs')

    debugger.HandleCommand(
        'command script add -h "dump segments of the specified module" -f '
        'LoadCommands.dump_shared_libs libs')


def dump_load_commands(debugger, command, result, internal_dict):
    """
    dump load commands of the specified module
    implemented in YJLLDB/src/LoadCommands.py
    """
    handle_command(debugger, command, result, 'lcs')


def dump_shared_libs(debugger, command, result, internal_dict):
    """
    dump shared libs of the specified module
    implemented in YJLLDB/src/LoadCommands.py
    """
    handle_command(debugger, command, result, 'libs')


def handle_command(debugger, command, result, prog):
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command_args = shlex.split(command, posix=False)
    # 创建parser
    parser = generate_option_parser(prog)
    # 解析参数，捕获异常
    try:
        # options是所有的选项，key-value形式，args是其余剩余所有参数，不包含options
        (options, args) = parser.parse_args(command_args)
    except Exception as error:
        print(error)
        result.SetError("\n" + parser.get_usage())
        return

    target = debugger.GetSelectedTarget()

    is_address = False
    addr_str = None
    lookup_module_name = None
    if len(args) == 1:
        is_address, name_or_addr = util.parse_arg(args[0])
        if is_address:
            addr_str = name_or_addr
        else:
            lookup_module_name = name_or_addr
    else:
        file_spec = target.GetExecutable()
        lookup_module_name = file_spec.GetFilename()
        full_path = str(file_spec)
        debug_dylib = full_path + '.debug.dylib'
        if os.path.exists(debug_dylib):
            lookup_module_name += '.debug.dylib'

    header_addr = 0
    header_data = None
    if is_address:
        header_addr = int(addr_str, 16)
        header_size = 0x4000

        error = lldb.SBError()
        header_data = target.ReadMemory(lldb.SBAddress(header_addr, target), header_size, error)
        if not error.Success():
            result.AppendMessage('read header failed! {}'.format(error.GetCString()))
            return
    else:
        bundle_path = target.GetExecutable().GetDirectory()
        for module in target.module_iter():
            module_file_spec = module.GetFileSpec()
            module_dir = module_file_spec.GetDirectory()
            module_name = module_file_spec.GetFilename()

            if len(lookup_module_name):
                lib_name = lookup_module_name + '.dylib'
                if lookup_module_name != module_name and lib_name != module_name:
                    continue
            else:
                if bundle_path not in module_dir:
                    continue

            print("-----parsing module %s-----" % module_name)
            seg = module.FindSection('__TEXT')
            if not seg:
                result.AppendMessage('seg __TEXT not found')
                continue

            header_addr = seg.GetLoadAddress(target)
            first_sec = seg.GetSubSectionAtIndex(0)
            sec_addr = first_sec.GetLoadAddress(target)

            error = lldb.SBError()
            header_size = sec_addr - header_addr
            header_data = target.ReadMemory(lldb.SBAddress(header_addr, target), header_size, error)
            if not error.Success():
                result.AppendMessage('read header failed! {}'.format(error.GetCString()))
                continue

    info = MachO.parse_header(header_data, False)
    # print(json.dumps(info, indent=2))

    slide = header_addr - int(info['text_vmaddr'], 16)
    lcs = info['lcs']
    lcs_len = len(lcs)
    width = len(str(lcs_len))
    lcs_info = ''
    LC_REQ_DYLD = 0x80000000
    if prog == 'lcs':
        for idx, lc in enumerate(lcs):
            cmd = int(lc['cmd'], 16)
            if cmd == 0x1 or cmd == 0x19:  # LC_SEGMENT_64
                seg_start = slide + int(lc['vmaddr'], 16)
                seg_size = int(lc['vmsize'], 16)
                seg_end = seg_start + seg_size
                seg_name = lc['name']

                lcs_info += ('LC {:0{width}d}: LC_SEGMENT_64\t\tMem: {:#011x}-{:#011x}\t{}\n'.
                            format(idx, seg_start, seg_end, seg_name, width=width))

                sects = lc['sects']
                for sect in sects:
                    sec_name = sect['name']
                    sec_start = slide + int(sect['addr'], 16)
                    sec_size = int(sect['size'], 16)
                    sec_end = sec_start + sec_size
                    sec_flags = flags_str_from_value(int(sect['flags'], 16))

                    name_len = len(sec_name)
                    num = math.floor(name_len / 4)
                    lcs_info += '\tMem: {:#09x}-{:#09x}\t\t{}{}{}\n'. \
                        format(sec_start, sec_end, sec_name, '\t' * (5 - num), sec_flags[:-1])
            elif cmd == 0x2:
                lcs_info += 'LC {:0{width}d}: LC_SYMTAB\n'.format(idx, width=width)

                symoff = lc['symoff']
                nsyms = lc['nsyms']
                stroff = lc['stroff']
                strsize = lc['strsize']

                lcs_info += '\tSymbol table is at offset {:#x} ({}), 274 entries\n'.format(symoff, symoff, nsyms)
                lcs_info += '\tString table is at offset {:#x} ({}), 7440 bytes\n'.format(stroff, stroff, strsize)
            elif cmd == 0x5:
                lcs_info += 'LC {:0{width}d}: LC_UNIXTHREAD\n'.format(idx, width=width)
            elif cmd == 0xb:
                lcs_info += 'LC {:0{width}d}: LC_SYMTAB\n'.format(idx, width=width)

                ilocalsym = lc['ilocalsym']
                nlocalsym = lc['nlocalsym']
                if nlocalsym > 0:
                    lcs_info += '\t{} local symbols at index {}\n'.format(nlocalsym, ilocalsym)
                else:
                    lcs_info += '\tNo local symbols\n'

                iextdefsym = lc['iextdefsym']
                nextdefsym = lc['nextdefsym']
                if nextdefsym > 0:
                    lcs_info += '\t{} external symbols at index {}\n'.format(nextdefsym, iextdefsym)
                else:
                    lcs_info += '\tNo external symbols\n'

                iundefsym = lc['iundefsym']
                nundefsym = lc['nundefsym']
                if nundefsym > 0:
                    lcs_info += '\t{} undefined symbols at index {}\n'.format(nundefsym, iundefsym)
                else:
                    lcs_info += '\tNo undefined symbols\n'

                tocoff = lc['tocoff']
                ntoc = lc['ntoc']
                if ntoc > 0:
                    lcs_info += '\t{} TOC at offset {:#x}\n'.format(ntoc, tocoff)
                else:
                    lcs_info += '\tNo TOC\n'

                modtaboff = lc['modtaboff']
                nmodtab = lc['nmodtab']
                if nmodtab > 0:
                    lcs_info += '\t{} module table at offset {:#x}\n'.format(nmodtab, modtaboff)
                else:
                    lcs_info += '\tNo modtab\n'

                indirectsymoff = lc['indirectsymoff']
                nindirectsyms = lc['nindirectsyms']
                if nindirectsyms:
                    lcs_info += '\t{} indirect symbols at offset {:#x}\n'.format(nindirectsyms, indirectsymoff)
                else:
                    lcs_info += '\tNo indirect symbols\n'
            elif cmd == 0xc:
                lcs_info += 'LC {:0{width}d}: LC_LOAD_DYLIB\t\t\t{}\n'.format(idx, lc['name'], width=width)
            elif cmd == 0xd:
                lcs_info += 'LC {:0{width}d}: LC_ID_DYLIB\t\t\t\t{}\n'.format(idx, lc['name'], width=width)
            elif cmd == 0xe:
                lcs_info += 'LC {:0{width}d}: LC_LOAD_DYLINKER\t\t\t{}\n'.format(idx, lc['name'], width=width)
            elif cmd == 0xf:
                lcs_info += 'LC {:0{width}d}: LC_ID_DYLINKER\t\t\t{}\n'.format(idx, lc['name'], width=width)
            elif cmd == 0x18 | LC_REQ_DYLD:
                lcs_info += 'LC {:0{width}d}: LC_LOAD_WEAK_DYLIB\t\t{}\n'.format(idx, lc['name'], width=width)
            elif cmd == 0x1b:
                lcs_info += 'LC {:0{width}d}: LC_UUID\t\t\t\t\tUUID: {}\n'.format(idx, lc['uuid'], width=width)
            elif cmd == 0x1c | LC_REQ_DYLD:
                lcs_info += 'LC {:0{width}d}: LC_RPATH\t\t\t\t\t{}\n'.format(idx, lc['name'], width=width)
            elif cmd == 0x1d:
                lcs_info += ('LC {:0{width}d}: LC_CODE_SIGNATURE\t\tOffset: {} Size: {}\n'.
                             format(idx, int(lc['dataoff'], 16), int(lc['datasize'], 16), width=width))
            elif cmd == 0x22 or cmd == 0x22 | LC_REQ_DYLD:
                lcs_info += 'LC {:0{width}d}: LC_DYLD_INFO\n'.format(idx, width=width)
            elif cmd == 0x24:
                lcs_info += ('LC {:0{width}d}: LC_VERSION_MIN_MACOSX\tMinimum MacOSX version: {}\n'.
                             format(idx, lc['version'], width=width))
            elif cmd == 0x25:
                lcs_info += ('LC {:0{width}d}: LC_VERSION_MIN_IPHONEOS\tMinimum iOS version: {}\n'.
                             format(idx, lc['version'], width=width))
            elif cmd == 0x26:
                lcs_info += ('LC {:0{width}d}: LC_FUNCTION_STARTS\t\tOffset: {} Size: {}\n'.
                             format(idx, int(lc['dataoff'], 16), int(lc['datasize'], 16), width=width))
            elif cmd == 0x28 | LC_REQ_DYLD:
                lcs_info += ('LC {:0{width}d}: LC_MAIN\t\t\t\t\tEntry Point: 0x{}\n'.
                             format(idx, lc['entryoff'], width=width))
            elif cmd == 0x29:
                lcs_info += ('LC {:0{width}d}: LC_DATA_IN_CODE\t\t\tOffset: {} Size: {}\n'.
                             format(idx, int(lc['dataoff'], 16), int(lc['datasize'], 16), width=width))
            elif cmd == 0x2a:
                lcs_info += ('LC {:0{width}d}: LC_SOURCE_VERSION\t\tSource Version: {}\n'.
                             format(idx, lc['version'], width=width))
            elif cmd == 0x2c:
                lcs_info += ('LC {:0{width}d}: LC_ENCRYPTION_INFO_64\tEncryption: {} from offset {} spanning {} bytes\n'.
                             format(idx, lc['cryptid'], int(lc['cryptoff'], 16), int(lc['cryptsize'], 16), width=width))
            elif cmd == 0x2f:
                lcs_info += ('LC {:0{width}d}: LC_VERSION_MIN_TVOS\tMinimum TVOS version: {}\n'.
                             format(idx, lc['version'], width=width))
            elif cmd == 0x30:
                lcs_info += ('LC {:0{width}d}: LC_VERSION_MIN_WATCHOS\tMinimum watchOS version: {}\n'.
                             format(idx, lc['version'], width=width))
            elif cmd == 0x32:
                lcs_info += ('LC {:0{width}d}: LC_BUILD_VERSION\t\t\tPlatform: {} min OS: {}\n'.
                             format(idx, lc['platform'], lc['minos'], width=width))
            elif cmd == 0x33 | LC_REQ_DYLD:
                lcs_info += ('LC {:0{width}d}: LC_DYLD_EXPORTS_TRIE\t\tOffset: {} Size: {}\n'.
                             format(idx, int(lc['dataoff'], 16), int(lc['datasize'], 16), width=width))
            elif cmd == 0x34 | LC_REQ_DYLD:
                lcs_info += ('LC {:0{width}d}: LC_DYLD_CHAINED_FIXUPS\tOffset: {} Size: {}\n'.
                             format(idx, int(lc['dataoff'], 16), int(lc['datasize'], 16), width=width))

    elif prog == 'libs':
        for idx, lc in enumerate(lcs):
            cmd = int(lc['cmd'], 16)

            if cmd == 0xc:
                lcs_info += '{}\n'.format(lc['name'])
            if cmd == 0x18 | LC_REQ_DYLD:
                    lcs_info += '{}\n'.format(lc['name'])

        pass

    print(lcs_info)


def generate_option_parser(prog):
    usage = "usage: %prog [muodule name or header address]\n"

    parser = optparse.OptionParser(usage=usage, prog=prog)

    return parser
