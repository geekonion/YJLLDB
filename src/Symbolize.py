# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import os
import json
import util
import re
import LoadDSYM

g_last_exception_place_holder = '$Last Exception$'
g_thread_list_place_holder = '$thread list$'
g_max_name_width = 0
g_registers = {
    'x': ['x0', 'x1', 'x2', 'x3',
          'x4', 'x5', 'x6', 'x7',
          'x8', 'x9', 'x10', 'x11',
          'x12', 'x13', 'x14', 'x15',
          'x16', 'x17', 'x18', 'x19',
          'x20', 'x21', 'x22', 'x23',
          'x24', 'x25', 'x26', 'x27',
          'x28'],
    'r': ['r0', 'r1']
}

# runtime modules
g_uuid_loadAddr_map = {}
# modules in crash report
g_module_name_uuid_map = {}
g_crash_uuid_map = {}
g_dsym_dir = None


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "symbolize address, uncaught exception addresses list or crash report file" -f '
        'Symbolize.do_symbolize symbolize')


def do_symbolize(debugger, command, result, internal_dict):
    """
    symbolize uncaught exception addresses list
    implemented in YJLLDB/src/Symbolize.py
    """
    # 去掉转义符
    command = command.replace('\\', '\\\\')
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command = command.replace("(", "")
    command = command.replace(")", "")
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

    n_args = len(args)
    if n_args == 1:
        arg = args[0].replace('"', '').replace("'", '')
        if arg.startswith('0x'):
            addr = int(arg, 16)
            code, module_name, name_or_addr, offset = symbolize_addr(addr)
            if code == 0:
                result.AppendMessage('{:#x}: {}`{} + {}'.format(addr, module_name, name_or_addr, offset))
            else:
                result.AppendMessage('symbol not found')
        elif arg.isdigit():
            addr = int(arg)
            code, module_name, name_or_addr, offset = symbolize_addr(addr)
            if code == 0:
                result.AppendMessage('{:#x}: {}`{} + {}'.format(addr, module_name, name_or_addr, offset))
            else:
                result.AppendMessage('symbol not found')
        elif arg.endswith('.ips') or arg.endswith('.crash'):
            if options.dsym:
                global g_dsym_dir
                g_dsym_dir = options.dsym
            symbolize_crash_report(debugger, result, arg)
        else:
            result.AppendMessage('unknown argument')
    else:
        symbolize_uncaught_exception(debugger, result, args)


def symbolize_uncaught_exception(debugger, result, args):
    target = debugger.GetSelectedTarget()
    main_module = target.GetModuleAtIndex(0)

    backtrace = ""
    addresses = [int(x, 16) for x in args]
    for index, addr in enumerate(addresses):
        addr_obj = target.ResolveLoadAddress(addr)
        symbol = addr_obj.GetSymbol()

        module = addr_obj.GetModule()
        module_name = "unknown"
        if module:
            module_file_spec = module.GetFileSpec()
            module_name = module_file_spec.GetFilename()

        if main_module.__eq__(module):
            line_entry = addr_obj.GetLineEntry()
            file_spec = line_entry.GetFileSpec()
            file_name = file_spec.GetFilename()
            offset = "at {}:{}:{}".format(file_name, line_entry.GetLine(), line_entry.GetColumn())
        else:
            offset = addr - symbol.GetStartAddress().GetLoadAddress(target)

        symbol_str = "frame #{}: {:#x} {}`{} + {}\n".format(index, addr, module_name, symbol.GetName(), offset)
        backtrace += symbol_str

    result.AppendMessage("backtrace: \n{}".format(backtrace))


def symbolize_crash_report(debugger, result, file_path):
    if not os.path.exists(file_path):
        print('No such file: {}'.format(file_path))
        return

    target = debugger.GetSelectedTarget()
    global g_uuid_loadAddr_map
    for module in target.module_iter():
        uuid = module.GetUUIDString().upper().replace('-', '')
        header_addr = module.GetObjectFileHeaderAddress().GetLoadAddress(target)
        g_uuid_loadAddr_map[uuid] = header_addr

    if file_path.endswith('.ips'):
        final_report = symbolize_ips_file(file_path)
        result.AppendMessage(final_report)
    elif file_path.endswith('.crash'):
        final_report = symbolize_crash_file(file_path)
        result.AppendMessage(final_report)


def symbolize_ips_file(file_path):
    with open(file_path, 'r') as report_file:
        header_line = report_file.readline()
        if not header_line.startswith('{'):
            final_report = 'not supported yet'
            report_file.close()

            return final_report

        # header_dict = json.loads(header_line)
        # print(json.dumps(header_dict, indent=2))

        data_str = report_file.read().replace(header_line + '\n', '')
        report_file.close()

    if data_str.startswith('{'):
        is_json = True
    else:
        is_json = False

    if is_json:
        data_dict = json.loads(data_str)

        used_images = data_dict.get('usedImages')
        max_width = 0
        for image_dict in used_images:
            image_name = image_dict.get('name')
            if not image_name:
                continue
            name_len = len(image_name)
            if name_len > max_width:
                max_width = name_len

        final_report = ''
        image_list = build_images(data_dict)
        report_header, last_exception = build_header(data_dict, used_images, max_width)

        last_exception_obj = None
        if last_exception:
            last_exception_obj = build_last_exception(last_exception, used_images, max_width)

        thread_list = build_threads(data_dict, used_images, max_width)

        # 尝试加载符号文件
        if g_dsym_dir:
            dsym_dir = g_dsym_dir
        else:
            dsym_dir = os.path.dirname(file_path)
        LoadDSYM.try_load_dsym_file_in_dir(dsym_dir, g_crash_uuid_map)

        symbolize_thread_list(last_exception_obj, thread_list)

        if last_exception:
            report_header = report_header.replace(g_last_exception_place_holder, last_exception_obj.description())

        final_report += report_header
        for thread in thread_list:
            final_report += ' \n{}'.format(thread.description())

        final_report += build_thread_state(data_dict)
        final_report += image_list
        final_report += build_vm_summary(data_dict)
        final_report += build_report_notes(data_dict)

        final_report += ' \nEOF\n'
    else:
        final_report = 'not supported yet'

    return final_report


def build_header(data_dict, used_images, max_width):
    report_header = """
-------------------------------------
Translated Report (Full Report Below)
-------------------------------------
"""
    report_header += ' \n'
    report_header += 'Incident Identifier: {}\n'.format(data_dict.get('incident'))
    crash_reporterKey = data_dict.get('crashReporterKey')
    if crash_reporterKey:
        report_header += 'CrashReporter Key:   {}\n'.format(crash_reporterKey)
    report_header += 'Hardware Model:      {}\n'.format(data_dict.get('modelCode'))
    report_header += 'Process:             {} [{}]\n'.format(data_dict.get('procName'), data_dict.get('pid'))
    report_header += 'Path:                {}\n'.format(data_dict.get('procPath'))

    bundleInfo = data_dict.get('bundleInfo')
    if bundleInfo:
        report_header += 'Identifier:          {}\n'.format(bundleInfo.get('CFBundleIdentifier'))
        report_header += 'Version:             {} ({})\n'. \
            format(bundleInfo.get('CFBundleShortVersionString'), bundleInfo.get('CFBundleVersion'))

        DTAppStoreToolsBuild = bundleInfo.get('DTAppStoreToolsBuild')
        if DTAppStoreToolsBuild:
            report_header += 'AppStoreTools:       {}\n'.format(DTAppStoreToolsBuild)

    storeInfo = data_dict.get('storeInfo')
    if storeInfo:
        applicationVariant = storeInfo.get('applicationVariant')
        if applicationVariant:
            report_header += 'AppVariant:          {}\n'.format(applicationVariant)
        entitledBeta = storeInfo.get('entitledBeta')
        if entitledBeta is not None:
            report_header += 'Beta:                {}\n'.format('YES' if entitledBeta else 'NO')

    translated = data_dict.get('translated')
    code_des = 'Native'
    if translated == 'false':
        code_des = 'Translated'
    report_header += 'Code Type:           {} ({})\n'.format(data_dict.get('cpuType'), code_des)
    report_header += 'Role:                {}\n'.format(data_dict.get('procRole'))
    report_header += 'Parent Process:      {} [{}]\n'.format(data_dict.get('parentProc'), data_dict.get('parentPid'))
    report_header += 'Coalition:           {} [{}]\n'. \
        format(data_dict.get('coalitionName'), data_dict.get('coalitionID'))
    report_header += ' \n'
    report_header += 'Date/Time:           {}\n'.format(data_dict.get('captureTime'))
    report_header += 'Launch Time:         {}\n'.format(data_dict.get('procLaunch'))

    osVersion = data_dict.get('osVersion')
    if osVersion:
        report_header += 'OS Version:          {} ({})\n'. \
            format(osVersion.get('train'), osVersion.get('build'))
        report_header += 'Release Type:        {}\n'.format(osVersion.get('releaseType'))

    basebandVersion = data_dict.get('basebandVersion')
    if basebandVersion:
        report_header += 'Baseband Version:    {}\n'.format(basebandVersion)
    report_header += 'Report Version:      {}\n'.format(data_dict.get(''))

    report_header += ' \n'

    exception = data_dict.get('exception')
    if exception:
        report_header += 'Exception Type:  {} ({})\n'. \
            format(exception.get('type'), exception.get('signal'))
        subtype = exception.get('subtype')
        if subtype:
            report_header += 'Exception Subtype: {}\n'.format(subtype)
        report_header += 'Exception Codes: {}\n'.format(exception.get('codes'))

    vm_region_info = data_dict.get('vmRegionInfo')
    if not vm_region_info:
        vm_region_info = data_dict.get('vmregioninfo')
    if vm_region_info:
        report_header += 'VM Region Info: {}\n'.format(vm_region_info)

    termination = data_dict.get('termination')
    if termination:
        indicator = termination.get('indicator')
        if indicator:
            indicator_str = ' {}'.format(indicator)
        else:
            indicator_str = ''
        report_header += 'Termination Reason: {} {} {}\n'. \
            format(termination.get('namespace'), termination.get('code'), indicator_str)

        reasons = termination.get('reasons')
        if reasons:
            report_header += '{}\n'.format(reasons)

        proc = termination.get('byProc')
        if proc:
            report_header += 'Terminating Process: {} [{}]\n'.format(proc, termination.get('byPid'))

    report_header += ' \n'
    report_header += 'Triggered by Thread:  {}\n'.format(data_dict.get('faultingThread'))

    asi = data_dict.get('asi')
    if asi:
        report_header += ' \n'
        report_header += 'Application Specific Information:\n'
        for key in asi:
            message = '\n'.join(asi[key])
            report_header += '{}\n'.format(message)

    last_exception = data_dict.get('lastExceptionBacktrace')
    if last_exception:
        report_header += ' \n{}'.format(g_last_exception_place_holder)

    kernel_triage = data_dict.get('ktriageinfo')
    if kernel_triage:
        report_header += ' \n'
        report_header += 'Kernel Triage:\n{}\n'.format(kernel_triage)

    return report_header, last_exception


def build_last_exception(last_exception, used_images, max_width):
    thread_obj = Thread()
    thread_obj.title = 'Last Exception Backtrace:\n'
    thread_obj.frames = build_backtrace(last_exception, used_images, max_width)

    return thread_obj


def build_backtrace(frames, used_images, max_width):
    frame_list = []
    idx = 0
    for frame in frames:
        image_offset = frame.get('imageOffset')
        symbol = frame.get('symbol')
        imageIndex = frame.get('imageIndex')
        image_dict = used_images[imageIndex]
        image_name = image_dict.get('name')
        image_base = image_dict.get('base')

        func_addr = image_base + image_offset

        frame_obj = Frame()
        frame_obj.idx = idx
        frame_obj.image_name = image_name
        frame_obj.max_width = max_width
        frame_obj.load_addr = func_addr
        frame_obj.base = image_base
        frame_obj.file_offset = image_offset
        if symbol:
            frame_obj.symbol_name = symbol
            frame_obj.symbol_offset = frame.get('symbolLocation')

        frame_list.append(frame_obj)

        idx += 1

    return frame_list


def build_threads(data_dict, used_images, max_width):
    threads = data_dict.get('threads')

    thread_list = []
    thread_idx = 0
    for thread in threads:
        thread_obj = build_thread(thread, thread_idx, used_images, max_width)
        thread_list.append(thread_obj)
        del thread_obj

        thread_idx += 1

    return thread_list


def build_thread(thread_dict, thread_idx, used_images, max_width):
    thread_title = ''
    triggered = thread_dict.get('triggered')
    queue = thread_dict.get('queue')
    name = thread_dict.get('name')

    if queue:
        if not name:
            name = ''
        thread_title += 'Thread {} name: {} Dispatch queue: {}\n'.format(thread_idx, name, queue)
    elif name:
        thread_title += 'Thread {} name: {}\n'.format(thread_idx, name, queue)

    trigger_flag = ''
    if triggered:
        trigger_flag = ' Crashed'
    thread_title += 'Thread {}{}:\n'.format(thread_idx, trigger_flag)

    thread_obj = Thread()
    thread_obj.title = thread_title
    frames = thread_dict.get('frames')
    thread_obj.frames = build_backtrace(frames, used_images, max_width)

    return thread_obj


def build_thread_state(data_dict):
    index = data_dict.get('faultingThread')
    threads = data_dict.get('threads')
    thread = threads[index]
    thread_state = thread.get('threadState')

    flavor = thread_state.get('flavor')
    if flavor == 'ARM_THREAD_STATE64':
        flavor_str = 'ARM Thread State (64-bit)'
    else:
        flavor_str = flavor

    thread_state_str = ' \n'
    thread_state_str += 'Thread {} crashed with {}:\n  '.format(index, flavor_str)
    registers = thread_state.get('x')
    if registers:
        reg_idx = 0
        for reg in registers:
            reg_name = g_registers['x'][reg_idx]
            if reg_idx > 0 and reg_idx % 4 == 0:
                thread_state_str += '\n  {:>3}: {:#018x}  '.format(reg_name, reg.get('value'))
            else:
                thread_state_str += '{:>3}: {:#018x}  '.format(reg_name, reg.get('value'))

            reg_idx += 1

    reg_fp = thread_state.get('fp').get('value')
    reg_lr = thread_state.get('lr').get('value')
    reg_sp = thread_state.get('sp').get('value')
    reg_pc = thread_state.get('pc').get('value')
    reg_cpsr = thread_state.get('cpsr').get('value')
    reg_far = thread_state.get('far').get('value')
    esr_dict = thread_state.get('esr')
    reg_esr = esr_dict.get('value')
    esr_des = esr_dict.get('description')
    thread_state_str += ' fp: {:#018x}   lr: {:#018x}\n'.format(reg_fp, reg_lr)
    thread_state_str += '   sp: {:#018x}   pc: {:#018x} cpsr: {:#x}\n'.format(reg_sp, reg_pc, reg_cpsr)
    thread_state_str += '  far: {:#018x}  esr: {:#x} {}\n'.format(reg_far, reg_esr, esr_des)

    return thread_state_str


def build_images(data_dict):
    used_images = data_dict.get('usedImages')
    images = sorted(used_images, key=lambda image_dict: image_dict.get('base'))

    image_list = ' \n'
    image_list += 'Binary Images:\n'

    global g_crash_uuid_map, g_module_name_uuid_map
    for image in images:
        base = image.get('base')
        size = image.get('size')
        if size > 0:
            end = base + size - 1
        else:
            end = base + size
        arch = image.get('arch')
        uuid = image.get('uuid').upper()
        path = image.get('path')
        name = image.get('name')
        image_list += '\t{:#x} - {:#x} {} {} <{}> {}\n'.format(base, end, name, arch, uuid, path)

        global g_crash_uuid_map, g_module_name_uuid_map
        g_crash_uuid_map[uuid] = True
        g_module_name_uuid_map[name] = uuid.replace('-', '')

    image_list += ' \n'
    image_list += ' \n'
    image_list += 'sharedCache:\n'
    sharedCache = data_dict.get('sharedCache')
    base = sharedCache.get('base')
    size = sharedCache.get('size')
    if size > 0:
        end = base + size - 1
    else:
        end = base + size
    uuid = sharedCache.get('uuid').upper()
    image_list += '{:#x} - {:#x} <{}>\n'.format(base, end, uuid)

    return image_list


def build_vm_summary(data_dict):
    vm_des = ' \n'
    vmSummary = data_dict.get('vmSummary')
    if not vmSummary:
        return ''

    vm_des += vmSummary

    return vm_des


def build_report_notes(data_dict):
    report_notes_str = ' \n'
    report_notes_str += 'Error Formulating Crash Report:\n'
    report_notes = data_dict.get('reportNotes')
    if not report_notes:
        return ''
    for report_note in report_notes:
        report_notes_str += '{}\n'.format(report_note)

    return report_notes_str


def symbolize_crash_file(file_path):
    with open(file_path, 'r') as report_file:
        content = report_file.read()
        report_file.close()

    lines = content.split('\n')

    thread_list = []

    in_last_exception = False
    last_exception = None
    in_thread = False
    thread_obj = None
    thread_title = ''
    frames = None

    in_image_list = False

    final_lines = []
    for line in lines:
        if line == 'Last Exception Backtrace:':
            in_last_exception = True
            last_exception = Thread()
            last_exception.title = 'Last Exception Backtrace:\n'
            frames = []
            continue
        elif line.startswith('Thread '):
            if line.find('Thread State') > 0:
                final_lines.append(g_thread_list_place_holder)
                thread_title += '{}\n'.format(line)
            elif line.endswith(':'):
                in_thread = True
                thread_obj = Thread()
                thread_title += '{}\n'.format(line)
                thread_obj.title = thread_title
                thread_title = ''
                frames = []
                continue
            else:
                thread_title += '{}\n'.format(line)
                continue
        elif line.startswith('Binary Images:'):
            in_image_list = True
            continue

        if in_last_exception:
            if len(line) == 0:
                in_last_exception = False
                last_exception.frames = frames
                frames = None
                final_lines.append(g_last_exception_place_holder)
            else:
                frame_obj = parse_frame_line(line)
                frames.append(frame_obj)

            continue
        elif in_thread:
            if len(line) == 0:
                in_thread = False
                thread_obj.frames = frames
                frames = None
                thread_list.append(thread_obj)
                thread_obj = None
            else:
                frame_obj = parse_frame_line(line)
                frames.append(frame_obj)

            continue
        elif in_image_list:
            if len(line) == 0:
                in_image_list = False
            else:
                parse_image_line(line)

        if line == '\n' or len(line) == 0:
            final_lines.append(' \n')
        else:
            final_lines.append(line)

    final_report = '\n'.join(final_lines)

    # 尝试加载符号文件
    if g_dsym_dir:
        dsym_dir = g_dsym_dir
    else:
        dsym_dir = os.path.dirname(file_path)
    LoadDSYM.try_load_dsym_file_in_dir(dsym_dir, g_crash_uuid_map)

    symbolize_thread_list(last_exception, thread_list)

    if last_exception:
        final_report = final_report.replace(g_last_exception_place_holder, last_exception.description())

    thread_list_str = ''
    for thread in thread_list:
        thread_list_str += '{} \n'.format(thread.description())

    final_report = final_report.replace(g_thread_list_place_holder, thread_list_str)

    return final_report


def replace_multiple_spaces(text):
    return re.sub(r'\s+', ' ', text)


def parse_frame_line(frame_line):
    # 4 Foundation 0x1b2ac88a8 -[NSObject(NSThreadPerformAdditions) performSelector:onThread:withObject:waitUntilDone:modes:] + 916

    frame_line = replace_multiple_spaces(frame_line)
    pos1 = frame_line.find(' ')
    frame_idx = frame_line[:pos1]
    pos2 = frame_line.find(' 0x', pos1 + 1)
    image_name = frame_line[pos1 + 1: pos2]
    pos3 = frame_line.find(' ', pos2 + 3)
    load_addr = frame_line[pos2 + 1: pos3]
    pos4 = frame_line.find(' + ', pos3 + 1)
    name_or_addr = frame_line[pos3 + 1: pos4]
    offset = frame_line[pos4 + 3:]

    global g_max_name_width
    n_name = len(image_name)
    if n_name > g_max_name_width:
        g_max_name_width = n_name

    frame_obj = Frame()
    frame_obj.idx = int(frame_idx)
    frame_obj.image_name = image_name
    frame_obj.load_addr = int(load_addr, 16)
    if name_or_addr.startswith('0x'):
        frame_obj.base = int(name_or_addr, 16)
        frame_obj.file_offset = int(offset)
    else:
        frame_obj.symbol_name = name_or_addr
        frame_obj.symbol_offset = int(offset)

    return frame_obj


def parse_image_line(image_line):
    # 0x104c9c000 - 0x104d1bfff dyld arm64 <444f50414d494e45444f50414d494e45> /usr/lib/dyld
    image_line = replace_multiple_spaces(image_line)
    pos1 = image_line.find(' - 0x')
    pos2 = image_line.find(' ', pos1 + 4)
    pos3 = image_line.find(' ', pos2 + 1)
    image_name = image_line[pos2 + 1: pos3]
    pos4 = image_line.find('<', pos3)
    pos5 = image_line.find('>', pos4)
    uuid = image_line[pos4 + 1: pos5].upper()

    global g_crash_uuid_map, g_module_name_uuid_map
    g_crash_uuid_map[uuid] = True
    g_module_name_uuid_map[image_name] = uuid.replace('-', '')


def symbolize_thread_list(last_exception_obj, thread_list):
    func_map = {}
    frame_map = {}
    module_map = {}

    debugger = lldb.debugger
    target = debugger.GetSelectedTarget()

    target_frames = []
    if last_exception_obj:
        frames = last_exception_obj.frames
        target_frames.extend(frames)

    for thread in thread_list:
        target_frames.extend(thread.frames)

    file_spec = target.GetExecutable()
    module = target.FindModule(file_spec)
    main_addr = module.GetObjectFileEntryPointAddress().GetLoadAddress(target)

    for frame in target_frames:
        if frame.symbol_name:
            continue

        image_name = frame.image_name
        uuid = g_module_name_uuid_map[image_name]
        header_addr = g_uuid_loadAddr_map.get(uuid)
        if header_addr and header_addr > 0:
            addr_list = func_map.get(image_name)
            if not addr_list:
                addr_list = []
                func_map[image_name] = addr_list

            load_addr = header_addr + frame.file_offset

            addr_obj = lldb.SBAddress(load_addr, target)
            symbol = addr_obj.GetSymbol()
            symbol_start = symbol.GetStartAddress().GetLoadAddress(target)
            symbol_name = symbol.name
            if symbol_start == main_addr:
                frame.symbol_name = 'main'
            elif symbol_name.find('unnamed_symbol') == -1:
                frame.symbol_name = symbol_name
            else:
                addr_list.append(symbol_start)
                frame_map[str(symbol_start)] = frame
                module_map[image_name] = str(addr_obj.module.file)

            frame.symbol_offset = load_addr - symbol_start

    for image_name in func_map:
        addr_list = func_map[image_name]
        if len(addr_list) == 0:
            continue

        command_script = find_addresses_in_module(addr_list, module_map[image_name])
        method_json_str = util.exe_script(command_script)

        methods_info = None
        # 空json的最小长度为2，即只包含一对括号
        if len(method_json_str) > 2:
            methods_info = json.loads(method_json_str)

        if methods_info:
            for key in methods_info:
                frame = frame_map[key]
                frame.symbol_name = methods_info[key]


def symbolize_addr(addr):
    debugger = lldb.debugger
    target = debugger.GetSelectedTarget()

    addr_obj = lldb.SBAddress(addr, target)
    symbol = addr_obj.GetSymbol()

    code = -1
    name_or_addr = None
    offset = 0
    if not symbol:
        return code, None, name_or_addr, offset

    symbol_start = symbol.GetStartAddress().GetLoadAddress(target)
    symbol_name = symbol.name
    module = addr_obj.module
    module_path = str(module.file)
    module_name = os.path.basename(module_path)

    # 有符号
    if symbol_name.find('unnamed_symbol') == -1:
        code = 0
        name_or_addr = symbol_name
    # 无符号
    else:
        methods_info = None
        command_script = find_addresses_in_module([symbol_start], module_path)
        method_json_str = util.exe_script(command_script)
        # 空json的最小长度为2，即只包含一对括号
        if len(method_json_str) > 2:
            methods_info = json.loads(method_json_str)

        if methods_info:
            code = 0
            name_or_addr = methods_info[str(symbol_start)]

    offset = addr - symbol_start

    return code, module_name, name_or_addr, offset


def find_addresses_in_module(addr_list, module_path):
    command_script = '@import ObjectiveC;\n@import Foundation;\n'
    command_script += 'NSArray *methods_list = @[\n'
    for addr in addr_list:
        command_script += '\t@(' + str(addr) + '),\n'
    command_script += '];\n'
    command_script += 'NSString *module_path = @"' + str(module_path) + '";'

    command_script += r'''
    
    NSMutableArray *addr_list = [NSMutableArray arrayWithArray:methods_list];
    
    unsigned int n_classes = 0;
    const char **allClasses = (const char **)objc_copyClassNamesForImage((const char *)[module_path UTF8String], &n_classes);
    if (n_classes == 0) {
        NSString *debug_path = [module_path stringByAppendingString:@".debug.dylib"];
        allClasses = (const char **)objc_copyClassNamesForImage((const char *)[debug_path UTF8String], &n_classes);
    }
    
    NSMutableDictionary *methods_info = [NSMutableDictionary dictionary];
    
    for (int i = 0; i < n_classes; i++) {
        const char *cls_name = allClasses[i];
        Class cls = objc_getClass(cls_name);
        
        // instance methods
        unsigned int n_imethods = 0;
        Method *methods = (Method *)class_copyMethodList(cls, &n_imethods);
        for (int j = 0; j < n_imethods; j++) {
            Method method = methods[j];
            uint64_t method_imp = (uint64_t)method_getImplementation(method);
            NSNumber *addr = @(method_imp);
            if ([addr_list containsObject:addr]) {
                const char *sel_name = sel_getName((SEL)method_getName(method));
                NSString *key = [NSString stringWithFormat:@"%lld", method_imp];
                methods_info[key] = [NSString stringWithFormat:@"-[%s %s]", cls_name, sel_name];
                [addr_list removeObject:addr];
            }
        }
        free(methods);
        
        if ([addr_list count] == 0) {
            break;
        }
        
        // class methods
        unsigned int n_cmethods = 0;
        Method *classMethods = (Method *)class_copyMethodList((Class)objc_getMetaClass(cls_name), &n_cmethods);
        for (int k = 0; k < n_cmethods; k++) {
            Method method = classMethods[k];
            uint64_t method_imp = (uint64_t)method_getImplementation(method);
            NSNumber *addr = @(method_imp);
            if ([addr_list containsObject:addr]) {
                const char *sel_name = sel_getName((SEL)method_getName(method));
                NSString *key = [NSString stringWithFormat:@"%lld", method_imp];
                methods_info[key] = [NSString stringWithFormat:@"+[%s %s]", cls_name, sel_name];
                [addr_list removeObject:addr];
            }
        }
        free(classMethods);
        if ([addr_list count] == 0) {
            break;
        }
    }
    free(allClasses);
    
    NSString *json_str = nil;
    NSData *json_data = [NSJSONSerialization dataWithJSONObject:methods_info options:kNilOptions error:nil];
    // 4 NSUTF8StringEncoding
    json_str = [[NSString alloc] initWithData:json_data encoding:4];
    
    json_str;
    '''
    return command_script


class Frame:
    idx = -1
    image_name = ''
    max_width = 0  # max width of image name
    load_addr = 0
    base = 0
    file_offset = 0
    symbol_name = ''
    symbol_offset = 0

    def description(self):
        frame_des = ''
        if len(self.symbol_name) > 0:
            name_or_addr = self.symbol_name
            offset = self.symbol_offset
        else:
            name_or_addr = '{:#x}'.format(self.base)
            offset = self.file_offset

        if self.max_width == 0:
            self.max_width = g_max_name_width

        frame_des += '{:<4}{:<{}}  {:#x} {} + {}\n'. \
            format(self.idx, self.image_name, self.max_width, self.load_addr, name_or_addr, offset)

        return frame_des


class Thread:
    title = ''
    frames: [Frame] = []

    def description(self):
        thread_des = '{}\n'.format(self.title)
        for frame in self.frames:
            thread_des += '{}\n'.format(frame.description())

        return thread_des


def generate_option_parser():
    usage = "usage: \n%prog addr1 [addr2 ...]" \
            "%prog /path/to/crash report file"

    parser = optparse.OptionParser(usage=usage, prog='symbolize')
    parser.add_option("-s", "--dsym",
                      dest="dsym",
                      help="path to dir of dSYM")

    return parser
