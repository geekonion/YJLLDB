# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import util
import MachOHelper

extra_offset = 0
base_num_frames = 0
base_frame = None
last_frame = None
last_offset = 0
last_thread = None
call_num = 0
oneshot = False


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "trace all functions in the specified module, see also mtrace" -f '
        'TraceModuleByFunctionStarts.trace_all_functions_in_module mtrace_fs')


def trace_all_functions_in_module(debugger, command, result, internal_dict):
    """
    trace all functions in the specified module, see also mtrace
    implemented in YJLLDB/src/TraceModuleByFunctionStarts.py
    """
    # 去掉转义符
    command = command.replace('\\', '\\\\')
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

    if args:
        lookup_module_name_or_addr = ''.join(args)
    else:
        lookup_module_name_or_addr = None

    if not lookup_module_name_or_addr:
        result.AppendMessage(parser.get_usage())
        return

    lookup_module_name_or_addr = lookup_module_name_or_addr.replace("'", "")

    if options.oneshot:
        global oneshot
        oneshot = True

    funcs, module_file_spec, func_starts_found = MachOHelper.get_function_starts(lookup_module_name_or_addr)
    if not func_starts_found:
        result.AppendMessage('Function Starts not found in {}'.format(lookup_module_name_or_addr))
    elif not module_file_spec:
        result.AppendMessage("module {} not found".format(lookup_module_name_or_addr))
    else:
        target = debugger.GetSelectedTarget()
        tid = 0
        if options.thread:
            process = target.GetProcess()
            thread = process.GetSelectedThread()
            tid = thread.GetThreadID()
        name = module_file_spec.GetFilename()
        print("-----traces functions in %s-----" % name)

        total_count = 0
        func_names = set()
        module_list = lldb.SBFileSpecList()
        module_list.Append(module_file_spec)
        comp_unit_list = lldb.SBFileSpecList()

        for addr, func_size in funcs:
            addr_obj = target.ResolveLoadAddress(addr)
            symbol = addr_obj.GetSymbol()
            # 2为Code，5为Trampoline，即调用的系统函数
            if symbol.GetType() != 2:
                continue

            sym_name = symbol.GetName()
            sym_start_addr = symbol.GetStartAddress()
            if not options.individual and not sym_name:
                continue

            if not options.all:
                if '[' not in sym_name:
                    continue
                if sym_name.endswith(' .cxx_destruct]'):
                    continue
            else:
                # 过滤析构函数
                if "::~" in sym_name:
                    continue
                # 过滤objc_msgSend stubs
                if sym_name.startswith("objc_msgSend$"):
                    continue

                """
                调用系统库c++函数和operator也会在__TEXT.__text产生一个函数
                (lldb) br list 13293.1
                13293: address = demo[0x00000001000774d8], locations = 1, resolved = 1, hit count = 1
                  13293.1: where = demo`std::__1::vector<unsigned char, std::__1::allocator<unsigned char> >::operator[]
                  [abi:v15006](unsigned long) at vector:1455, address = 0x00000001004a74d8, resolved, hit count = 1 
    
                (lldb) image lookup -a 0x00000001004a74d8
                      Address: demo[0x00000001000774d8] (demo.__TEXT.__text + 463104)
                      Summary: demo`std::__1::vector<unsigned char, std::__1::allocator<unsigned char> >::operator[]
                      [abi:v15006](unsigned long) at vector:1455
                """

                # 使用符号路径过滤系统库函数
                if ".platform/Developer/SDKs/" in str(sym_start_addr.GetLineEntry().GetFileSpec()):
                    if options.verbose:
                        result.AppendMessage(f"ignore function {sym_name} at {sym_start_addr.GetLineEntry()}")
                    continue

            if options.verbose:
                result.AppendMessage(sym_start_addr.GetLineEntry())

            if options.individual:
                brkpoint = target.BreakpointCreateBySBAddress(sym_start_addr)
                # 判断下断点是否成功
                if not brkpoint.IsValid() or brkpoint.num_locations == 0:
                    result.AppendWarning("Breakpoint isn't valid or hasn't found any hits")
                else:
                    total_count += 1
                    if options.thread:
                        brkpoint.SetThreadID(tid)
                    brkpoint.SetAutoContinue(True)
                    if options.humanized:
                        # 给断点设置回调，这个回调是被私有的C++ API调用的，并只能调用特定签名的函数
                        brkpoint.SetScriptCallbackFunction("TraceModuleByFunctionStarts.breakpoint_handler")
                    else:
                        commands = lldb.SBStringList()
                        commands.AppendString('frame info')
                        brkpoint.SetCommandLineCommands(commands)
                    if options.oneshot:
                        brkpoint.SetOneShot(True)

                    addr = sym_start_addr.GetLoadAddress(target)
                    result.AppendMessage("begin trace with Breakpoint {}: where = {}`{}, address = 0x{:x}"
                                         .format(brkpoint.GetID(), name, sym_name, addr))
            else:
                func_names.add(sym_name)

        if options.individual:
            result.AppendMessage("begin trace with {} breakpoint".format(total_count))
        else:
            # BreakpointCreateByNames(SBTarget self, char const ** symbol_name, uint32_t num_symbol,
            # uint32_t name_type_mask, SBFileSpecList module_list, SBFileSpecList comp_unit_list) -> SBBreakpoint...
            n_func_names = len(func_names)
            result.AppendMessage(f"will trace {n_func_names} names")
            if n_func_names > 0:
                brkpoint = target.BreakpointCreateByNames(list(func_names),
                                                          n_func_names,
                                                          lldb.eFunctionNameTypeFull,
                                                          module_list,
                                                          comp_unit_list)
                # 判断下断点是否成功
                if not brkpoint.IsValid() or brkpoint.num_locations == 0:
                    result.AppendWarning("Breakpoint isn't valid or hasn't found any hits")
                else:
                    if options.thread:
                        brkpoint.SetThreadID(tid)
                    brkpoint.SetAutoContinue(True)
                    if options.humanized:
                        # 给断点设置回调，这个回调是被私有的C++ API调用的，并只能调用特定签名的函数
                        brkpoint.SetScriptCallbackFunction("TraceModuleByFunctionStarts.breakpoint_handler")
                    else:
                        commands = lldb.SBStringList()
                        commands.AppendString('frame info')
                        brkpoint.SetCommandLineCommands(commands)
                    result.AppendMessage("begin trace with Breakpoint {}: {} locations"
                                         .format(brkpoint.GetID(), brkpoint.GetNumLocations()))


def breakpoint_handler(frame, bp_loc, dict):
    global oneshot
    if oneshot:
        bp_loc.SetEnabled(False)

    thread = frame.GetThread()

    current_num_frames = thread.GetNumFrames()
    global extra_offset
    global base_num_frames
    global base_frame
    global last_frame
    global last_offset
    global call_num
    global last_thread

    if last_thread != thread:
        base_num_frames = 0
        last_frame = None
        base_frame = None
        last_offset = 0
        call_num = 0
        last_thread = thread

    if base_num_frames == 0:
        print('{0} thread #{1} tid = 0x{2:x} call{0}'.format('-' * 30, thread.GetIndexID(), thread.GetThreadID()))
        base_num_frames = current_num_frames
        base_frame = frame
    elif base_num_frames == 1 and current_num_frames > base_num_frames:
        base_num_frames = current_num_frames
        base_frame = frame
        extra_offset = 1
    elif current_num_frames < base_num_frames:
        print('{0} thread #{1} tid = 0x{2:x} call{0}'.format('-' * 30, thread.GetIndexID(), thread.GetThreadID()))
        base_num_frames = current_num_frames
        base_frame = frame
        call_num = 0
    elif current_num_frames > base_num_frames:
        # base_frame为空，代表之前记录的frame已经被释放，即之前的调用结束
        if not base_frame:
            print('{0} thread #{1} tid = 0x{2:x} call{0}'.format('-' * 30, thread.GetIndexID(), thread.GetThreadID()))
            base_num_frames = current_num_frames
            base_frame = frame
            call_num = 0

    if last_frame == frame:
        call_num += 1
    else:
        if call_num > 1:
            print('{} called {} times'.format('  ' * last_offset, call_num))

        call_num = 0

        addr = bp_loc.GetAddress()
        desc = util.get_desc_for_address(addr)
        offset = current_num_frames - base_num_frames + extra_offset
        if offset == 0:
            print('call {}'.format(desc))
        else:
            print('{} call {}'.format('  ' * offset, desc))

        last_frame = frame
        last_offset = offset


def generate_option_parser():
    usage = "usage: %prog [options] module name or loadAddress\n" + \
        "By default, only OC methods are traced.\n" \
        "To trace swift、c、c++ functions, you need to add the -a option."

    parser = optparse.OptionParser(usage=usage, prog='mtrace_fs')
    parser.add_option("-a", "--all",
                      action="store_true",
                      default=False,
                      dest="all",
                      help="trace all functions")
    parser.add_option("-1", "--oneshot",
                      action="store_false",
                      default=True,
                      dest="oneshot",
                      help="disable oneshot, default is oneshot")
    parser.add_option("-H", "--humanized",
                      action="store_true",
                      default=False,
                      dest="humanized",
                      help="print humanized backtrace, but higher cost than default")

    parser.add_option("-t", "--thread",
                      action="store_true",
                      default=False,
                      dest="thread",
                      help="trace current thread only")

    parser.add_option("-v", "--verbose",
                      action="store_true",
                      default=False,
                      dest="verbose",
                      help="verbose output")

    parser.add_option("-i", "--individual",
                      action="store_true",
                      default=False,
                      dest="individual",
                      help="create breakpoints with individual mode")

    return parser
