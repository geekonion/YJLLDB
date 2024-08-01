# -*- coding: UTF-8 -*-

import lldb
import time

start_time = 0
break_ids = []
clean_done = False
breakpoint_ignore_count = 99


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "find endless loop" -f '
        'FindEndlessLoop.find_endless_loop find_el')


def find_endless_loop(debugger, command, result, internal_dict):
    """
    find endless loop
    implemented in YJLLDB/src/FindEndlessLoop.py
    """

    target = debugger.GetSelectedTarget()
    main_module = target.GetModuleAtIndex(0)

    process = target.GetProcess()
    for thread in process:
        for frame in thread:
            module = frame.GetModule()
            if main_module.__eq__(module):
                addr = frame.GetPCAddress()
                breakpoint = target.BreakpointCreateBySBAddress(addr)

                # 判断下断点是否成功
                if not breakpoint.IsValid() or breakpoint.num_locations == 0:
                    result.AppendWarning("Breakpoint isn't valid or hasn't found any hits")
                else:
                    global break_ids
                    break_ids.append(breakpoint.GetID())
                    result.AppendMessage("Breakpoint {}: where = {}, address = 0x{:x}".
                                         format(breakpoint.GetID(),
                                                get_desc_for_address(target, addr),
                                                addr.GetLoadAddress(target)))

                breakpoint.SetAutoContinue(True)
                breakpoint.SetIgnoreCount(breakpoint_ignore_count)
                # 给断点设置回调，这个回调是被私有的C++ API调用的，并只能调用特定签名的函数
                breakpoint.SetScriptCallbackFunction("FindEndlessLoop.breakpoint_handler")
    global start_time
    start_time = time.perf_counter()

    # 自动继续程序，以便统计调用频率
    debugger.SetAsync(True)
    process.Continue()
    result.SetStatus(lldb.eReturnStatusSuccessContinuingResult)


def get_desc_for_address(target, addr):
    symbol = addr.GetSymbol()

    module = addr.GetModule()
    module_name = "unknown"
    if module:
        module_file_spec = module.GetFileSpec()
        module_name = module_file_spec.GetFilename()

    offset = addr.GetLoadAddress(target) - symbol.GetStartAddress().GetLoadAddress(target)

    line_entry = addr.GetLineEntry()
    if line_entry:
        file_spec = line_entry.GetFileSpec()
        file_name = file_spec.GetFilename()
        return "{}`{} + {} at {}:{}:{}".format(module_name, symbol.GetName(), offset, file_name, line_entry.GetLine(),
                                               line_entry.GetColumn())

    return "{}`{} + {}".format(module_name, symbol.GetName(), offset)


def breakpoint_handler(frame, bp_loc, dict):
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()

    global clean_done
    if not clean_done:
        for break_id in break_ids:
            brkpoint = target.FindBreakpointByID(break_id)
            loc = brkpoint.FindLocationByID(1)
            if loc and loc.GetHitCount() < 5:
                print("delete breakpoint {}".format(break_id))
                target.BreakpointDelete(break_id)
        clean_done = True

    hit_count = bp_loc.GetHitCount()
    addr = bp_loc.GetAddress()
    if hit_count >= 1000:
        bp_loc.SetEnabled(False)
        print("==" * 40)
        print("↓ " * 40)
        print("disable breakpoint {}\nThere may be an endless loop here. Please confirm by yourself".
              format(get_desc_for_address(target, addr)))
    else:
        now = time.perf_counter()
        time_interval = now - start_time
        hps = round(hit_count / time_interval)
        print("call {}, {} times per second, hit_count: {}".format(get_desc_for_address(target, addr), hps, hit_count))
        # 重新设置ignore count，因为断点每命中一次，ignore count都会减1，直到为0，就会触发断点
        # 间接实现每breakpoint_ignore_count次命中一次的效果
        # https://stackoverflow.com/questions/40615222/how-can-i-setup-an-lldb-breakpoint-firing-every-10th-time
        bp_loc.SetIgnoreCount(breakpoint_ignore_count)
