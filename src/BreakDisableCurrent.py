# -*- coding: UTF-8 -*-

import lldb
import os


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "disable the breakpoint(s) that is(are) currently hit" -f '
        'BreakDisableCurrent.disable_current_breakpoint bdc')


def disable_current_breakpoint(debugger, command, result, internal_dict):
    """
    disable the breakpoint(s) that is(are) currently hit
    implemented in YJLLDB/src/BreakDisableCurrent.py
    """
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    # thread = process.GetSelectedThread()

    for thread in process:
        reason = thread.GetStopReason()
        if reason == lldb.eStopReasonBreakpoint:
            n_reason = thread.GetStopReasonDataCount()
            # reason data应该成对出现，分别代表breakpoint_id和location_id
            if n_reason % 2 != 0:
                print("unexpected breakpoint data")
                continue

            for i in range(int(n_reason / 2)):
                # disable BreakpointLocation时，对应的StopReasonData会被移除，所以，每次都是从0开始取data
                # 如果只是遍历data，并不disable的话，要像遍历普通list一样，index需要增加
                brkpoint_id = thread.GetStopReasonDataAtIndex(0)
                loc_id = thread.GetStopReasonDataAtIndex(1)
                disable_breakpoint(target, thread, result, brkpoint_id, loc_id)
            print("and continue\n")

            # https://stackoverflow.com/questions/64205500/continue-after-python-lldb-script-has-finished
            is_async = debugger.GetAsync()
            debugger.SetAsync(True)
            process.Continue()
            if not is_async:
                debugger.SetAsync(is_async)
            # lldb.eReturnStatusSuccessContinuingNoResult lldb.eReturnStatusSuccessContinuingResult
            result.SetStatus(lldb.eReturnStatusSuccessContinuingNoResult)
            break
        elif reason == lldb.eStopReasonSignal:
            reason_data = thread.GetStopReasonDataAtIndex(0)
            # <sys/signals.h>
            if reason_data == 17:  # SIGSTOP
                is_async = debugger.GetAsync()
                debugger.SetAsync(True)
                process.Continue()
                if not is_async:
                    debugger.SetAsync(is_async)


def disable_breakpoint(target, thread, result, brkpoint_id, loc_id):
    brkpoint = target.FindBreakpointByID(brkpoint_id)
    loc = brkpoint.FindLocationByID(loc_id)
    loc.SetEnabled(False)

    frame = thread.GetFrameAtIndex(0)
    module = frame.GetModule()
    module_file_spec = module.GetFileSpec()
    module_name = module_file_spec.GetFilename()
    # result.AppendMessage("disable breakpoint {}.{} [0x{:x}]{}`{}".
    #                      format(brkpoint_id, loc_id, loc.GetLoadAddress(),
    #                             module_name, frame.GetDisplayFunctionName()))
    print("disable breakpoint {}.{} [0x{:x}]{}`{}".
          format(brkpoint_id, loc_id, loc.GetLoadAddress(),
                 module_name, frame.GetDisplayFunctionName()))
