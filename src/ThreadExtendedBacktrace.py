# -*- coding: UTF-8 -*-

import lldb

g_types = ["Application Specific Backtrace", "libdispatch", "pthread"]


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "get extended backtrace of thread" -f '
        'ThreadExtendedBacktrace.get_thread_extended_backtrace thread_eb')


def get_thread_extended_backtrace(debugger, command, result, internal_dict):
    """
    get extended backtrace of thread
    implemented in YJLLDB/src/ThreadExtendedBacktrace.py
    """

    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()

    backtrace = ''
    for ext_type in g_types:
        ext_thread = thread.GetExtendedBacktraceThread(ext_type)
        if ext_thread:
            backtrace += '{}\n'.format(ext_thread)
            for frame in ext_thread:
                backtrace += '    {}\n'.format(frame)

    if len(backtrace) > 0:
        result.AppendMessage(backtrace)