# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import os
import util

g_app_name = None
g_system = False


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "trace notification" -f '
        'Notifier.trace_notification notifier')


def trace_notification(debugger, command, result, internal_dict):
    """
    trace notification
    implemented in YJLLDB/src/Notifier.py
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

    global g_system, g_app_name
    g_system = options.system
    target = debugger.GetSelectedTarget()

    app_path = target.GetExecutable().GetDirectory()
    last_slash_pos = app_path.rfind('/')
    if last_slash_pos > 0:
        g_app_name = app_path[last_slash_pos:] + os.path.sep
    else:
        result.SetError("App path not found")
        return

    trace_ns_notification(target, result)
    trace_cf_notification(target, result)


def trace_ns_notification(target, result):
    func_names = ['-[NSNotificationCenter postNotification:]',
                  '-[NSNotificationCenter postNotificationName:object:userInfo:]'
                  ]
    trace_funcs(target, result, func_names, "Notifier.handle_ns_notification")


def trace_cf_notification(target, result):
    # CFNotificationCenterPostNotification 会调用 CFNotificationCenterPostNotificationWithOptions
    func_names = [
                  'CFNotificationCenterPostNotificationWithOptions'
                  ]
    trace_funcs(target, result, func_names, "Notifier.handle_cf_notification")


def trace_funcs(target, result, func_names, handler):
    for name in func_names:
        brkpoint = target.BreakpointCreateByName(name)
        # 判断下断点是否成功
        if not brkpoint.IsValid() or brkpoint.num_locations == 0:
            result.AppendWarning("Breakpoint isn't valid or hasn't found any hits")
        else:
            brkpoint.SetAutoContinue(True)
            brkpoint.SetScriptCallbackFunction(handler)

            result.AppendMessage("begin trace {} with Breakpoint {}".format(name, brkpoint.GetID()))


def handle_ns_notification(frame, bp_loc, dict):
    handle_notification(frame, 'NS', 'x2')


def handle_cf_notification(frame, bp_loc, dict):
    handle_notification(frame, 'CF', 'x1', 'x0')


def handle_notification(frame, name, reg_name, reg_0_name='x0'):
    is_cf = name == 'CF'
    reg_0_value = None
    if is_cf:
        reg_0_value = frame.FindRegister(reg_0_name)
    reg_value = frame.FindRegister(reg_name)
    thread = frame.GetThread()
    parent_frame = thread.GetFrameAtIndex(1)
    module = parent_frame.GetModule()
    is_sys_mod = is_sys_module(module, g_app_name)
    if is_sys_mod and not g_system:
        return

    '''
    CFNotificationCenter的3种类型：
    CFNotificationCenterGetDistributedCenter()
    CFNotificationCenterGetLocalCenter()
    CFNotificationCenterGetDarwinNotifyCenter()
    '''
    parent_name = parent_frame.GetDisplayFunctionName()
    if parent_name == '__NSFinalizeThreadData':  # 执行po会造成崩溃，只输出地址
        if is_cf:
            print('{} post a {} notification {}, with {}'.
                  format(parent_name, name, reg_value.GetValue(), reg_0_value.GetValue()))
        else:
            print('{} post a {} notification {}'.format(parent_name, name, reg_value.GetValue()))
    else:
        obj = util.exe_command('po {}'.format(reg_value.GetValue()))
        if is_cf:
            notifier = util.exe_command('po {}'.format(reg_0_value.GetValue()))
            print('{} post a {} notification {}, with {}'.format(parent_name, name, obj, notifier))
        else:
            print('{} post a {} notification {}'.format(parent_name, name, obj))


def is_sys_module(module, app_name):
    module_path = str(module.GetFileSpec())
    pos = module_path.rfind(app_name)

    return pos < 0


def generate_option_parser():
    usage = "usage: notifier"

    parser = optparse.OptionParser(usage=usage, prog='notifier')
    parser.add_option("-s", "--system",
                      action="store_true",
                      dest="system",
                      default=False,
                      help="trace notifications from system libs")

    return parser
