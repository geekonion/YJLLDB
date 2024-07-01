# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import util


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "find AppDelegate class" -f '
        'AppDelegate.find_app_delegate appdelegate')


def find_app_delegate(debugger, command, result, internal_dict):
    """
    find AppDelegate class
    implemented in YJLLDB/src/AppDelegate.py
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

    class_names_str = get_app_delegate_class()
    if class_names_str:
        class_names = class_names_str.split('\n')
        class_names = sorted(class_names)

        result.AppendMessage("{}".format('\n'.join(class_names)))


def get_app_delegate_class():
    command_script = '@import Foundation;'
    command_script += r'''
    NSString *module_path = [[NSBundle mainBundle] executablePath];
    
    NSMutableString *result = [NSMutableString string];
    if (module_path) {
        unsigned int nclass = 0;
        const char **names = (const char **)objc_copyClassNamesForImage((const char *)[module_path UTF8String], &nclass);
        if (names) {
            Protocol *AppDelegate = NSProtocolFromString(@"UIApplicationDelegate");
            for (unsigned int i = 0; i < nclass; i++) {
                NSString *className = [NSString stringWithUTF8String:names[i]];
                Class cls = NSClassFromString(className);
                if (cls && (BOOL)[cls conformsToProtocol:AppDelegate]) {
                    [result appendFormat:@"%@\n", className];
                    break;
                }
            }
            free(names);
        }
    }
    
    result;
    '''

    ret_str = util.exe_script(command_script)

    return ret_str


def generate_option_parser():
    usage = "usage: %prog [ModuleName]\n"

    parser = optparse.OptionParser(usage=usage, prog='appdelegate')

    return parser
