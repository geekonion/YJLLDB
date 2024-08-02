# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import util


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "dump all class names in the specified module" -f '
        'DumpClassNamesInModule.dump_classes_in_module classes')


def dump_classes_in_module(debugger, command, result, internal_dict):
    """
    dump all class names in the specified module
    implemented in YJLLDB/src/DumpClassNamesInModule.py
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
        lookup_module_name = ''.join(args)
    else:
        lookup_module_name = ''

    lookup_module_name = lookup_module_name.replace("'", "")
    class_names_str = get_module_regions(lookup_module_name)
    if class_names_str:
        class_names = class_names_str.split('\n')
        class_names = sorted(class_names)

        result.AppendMessage("{}".format('\n'.join(class_names)))


def get_module_regions(module):
    command_script = '@import Foundation;'
    command_script += 'NSString *x_module_name = @"' + module + '";'
    command_script += r'''
    if (![x_module_name length]) {
        NSString *cls_module_path = [[NSBundle mainBundle] executablePath];
        NSString *dlg_dylib = [cls_module_path stringByAppendingString:@".debug.dylib"];
        if ((BOOL)[[NSFileManager defaultManager] fileExistsAtPath:dlg_dylib]) {
            x_module_name = [dlg_dylib lastPathComponent];
        } else {
            x_module_name = [cls_module_path lastPathComponent];
        }
    }
    
    const char *module_path = NULL;
    uint32_t image_count = (uint32_t)_dyld_image_count();
    for (uint32_t i = 0; i < image_count; i++) {
        const char *name = (const char *)_dyld_get_image_name(i);
        if (!name) {
            continue;
        }
        
        NSString *module_name = [[NSString stringWithUTF8String:name] lastPathComponent];
        if ([module_name isEqualToString:x_module_name]) {
            module_path = name;
            break;
        }
    }
    
    NSMutableString *result = [NSMutableString string];
    if (module_path) {
        unsigned int nclass = 0;
        const char **all_cls_names = (const char **)objc_copyClassNamesForImage(module_path, &nclass);
        if (all_cls_names) {
            for (unsigned int i = 0; i < nclass; i++) {
                NSString *className = [NSString stringWithUTF8String:all_cls_names[i]];
                Class cls = NSClassFromString(className);
                if (cls) {
                    [result appendFormat:@"%@ <%p>\n", className, cls];
                } else {
                    [result appendFormat:@"%@\n", className];
                }
            }
            free(all_cls_names);
        }
    }
    
    result;
    '''

    ret_str = util.exe_script(command_script)

    return ret_str


def generate_option_parser():
    usage = "usage: %prog [ModuleName]\n"

    parser = optparse.OptionParser(usage=usage, prog='classes')

    return parser
