# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import util
import json

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "break methods of class" -f '
        'BreakClass.break_class bclass')


def break_class(debugger, command, result, internal_dict):
    """
    break methods of class
    implemented in YJLLDB/src/BreakClass.py
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

    n_args = len(args)
    if n_args == 1:
        class_name = args[0]
    else:
        result.AppendMessage(parser.get_usage())
        return

    target = debugger.GetSelectedTarget()

    dump_level = 0
    if options.instance:
        dump_level += 1
    elif options.cls:
        dump_level += 2
    else:
        dump_level = 3

    method_list_str = dump_class(class_name, dump_level)
    method_list = json.loads(method_list_str)

    total_count = 0
    for method in method_list:
        addr = int(method["addr"])
        addr_obj = target.ResolveLoadAddress(addr)

        module = addr_obj.GetModule()
        module_file_spec = module.GetFileSpec()
        name = module_file_spec.GetFilename()

        brkpoint = target.BreakpointCreateBySBAddress(addr_obj)
        # 判断下断点是否成功
        if not brkpoint.IsValid() or brkpoint.num_locations == 0:
            result.AppendWarning("Breakpoint isn't valid or hasn't found any hits")
        else:
            total_count += 1
            result.AppendMessage("Breakpoint {}: where = {}`{}, address = 0x{:x}"
                                 .format(brkpoint.GetID(), name, method['name'], addr))

    result.AppendMessage("set {} breakpoints".format(total_count))


def dump_class( class_name, dump_level):
    command_script = '@import Foundation;\n@import ObjectiveC;\n'
    command_script += 'const char *dm_clsName = "' + class_name + '";\n'
    command_script += 'int dump_level = {};\n'.format(dump_level)
    command_script += r'''
    NSMutableArray *dm_array = [NSMutableArray array];
    
    void (^dump_methods)(Class, BOOL) = ^(Class dm_tmp_cls, BOOL isClassMethod) {
        unsigned int nDMMethods = 0;
        Method *dm_methods = (Method *)class_copyMethodList(dm_tmp_cls, &nDMMethods);
        
        for (int i = 0; i < nDMMethods; i++) {
            Method dm_method = dm_methods[i];
            IMP dm_imp = (IMP)method_getImplementation(dm_method);
            const char *dm_prefix = isClassMethod ? "+" : "-";
            NSString *dm_name = [NSString stringWithFormat:@"%s[%s %s]", dm_prefix, dm_clsName, (const char *)sel_getName((SEL)method_getName(dm_method))];
            [dm_array addObject:@{
                @"addr": @((uintptr_t)dm_imp),
                @"name": dm_name
            }];
        }
    };
    
    Class dm_cls = objc_getClass(dm_clsName);
    if (dm_cls && (dump_level == 3 || dump_level == 2)) {
        dump_methods((Class)object_getClass(dm_cls), YES);
    }
    
    if (dm_cls && (dump_level == 3 || dump_level == 1)) {
        dump_methods(dm_cls, NO);
    }
    
    NSData *data = [NSJSONSerialization dataWithJSONObject:dm_array options:kNilOptions error:nil];
    // 4 NSUTF8StringEncoding
    NSString *json_str = [[NSString alloc] initWithData:data encoding:4];
    json_str;
    '''

    ret_str = util.exe_script(command_script)

    return ret_str


def generate_option_parser():
    usage = "usage: %prog <class name>\n"

    parser = optparse.OptionParser(usage=usage, prog='bclass')
    parser.add_option("-c", "--class",
                      action="store_true",
                      default=False,
                      dest="cls",
                      help="break class methods")
    parser.add_option("-i", "--instance",
                      action="store_true",
                      default=False,
                      dest="instance",
                      help="break instance methods")

    return parser
