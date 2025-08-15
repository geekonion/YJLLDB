# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import util
import json


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "dump all classes in the specified module" -f '
        'Objc.dump_classes_in_module classes')

    debugger.HandleCommand(
        'command script add -h "find duplicate class(es)" -f '
        'Objc.find_duplicate_classes duplicate_class')

    debugger.HandleCommand(
        'command script add '
        '-h "Dumps all methods implemented by the NSObject subclass, supporting both iOS and MacOS." '
        '-f Objc.dump_methods dmethods')

    debugger.HandleCommand(
        'command script add '
        '-h "Dumps all ivars for an instance of a particular class which inherits from NSObject, '
        'supporting both iOS and MacOS." '
        '-f Objc.dump_ivars divars')


def dump_classes_in_module(debugger, command, result, internal_dict):
    """
    dump all classes in the specified module
    implemented in YJLLDB/src/Objc.py
    """
    handle_command(command, result, 'classes')


def dump_methods(debugger, command, result, internal_dict):
    """
    Dumps all methods implemented by the NSObject subclass, supporting both iOS and MacOS.
    implemented in YJLLDB/src/Objc.py
    """
    handle_command(command, result, 'dmethods')


def dump_ivars(debugger, command, result, internal_dict):
    """
    Dumps all ivars for an instance of a particular class which inherits from NSObject, supporting both iOS and MacOS.
    implemented in YJLLDB/src/Objc.py
    """
    handle_command(command, result, 'ivars')


def handle_command(command, result, name):
    # 去掉转义符
    command = command.replace('\\', '\\\\')
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command_args = shlex.split(command, posix=False)
    # 创建parser
    parser = generate_option_parser(name)
    # 解析参数，捕获异常
    try:
        # options是所有的选项，key-value形式，args是其余剩余所有参数，不包含options
        (options, args) = parser.parse_args(command_args)
    except Exception as error:
        print(error)
        result.SetError("\n" + parser.get_usage())
        return

    n_args = len(args)
    if n_args == 0:
        input_arg = ''
    elif n_args == 1:
        input_arg = args[0]
        input_arg = input_arg.replace("'", "")
        input_arg = input_arg.replace('"', '')
    else:
        result.AppendMessage(parser.get_usage())
        return

    if name == 'classes':
        class_names_str = get_module_regions(input_arg)
        if class_names_str:
            class_names = class_names_str.split('\n')
            class_names = sorted(class_names)

            result.AppendMessage("{}".format('\n'.join(class_names)))

        return

    if name == 'dmethods':
        result.AppendMessage(get_methods(input_arg))
    elif name == 'ivars':
        result.AppendMessage(get_ivars(input_arg))


def find_duplicate_classes(debugger, command, result, internal_dict):
    """
    find duplicate class(es)
    implemented in YJLLDB/src/Objc.py
    """
    json_str = dump_duplicate_oc_classes()
    class_dict = json.loads(json_str)
    for cls_name in class_dict:
        print('class {} is implemented in:'.format(cls_name))
        paths = class_dict[cls_name]
        for image_path in paths:
            print('\t{}'.format(image_path))

    print('{} duplicate classes found'.format(len(class_dict)))


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


def get_methods(input_arg):
    command_script = '@import Foundation;\n@import ObjectiveC;\n'
    if input_arg.startswith('0x'):
        command_script += 'Class mthd_cls = (Class)[(id)' + input_arg + ' class];'
    else:
        command_script += 'Class mthd_cls = (Class)[' + input_arg + ' class];'
    command_script += r'''
    NSString *x_method_des = nil;
    NSString *x_mthd_source = nil;
    if ((BOOL)[mthd_cls respondsToSelector:@selector(_shortMethodDescription)]) {
        x_method_des = (id)[mthd_cls _shortMethodDescription];
        x_mthd_source = @" (UI)\n";
    } else if ((BOOL)[mthd_cls respondsToSelector:@selector(fp_shortMethodDescription)]) {
        x_method_des = (id)[mthd_cls fp_shortMethodDescription];
        x_mthd_source = @" (FP)\n";
    } else if ((BOOL)[mthd_cls respondsToSelector:@selector(_fd_shortMethodDescription)]) {
        x_method_des = (id)[mthd_cls _fd_shortMethodDescription];
        x_mthd_source = @" (DK)\n";
    } else {
        x_mthd_source = @" (JIT)\n";
        NSMutableString *method_list = [NSMutableString string];
        [method_list appendFormat:@"in %s:\n", class_getName(mthd_cls)];
    
        Class meta_cls = object_getClass(mthd_cls);
        unsigned c_count = 0;
        Method *c_methods = class_copyMethodList(meta_cls, &c_count);
        if (c_count > 0) {
            [method_list appendFormat:@"\tClass Methods:\n"];
        }
        for (int i = 0; i < c_count; i++) {
            Method method = c_methods[i];
            const char *ret_type = method_copyReturnType(method);
            const char *sel_name = sel_getName(method_getName(method));
            void * imp = (void *)method_getImplementation(method);
            [method_list appendFormat:@"\t\t+ (%s) %s; (%p)\n", ret_type, sel_name, imp];
            
            free((void *)ret_type);
        }
        free(c_methods);
        
        unsigned i_count = 0;
        Method *i_methods = class_copyMethodList(mthd_cls, &i_count);
        if (i_methods > 0) {
            [method_list appendString:@"\tInstance Methods:\n"];
        }
        for (int i = 0; i < i_count; i++) {
            Method method = i_methods[i];
            const char *ret_type = method_copyReturnType(method);
            const char *sel_name = sel_getName(method_getName(method));
            void * imp = (void *)method_getImplementation(method);
            [method_list appendFormat:@"\t\t- (%s) %s; (%p)\n", ret_type, sel_name, imp];
            
            free((void *)ret_type);
        }
        free(i_methods);
        
        [method_list appendFormat:@"(%s ...)", class_getName((Class)[mthd_cls superclass])];
        
        x_method_des = method_list;
    }
    
    NSMutableString *x_method_des_ret = [NSMutableString stringWithString:x_method_des];
    NSRange range = [x_method_des_ret rangeOfString:@"\n"];
    if (range.location != NSNotFound) {
        [x_method_des_ret replaceCharactersInRange:range withString:x_mthd_source];
    }
    
    x_method_des_ret;
    '''

    ret_str = util.exe_script(command_script)

    return ret_str


def get_ivars(input_arg):
    command_script = '@import Foundation;\n@import ObjectiveC;\n'
    if input_arg.startswith('0x'):
        command_script += 'id ivar_obj = (id)' + input_arg + ';'
    else:
        command_script += 'id ivar_obj = ' + input_arg + ';'
    command_script += r'''
    NSString *x_ivar_des = nil;
    NSString *x_ivar_source = nil;
    if ((BOOL)[ivar_obj respondsToSelector:@selector(_ivarDescription)]) {
        x_ivar_des = (id)[ivar_obj _ivarDescription];
        x_ivar_source = @" (UI)\n";
    } else if ((BOOL)[NSObject respondsToSelector:@selector(fp__ivarDescriptionForClass:)]) {
        Class ivar_cls = nil;
        if (object_isClass(ivar_obj)) {
            ivar_cls = ivar_obj;
        } else {
            ivar_cls = (Class)[ivar_obj class];
        }
        x_ivar_des = (id)[NSObject fp__ivarDescriptionForClass:ivar_cls];
        x_ivar_source = @" (FP)\n";
    } else if ((BOOL)[ivar_obj respondsToSelector:@selector(_fd_ivarDescription)]) {
        x_ivar_des = (id)[ivar_obj _fd_ivarDescription];
        x_ivar_source = @" (DK)\n";
    } else {
        x_ivar_source = @" (JIT)\n";
        void (^parse_ivars)(Class, NSMutableString *) = ^(Class cls, NSMutableString *ivar_list){
            [ivar_list appendFormat:@"in %s:\n", class_getName(cls)];
            unsigned v_count = 0;
            Ivar *ivars = class_copyIvarList(cls, &v_count);
            for (int i = 0; i < v_count; i++) {
                Ivar ivar = ivars[i];
                const char *ivar_name = ivar_getName(ivar);
                ptrdiff_t offset = ivar_getOffset(ivar);
                [ivar_list appendFormat:@"\t%ld: %s\n", offset, ivar_name];
            }
            
            free(ivars);
        };
        
        Class ivar_class = [ivar_obj class];
        NSMutableString *ivar_list = [NSMutableString string];
        Class tmp_cls = nil;
        while (ivar_class) {
            parse_ivars(ivar_class, ivar_list);
            tmp_cls = (Class)[ivar_class superclass];
            if (tmp_cls == ivar_class) {
                break;
            }
            ivar_class = tmp_cls;
        }
        
        x_ivar_des = ivar_list;
    }
    
    NSMutableString *x_ivar_des_ret = [NSMutableString stringWithString:x_ivar_des];
    NSRange range = [x_ivar_des_ret rangeOfString:@"\n"];
    if (range.location != NSNotFound) {
        [x_ivar_des_ret replaceCharactersInRange:range withString:x_ivar_source];
    }
    
    x_ivar_des_ret;
    '''

    ret_str = util.exe_script(command_script)

    return ret_str


def dump_duplicate_oc_classes():
    command_script = '@import Foundation;\n@import ObjectiveC;\n'
    command_script += r'''
    NSMutableArray *path_array = [NSMutableArray array];
    NSMutableArray *cls_array = [NSMutableArray array];
    
    uint32_t img_count = (uint32_t)_dyld_image_count();
    for (uint32_t idx = 0; idx < img_count; idx++) {
        @autoreleasepool {
            const char *image_path = (const char *)_dyld_get_image_name(idx);
            unsigned n_classes = 0;
            const char **classes = objc_copyClassNamesForImage(image_path, &n_classes);
            if (n_classes != 0) {
                NSString *path = [NSString stringWithUTF8String:image_path];
                NSMutableArray *classNames = [NSMutableArray array];
                for (int i = 0; i < n_classes; i++) {
                    const char *name = classes[i];
                    [classNames addObject:[NSString stringWithUTF8String:name]];
                }
                
                [path_array addObject:path];
                [cls_array addObject:classNames];
            }
            if (classes) {
                free(classes);
                classes = NULL;
            }
        }
    }
    
    NSString *bundle_path = [NSBundle mainBundle].bundlePath;
    NSString *bundle_parent = [bundle_path stringByDeletingLastPathComponent];
    NSMutableDictionary *class_dict = [NSMutableDictionary dictionary];
    NSInteger count = [cls_array count];
    for (NSInteger i = 0; i < count; i++) {
        NSString *path = path_array[i];
        if (![path containsString:bundle_path]) {
            continue;
        }
        @autoreleasepool {
            NSArray *cls_arr1 = cls_array[i];
            for (NSInteger j = i + 1; j < count; j++) {
                @autoreleasepool {
                    NSMutableSet *cls_set1 = [NSMutableSet setWithArray:cls_arr1];
                    NSArray *cls_arr2 = cls_array[j];
                    NSMutableSet *cls_set2 = [NSMutableSet setWithArray:cls_arr2];
                    [cls_set1 intersectSet:cls_set2];
                    for (id<NSCopying> cls_name in cls_set1) {
                        NSMutableArray *paths = class_dict[cls_name];
                        if (!paths) {
                            paths = [NSMutableArray array];
                            class_dict[cls_name] = paths;
                            NSString *rel_path = [path stringByReplacingOccurrencesOfString:bundle_parent withString:@""];
                            [paths addObject:rel_path];
                        }
                        
                        NSString *rel_path = [path_array[j] stringByReplacingOccurrencesOfString:bundle_parent withString:@""];
                        [paths addObject:rel_path];
                    }
                }
            }
        }
    }
    
    NSData *data = [NSJSONSerialization dataWithJSONObject:class_dict options:kNilOptions error:nil];
    // 4 NSUTF8StringEncoding
    NSString *cls_json_str = [[NSString alloc] initWithData:data encoding:4];
    
    cls_json_str;
    '''

    ret_str = util.exe_script(command_script)

    return ret_str


def generate_option_parser(name):
    if name == 'classes':
        usage = "usage: %prog [ModuleName]\n"
    else:
        usage = "usage: %prog\n"

    parser = optparse.OptionParser(usage=usage, prog=name)

    return parser
