# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import util


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -h "list directory contents, just like ls -lh on mac."'
                           ' -f FileSystem.execute_ls ils')
    # debugger.HandleCommand('command script add -h "print Home directory path."'
    #                        ' -f FileSystem.show_home_directory home_dir')
    # debugger.HandleCommand('command script add -h "print bundle path."'
    #                        ' -f FileSystem.show_bundle_directory bundle_dir')
    # debugger.HandleCommand('command script add -h "print Documents path."'
    #                        ' -f FileSystem.show_doc_directory doc_dir')
    # debugger.HandleCommand('command script add -h "print Library path."'
    #                        ' -f FileSystem.show_library_directory lib_dir')
    # debugger.HandleCommand('command script add -h "print tmp path."'
    #                        ' -f FileSystem.show_tmp_directory tmp_dir')
    # debugger.HandleCommand('command script add -h "print Caches path."'
    #                        ' -f FileSystem.show_caches_directory caches_dir')
    debugger.HandleCommand('command script add -h "print group path."'
                           ' -f FileSystem.show_group_path group_dir')


def execute_ls(debugger, command, result, internal_dict):
    """
    list directory contents, just like ls -lh on Mac.
    implemented in YJLLDB/src/FileSystem.py
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

    if len(args) == 1:
        dir_path, dir_type = util.absolute_path(args[0])
        print_dir = dir_type != 'full'

        if 'nil' == dir_path:
            result.AppendMessage(f'{dir_type} dir path is nil')
            return

        if not dir_path:
            result.AppendMessage(dir_path)
            return

        file_list = ls_dir(dir_path)
        if 'object returned empty description' in file_list:
            file_list = 'total 0'
        if print_dir:
            result.AppendMessage("{}\n{}".format(dir_path, file_list))
        else:
            result.AppendMessage(file_list)
    elif len(args) == 0:
        dir_path = util.get_home_directory()
        file_list = ls_dir(dir_path)
        result.AppendMessage("{}\n{}".format(dir_path, file_list))
    else:
        result.AppendMessage(parser.get_usage())
        return


def ls_dir(dir_path):
    command_script = '@import Foundation;'
    command_script += 'NSString *dir_path = @"' + dir_path + '";'
    command_script += r'''
    NSMutableString *x_result = [NSMutableString string];
    NSFileManager *x_fileManager = [NSFileManager defaultManager];
    BOOL x_isDirectory = NO;
    BOOL x_exists = [x_fileManager fileExistsAtPath:dir_path isDirectory:&x_isDirectory];
    if (x_exists) {
        NSArray *files = nil;
        if (x_isDirectory) {
            files = (NSArray *)[x_fileManager contentsOfDirectoryAtPath:dir_path error:nil];
        } else {
            files = @[dir_path.lastPathComponent];
            dir_path = [dir_path stringByDeletingLastPathComponent];
        }
        for (NSString *name in files) {
            if ([(NSString *)name isEqualToString:@".com.apple.mobile_container_manager.metadata.plist"]) {
                continue;
            }
            NSString *fullpath = [dir_path stringByAppendingPathComponent:name];
            NSDictionary<NSFileAttributeKey, id> *attrs = [x_fileManager attributesOfItemAtPath:fullpath error:nil];
            NSString *filetype = attrs[NSFileType];
            NSString *type_str = nil;
            if ([filetype isEqualToString:NSFileTypeDirectory]) {
                type_str = @"d";
            } else if ([filetype isEqualToString:NSFileTypeSymbolicLink]) {
                type_str = @"l";
            } else if ([filetype isEqualToString:NSFileTypeRegular]) {
                type_str = @"-";
            } else {
                type_str = @"-";
            }
            NSInteger permissions = (NSInteger)[(id)attrs[NSFilePosixPermissions] integerValue];
            NSString *permissions_str = @"";
            if (permissions == 0755) {
                permissions_str = @"rwxr-xr-x";
            } else if (permissions == 0644) {
                permissions_str = @"rw-r--r--";
            } else {
                NSLog(@"");
            }
            NSInteger file_size = (NSInteger)[(id)attrs[NSFileSize] integerValue];
            
            NSString *size_str = nil;
            NSInteger KB = 1000;
            NSInteger MB = KB * KB;
            NSInteger GB = MB * KB;
            if (file_size < KB) {
                size_str = [NSString stringWithFormat:@"%10luB", file_size];
            } else if (file_size < MB) {
                size_str = [NSString stringWithFormat:@"%10.1fK", ((CGFloat)file_size) / KB];
            } else if (file_size < GB) {
                size_str = [NSString stringWithFormat:@"%10.1fM", ((CGFloat)file_size) / MB];
            } else {
                size_str = [NSString stringWithFormat:@"%10.1fG", ((CGFloat)file_size) / GB];
            }
            
            NSDate *modificationDate = (id)attrs[(NSFileAttributeKey)NSFileModificationDate];
            
            [x_result appendFormat:@"%@%@ %@ %@ %@\n", type_str, permissions_str, size_str, modificationDate, name];
        }
    }
    x_result;
    '''

    ret_str = util.exe_script(command_script)

    return ret_str


def show_bundle_directory(debugger, command, result, internal_dict):
    ret_str = util.get_bundle_directory()
    result.AppendMessage(ret_str)


def show_home_directory(debugger, command, result, internal_dict):
    ret_str = util.get_home_directory()
    result.AppendMessage(ret_str)


def show_doc_directory(debugger, command, result, internal_dict):
    ret_str = util.get_doc_directory()
    result.AppendMessage(ret_str)


def show_library_directory(debugger, command, result, internal_dict):
    ret_str = util.get_library_directory()
    result.AppendMessage(ret_str)


def show_tmp_directory(debugger, command, result, internal_dict):
    ret_str = util.get_tmp_directory()
    result.AppendMessage(ret_str)


def show_caches_directory(debugger, command, result, internal_dict):
    ret_str = util.get_caches_directory()
    result.AppendMessage(ret_str)


def show_group_path(debugger, command, result, internal_dict):
    """
    print App group path if any.
    implemented in YJLLDB/src/FileSystem.py
    """

    ret_str = util.get_group_path()
    result.AppendMessage(ret_str)


def generate_option_parser():
    usage = "usage: %prog [dir type or fullpath]\n" + \
            "supported dir type:\n" + \
            "\tbundle - bundle directory\n" + \
            "\thome - home directory, it's the default option\n" + \
            "\tdoc - Documents directory\n" + \
            "\tlib - Library directory\n" + \
            "\ttmp - tmp directory\n" + \
            "\tcaches - Caches directory\n" + \
            "\tgroup - group directory"

    parser = optparse.OptionParser(usage=usage, prog='ls')

    return parser
