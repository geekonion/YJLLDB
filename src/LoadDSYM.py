# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import os
import util


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "load dsym file(s)" -f LoadDSYM.load_dsym load_dSYM')


def load_dsym(debugger, command, result, internal_dict):
    """
    load dsym file(s)
    implemented in YJLLDB/src/LoadDSYM.py
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

    target = debugger.GetSelectedTarget()
    uuid_map = {}
    for module in target.module_iter():
        uuid = module.GetUUIDString().upper()
        uuid_map[uuid] = True

    n_totoal = 0
    n_success = 0
    for arg in args:
        # 普通文件
        if os.path.isfile(arg):
            print('{} is not a directory'.format(arg))
            continue

        # .dSYM文件
        if arg.endswith('.dSYM'):
            success, message = try_load_dsym_file(uuid_map, arg)
            n_totoal += 1
            if success:
                n_success += 1
            else:
                result.AppendMessage(message)

            continue

        # 文件夹
        for root, dirs, files in os.walk(arg):
            for dir_name in dirs[::-1]:
                if dir_name.endswith('.dSYM'):
                    # 遍历时排除.dSYM
                    dirs.remove(dir_name)

                    full_path = os.path.join(root, dir_name)
                    success, message = try_load_dsym_file(uuid_map, full_path)
                    n_totoal += 1
                    if success:
                        n_success += 1
                    else:
                        result.AppendMessage(message)

    if n_totoal == n_success:
        result.AppendMessage('{} dSYM file(s) loaded'.format(n_success))
    else:
        result.AppendMessage('{} dSYM file(s) loaded, {} failed'.format(n_success, n_totoal - n_success))


def try_load_dsym_file_in_dir(dir_path, uuid_map, log=False):
    for root, dirs, files in os.walk(dir_path):
        for dir_name in dirs[::-1]:
            if dir_name.endswith('.dSYM'):
                # 遍历时排除.dSYM
                dirs.remove(dir_name)

                full_path = os.path.join(root, dir_name)
                success, message = try_load_dsym_file(uuid_map, full_path)
                if log and not success:
                    print(message)


def try_load_dsym_file(uuid_map, path):
    code, output, error = util.exe_shell_command('dwarfdump --uuid {}'.format(path))
    if code != 0:
        return False, 'dwarfdump failed: {}'.format(error)

    # UUID: A8DD6B7B-EC72-3591-969B-AE8D7C2559CB (arm64) /path/to/.dSYM/Contents/Resources/DWARF/name
    lines = output.split('\n')
    found = False
    for line in lines:
        pos_start = line.find('UUID: ')
        if pos_start == -1:
            return False, 'uuid not found: {}'.format(path)

        start = pos_start + len('UUID: ')
        pos_end = line.find(' ', start)
        uuid = line[start: pos_end].upper()
        if uuid_map.get(uuid):
            found = True
            break

    if not found:
        return False, 'uuid not match: {}'.format(path)

    message = util.exe_command('target symbols add {}'.format(path))
    success = message.find('has been added to') > 0

    return success, message


def generate_option_parser():
    usage = "usage: %prog /path/to/.dSYM or /path/to/dir/of/.dSYM\n"

    parser = optparse.OptionParser(usage=usage, prog='load_dSYM')

    return parser
