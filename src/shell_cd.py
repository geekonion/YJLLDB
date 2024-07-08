# -*- coding: UTF-8 -*-

import lldb
import os


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "" -f shell_cd.handle_cd cd')


def handle_cd(debugger, command, result, internal_dict):
    """
    
    implemented in YJLLDB/src/shell_cd.py
    """
    command = command.strip()
    input_path = os.path.expanduser(command)
    cwd = os.getcwd()
    if not input_path.startswith(cwd):
        target_dir = os.path.join(cwd, input_path)
    else:
        target_dir = input_path

    if os.path.exists(target_dir):
        os.chdir(target_dir)
    else:
        print('cd: no such file or directory: {}'.format(target_dir))
