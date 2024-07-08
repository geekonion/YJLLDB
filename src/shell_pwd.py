# -*- coding: UTF-8 -*-

import os
import lldb


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "" -f '
        'shell_pwd.handle_pwd pwd')


def handle_pwd(debugger, command, result, internal_dict):
    """
    
    implemented in YJLLDB/src/shell_pwd.py
    """
    print(os.getcwd())
