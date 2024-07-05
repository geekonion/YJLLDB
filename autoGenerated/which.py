# -*- coding: UTF-8 -*-

import lldb
import util


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "" -f '
        'which.handle_which which')


def handle_which(debugger, command, result, internal_dict):
    """
    
    implemented in YJLLDB/autoGenerated/which.py
    """
    code, out, err = util.exe_shell_command('which ' + command)
    if err or code != 0:
        print(err)

    if out:
        print(out)
    