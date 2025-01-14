# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
from enum import Enum


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -h "find macho header."'
                           ' -f csops.find_macho_header csops')


def find_macho_header(debugger, command, result, internal_dict):
    """
    find macho header
    implemented in YJLLDB/src/csops.py
    """

    ret_str = find_macho(debugger)
    result.AppendMessage(ret_str)


def find_macho(debugger):
    command_script = '@import Foundation;'
    command_script += r'''
#define CS_OPS_STATUS           0       /* return status */
#define CS_GET_TASK_ALLOW           0x00000004
#define CS_PLATFORM_BINARY          0x04000000
#define CS_DEBUGGED                 0x10000000
    int csops(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize);
    uint32_t csFlags = 0;
    csops(getpid(), CS_OPS_STATUS, &csFlags, sizeof(csFlags));
    
    uint32_t csFlags1 = 0;
    pid_t pid = getpid();
    __asm __volatile ("mov w0, %w[pid]\n"
                      "mov x1, #0\n"
                      "mov x2, %[csFlags_ptr]\n"
                      "mov w3, #0x4\n"
                      "mov x16, #0xa9\n"
                      "svc #0x80\n"
                      :: [pid] "r"(pid),
                      [csFlags_ptr] "r"(&csFlags1)
                      :"x0", "x1", "x2", "w3", "x16"
                      );
    
    NSMutableString *result = [NSMutableString string];
    [result appendFormat:@"-->csFlags %p\n", csFlags];
    [result appendFormat:@"-->csFlags1 %p\n", csFlags1];
    BOOL isPlatform = csFlags1 & 0x04000000;
    BOOL isDebugged = csFlags1 & CS_DEBUGGED;
    BOOL getTask = csFlags1 & CS_GET_TASK_ALLOW;
    if (isDebugged) {
        [result appendString:@"-->可以被调试\n"];
    }
    if (getTask) {
        [result appendString:@"-->get task allow"];
    }
    result;
    '''
    ret_str = exe_script(debugger, command_script)

    return ret_str


def exe_script(debugger, command_script):
    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()
    interpreter.HandleCommand('exp -l objc -O -- ' + command_script, res)

    if not res.HasResult():
        print('execute JIT code failed:\n{}'.format(res.GetError()))
        return ''

    response = res.GetOutput()

    response = response.strip()
    # 末尾有两个\n
    if response.endswith('\n\n'):
        response = response[:-2]
    # 末尾有两个\n
    if response.endswith('\n'):
        response = response[:-1]

    return response


def generate_option_parser():
    usage = "usage: %prog\n"

    parser = optparse.OptionParser(usage=usage, prog='csops')

    return parser
