# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import util


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "read memory region with JIT code" -f '
        'ReadMemory.read_memory_as_hex jit_mem')


def read_memory_as_hex(debugger, command, result, internal_dict):
    """
    read memory region with JIT code
    implemented in YJLLDB/src/ReadMemory.py
    """
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

    if len(args) != 2:
        result.AppendMessage(parser.get_usage())
        return

    start_addr = args[0]
    size = args[1]

    ret = jit_read_memory(start_addr, size)

    result.AppendMessage(ret)


def jit_read_memory(start_addr, size):
    """
    给+[Checker checkModule:slide:name:dsc:]起始地址下断点
    分别使用dis和x命令读取内存
    再使用hex_mem读取内存
    可以看出lldb对下断点的地方进行了处理，返回的是函数原来的字节，而真是的字节是断点

    (lldb) dis -a 0x1025f4f6c -c 2
    AntiDebug`+[Checker checkModule:slide:name:dsc:]:
    ->  0x1025f4f6c <+0>: sub    sp, sp, #0x110
        0x1025f4f70 <+4>: stp    x28, x27, [sp, #0xf0]
    (lldb) x 0x1025f4f6c -c 8
    0x1025f4f6c: ff 43 04 d1 fc 6f 0f a9                          .C...o..

    (lldb) hex_mem 0x1025f4f6c 8
    0x1025f4f6c: 00 00 20 d4 fc 6f 0f a9                          .....o..
    (lldb) bytes2inst '00 00 20 d4'
    <+0>:	brk	#0

    """
    command_script = '@import Foundation;'
    command_script += 'const unsigned char *startAddr = (const unsigned char *){};'.format(start_addr)
    command_script += 'const unsigned char *size = (const unsigned char *){};'.format(size)
    command_script += r'''
    NSMutableString *hex_string = [NSMutableString string];

    NSMutableString *suffix = [NSMutableString stringWithCapacity:16];
    int len = 0;
    while (len < size) {
        if (len % 16 == 0) {
            [hex_string appendFormat:@"%p: ", startAddr + len];
        }
        unsigned char ch = startAddr[len];
        [hex_string appendFormat:@"%02x ", ch];
        if (isgraph(ch)) {
            [suffix appendFormat:@"%c", ch];
        } else {
            [suffix appendString:@"."];
        }
        
        len++;
        
        if (len % 16 == 0) {
            [hex_string appendFormat:@" %@\n", suffix];
            [suffix deleteCharactersInRange:NSMakeRange(0, suffix.length)];
        }
    }
    int mod = len % 16;
    if (mod) {
        int count = 16 - mod;
        for (int i = 0; i < count; i++) {
            [hex_string appendString:@"   "];
        }
        
        [hex_string appendFormat:@" %@\n", suffix];
    }
    
    hex_string;
    '''
    ret_str = util.exe_script(command_script)

    return ret_str


def generate_option_parser():
    usage = "usage: %prog start_addr size"

    parser = optparse.OptionParser(usage=usage, prog='jit_mem')

    return parser
