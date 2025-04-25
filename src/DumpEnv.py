# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import util

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "dump env" -f '
        'DumpEnv.dump_env denv')


def dump_env(debugger, command, result, internal_dict):
    """
    dump env
    implemented in YJLLDB/src/DumpEnv.py
    """

    command_script = r'''
    extern char ***_NSGetArgv(void);
    extern int *_NSGetArgc(void);
    
    NSMutableString *ret_envs = [NSMutableString string];
    char ***e_argv = _NSGetArgv();
    int *e_argc = _NSGetArgc();
    if (e_argv) {
        char **e_tmp = *e_argv;
        char **e_envs = e_tmp + *e_argc + 1;
        while (*e_envs) {
            char *tmp_env = *e_envs;
            [ret_envs appendString:(NSString *)[NSString stringWithUTF8String:tmp_env]];
            [ret_envs appendString:@"\n"];
            
            e_envs++;
        }
        
        // 跳过中间空隙
        while (!*e_envs) {
            e_envs++;
        }
        
        [ret_envs appendString:@"\t\nhidden envs:\n"];
        while (*e_envs) {
            char *tmp_env = *e_envs;
            [ret_envs appendString:(NSString *)[NSString stringWithUTF8String:tmp_env]];
            [ret_envs appendString:@"\n"];
            
            e_envs++;
        }
    }
    
    ret_envs;
    '''

    debugger.HandleCommand("exp -l objc -O -- " + command_script)


def generate_option_parser():
    usage = "usage: %prog\n"

    parser = optparse.OptionParser(usage=usage, prog='denv')

    return parser
