# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import util
import tempfile
import os


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -h "Convert assembly instructions to machine code."'
                           ' -f InstructionsAndBytes.instructions_to_bytes inst2bytes')

    debugger.HandleCommand('command script add -h "Convert machine code to assembly instructions"'
                           ' -f InstructionsAndBytes.bytes_to_instructions bytes2inst')


def instructions_to_bytes(debugger, command, result, internal_dict):
    """
    Convert assembly instructions to bytes.
    implemented in YJLLDB/src/InstructionsAndBytes.py
    """
    # 去掉转义符
    command = command.replace('\\', '\\\\')
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command_args = shlex.split(command, posix=False)
    # 创建parser
    parser = generate_option_parser('instructions_to_bytes', '<A sequence of instructions separated by semicolons>')

    # 解析参数，捕获异常
    try:
        # options是所有的选项，key-value形式，args是其余剩余所有参数，不包含options
        (options, args) = parser.parse_args(command_args)
    except Exception as error:
        print(error)
        result.SetError("\n" + parser.get_usage())
        return

    if len(args) != 1:
        print(parser.get_usage())
        return

    insts_str = args[0]
    insts_str = insts_str.replace("'", "")
    insts_str = insts_str.replace('"', "")
    insts_str = insts_str.replace(';', "\n")

    tmp_dir = tempfile.gettempdir()
    tmp_input_file = os.path.join(tmp_dir, 'yj_assembly.s')
    tmp_output_file = os.path.join(tmp_dir, 'yj_assembly.o')
    with open(tmp_input_file, 'w+') as x_file:
        x_file.write(insts_str)
        x_file.flush()

        x_file.close()

    target = debugger.GetSelectedTarget()
    file_spec = target.GetExecutable()
    module = target.FindModule(file_spec)
    triple = module.GetTriple()
    pos = triple.find('-')
    arch = triple[:pos]

    code, out, err = util.exe_shell_command('clang -c {} -arch {} -o {} && objdump -d {}'.
                                            format(tmp_input_file, arch, tmp_output_file, tmp_output_file))
    if err:
        result.SetError(err)
        return

    keyword = '0000000000000000 <ltmp0>:\n'
    pos = out.find(keyword)
    bytes_str = ''
    if pos > 0:
        insts_str = out[pos + len(keyword):]
        result.AppendMessage('disassembly: \n')
        insts = insts_str.split('\n')
        for inst in insts:
            open_angle_pos = inst.find('<')
            if open_angle_pos > 0:
                inst = inst[:open_angle_pos]

            result.AppendMessage(inst)

            inst = inst.lstrip(' ')
            pos1 = inst.find(':')
            pos2 = inst.find('\t', pos1)
            m_code = inst[pos1 + 2: pos2]
            bytes_data = bytes.fromhex(m_code)
            reversed_bytes = bytes_data[::-1]
            bytes_str += reversed_bytes.hex()

    result.AppendMessage('machine code: {}'.format(bytes_str))

    os.remove(tmp_input_file)
    if os.path.exists(tmp_output_file):
        os.remove(tmp_output_file)


def bytes_to_instructions(debugger, command, result, internal_dict):
    """
    Convert bytes to assembly instructions.
    implemented in YJLLDB/src/InstructionsAndBytes.py
    """
    # 去掉转义符
    command = command.replace('\\', '\\\\')
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command_args = shlex.split(command, posix=False)
    # 创建parser
    parser = generate_option_parser('bytes_to_instructions', '<A sequence of machine code>')

    # 解析参数，捕获异常
    try:
        # options是所有的选项，key-value形式，args是其余剩余所有参数，不包含options
        (options, args) = parser.parse_args(command_args)
    except Exception as error:
        print(error)
        result.SetError("\n" + parser.get_usage())
        return

    if len(args) != 1:
        print(parser.get_usage())
        return

    bytes_str = ''.join(args)
    bytes_str = bytes_str.replace("'", "")
    bytes_str = bytes_str.replace('"', "")
    bytes_str = bytes_str.replace(';', "\n")

    input_bytes = bytes.fromhex(bytes_str)
    bytes_size = len(input_bytes)
    if bytes_size % 4 != 0:
        print('The number of bytes must be an integer multiple of 4')
        return

    target = debugger.GetSelectedTarget()
    file_spec = target.GetExecutable()
    module = target.FindModule(file_spec)
    seg = module.FindSection('__TEXT')
    sec_text = None
    for sec in seg:
        sec_name = sec.GetName()
        if sec_name == '__text':
            sec_text = sec
            break
    if sec_text:
        sec_addr = sec_text.GetLoadAddress(target)
        sec_addr_obj = lldb.SBAddress(sec_addr, target)
        error = lldb.SBError()
        old_data = target.ReadMemory(sec_addr_obj, bytes_size, error)
        if not error.Success():
            print('read __text data failed!')
            return

        process = target.GetProcess()
        serr = lldb.SBError()
        n_bytes = process.WriteMemory(sec_addr, input_bytes, serr)
        if not serr.Success() or n_bytes != bytes_size:
            print('write data to __text failed!')
            return

        ninst = int(bytes_size / 4)
        insts = target.ReadInstructions(sec_addr_obj, ninst)
        for idx, inst in enumerate(insts):
            mnemonic = inst.GetMnemonic(target)
            operands = inst.GetOperands(target)
            print('<+{}>:\t{}\t{}'.format(idx * 4, mnemonic, operands))

        n_bytes = process.WriteMemory(sec_addr, old_data, serr)
        if not serr.Success() or n_bytes != bytes_size:
            print('restore data to __text failed!')
            return


def generate_option_parser(prog, info):
    usage = "usage: %prog " + info + '\n'

    parser = optparse.OptionParser(usage=usage, prog=prog)

    return parser
