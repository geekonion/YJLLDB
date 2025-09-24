# -*- coding: UTF-8 -*-

import lldb
import os
import json

g_file_path = os.path.realpath(__file__)
g_dir_name = os.path.dirname(os.path.dirname(g_file_path))
g_caches_dir = os.path.join(g_dir_name, 'Caches')


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "save breakpoints set by address" -f '
        'BreakpointSaveAndRestore.save_breakpoints bsave')

    debugger.HandleCommand(
        'command script add -h "restore breakpoints from cache file" -f '
        'BreakpointSaveAndRestore.restore_breakpoints bload')

    debugger.HandleCommand(
        'command script add -h "clear unresolved breakpoints" -f '
        'BreakpointSaveAndRestore.clear_breakpoints bclear')


def save_breakpoints(debugger, command, result, internal_dict):
    """
    save breakpoints set by address
    implemented in YJLLDB/src/BreakpointSaveAndRestore.py
    """
    target = debugger.GetSelectedTarget()

    brk_list = {}
    for brk in target.breakpoint_iter():
        brk_des = str(brk)
        # 符号断点
        if 'name = ' in brk_des:
            continue

        # 和源码能对应的，Xcode会自己处理
        if 'file = ' in brk_des:
            continue

        loc = brk.GetLocationAtIndex(0)
        addr_obj = loc.GetAddress()
        module = addr_obj.GetModule()
        if not module:
            print('module for breakpoint not found: {}'.format(brk))
            continue

        module_name = module.GetFileSpec().GetFilename()
        uuid = module.GetUUIDString()
        key = module_name + "#" + uuid
        brks = brk_list.get(key)
        if not brks:
            brks = []
            brk_list[key] = brks

        module_addr = module.GetSectionAtIndex(0).GetLoadAddress(target)
        brk_info = {
            "addr": '{:#x}'.format(addr_obj.GetLoadAddress(target) - module_addr),
            "enabled": brk.IsEnabled(),
            "autoContinue": brk.GetAutoContinue()
        }

        ignore_count = brk.GetIgnoreCount()
        if ignore_count:
            brk_info["ignoreCount"] = ignore_count

        condition = brk.GetCondition()
        if condition:
            brk_info["condition"] = condition

        thread_id = brk.GetThreadIndex()
        if 0 < thread_id < 0xffffffff:
            brk_info["threadID"] = thread_id

        string_list = lldb.SBStringList()
        success = brk.GetCommandLineCommands(string_list)
        if success:
            cmds = []
            for idx in range(string_list.GetSize()):
                cmds.append(string_list.GetStringAtIndex(idx))

            brk_info["cmds"] = cmds

        brks.append(brk_info)

    if len(brk_list):
        target_name = target.GetExecutable().GetFilename()
        filepath = os.path.join(g_caches_dir, target_name + ".json")
        with open(filepath, "w") as cache_file:
            json.dump(brk_list, cache_file, indent=4)
            print(f"Breakpoints saved to {filepath}")

        # print(json.dumps(brk_list, indent=4))


def restore_breakpoints(debugger, command, result, internal_dict):
    """
    restore breakpoints from cache file
    implemented in YJLLDB/src/BreakpointSaveAndRestore.py
    """
    target = debugger.GetSelectedTarget()
    target_name = target.GetExecutable().GetFilename()
    filepath = os.path.join(g_caches_dir, target_name + ".json")

    current_brk_list = []
    for brk in target.breakpoint_iter():
        brk_des = str(brk)
        if 'name = ' in brk_des:
            continue

        loc = brk.GetLocationAtIndex(0)
        addr = loc.GetAddress().GetLoadAddress(target)
        current_brk_list.append(addr)

    # create breakpoints with info from the file
    brk_list = load_json_from_file(filepath)
    if not brk_list:
        return

    for key in brk_list.keys():
        comps = key.split("#")
        name = comps[0]

        module = find_module_by_name(target, name)
        if not module:
            print('Module {} not found'.format(name))
            continue

        uuid = comps[1]
        if module.GetUUIDString() != uuid:
            print('Module mismatch detected {}'.format(name))
            continue

        module_addr = module.GetSectionAtIndex(0).GetLoadAddress(target)

        for brk_info in brk_list[key]:
            load_addr = module_addr + int(brk_info['addr'], 16)
            if load_addr in current_brk_list:
                print('A breakpoint at address {:#x} already exists'.format(load_addr))
                continue

            addr_obj = lldb.SBAddress(load_addr, target)
            brkpoint = target.BreakpointCreateBySBAddress(addr_obj)
            # 判断下断点是否成功
            if not brkpoint.IsValid() or brkpoint.num_locations == 0:
                print("Breakpoint isn't valid or hasn't found any hits")
                continue

            brkpoint.SetEnabled(brk_info["enabled"])
            for idx in range(brkpoint.GetNumLocations()):
                loc = brkpoint.GetLocationAtIndex(idx)
                loc.SetEnabled(True)

            brkpoint.SetAutoContinue(brk_info["autoContinue"])

            ignore_count = brk_info.get("ignoreCount")
            if ignore_count:
                brkpoint.SetIgnoreCount(ignore_count)

            condition = brk_info.get("condition")
            if condition:
                brkpoint.SetCondition(condition)

            thread_id = brk_info.get("threadID")
            if thread_id and 0 < thread_id < 0xffffffff:
                brkpoint.SetThreadIndex(thread_id)

            cmds = brk_info.get("cmds")
            if cmds:
                string_list = lldb.SBStringList()
                for cmd in cmds:
                    string_list.AppendString(cmd)

                brkpoint.SetCommandLineCommands(string_list)

            print("Breakpoint {}: where = {}, address = {:#x}"
                  .format(brkpoint.GetID(), addr_obj, load_addr))


def find_module_by_name(target, name):
    target_module = None
    for module in target.module_iter():
        mod_spec = module.GetFileSpec()
        module_name = mod_spec.GetFilename()
        if module_name == name:
            target_module = module
            break

    return target_module


def load_json_from_file(filename):
    try:
        with open(filename, "r") as f:
            data = json.load(f)  # 直接解析 JSON 文件
            return data
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in '{filename}'.")

    return None


def clear_breakpoints(debugger, command, result, internal_dict):
    """
    clear unresolved breakpoints
    implemented in YJLLDB/src/BreakpointSaveAndRestore.py
    """
    target = debugger.GetSelectedTarget()

    nbrk = target.GetNumBreakpoints()
    for idx in range(nbrk - 1, -1, -1):
        brk = target.GetBreakpointAtIndex(idx)
        brk_des = str(brk)
        if 'name = ' in brk_des:
            continue

        if not brk.IsEnabled():
            continue

        nloc = brk.GetNumLocations()
        if nloc > 1:
            continue

        loc = brk.GetLocationAtIndex(0)
        if not loc.IsResolved():
            print("delete unresolved breakpoint {}: at {}".
                  format(brk.GetID(), loc.GetAddress()))
            target.BreakpointDelete(brk.GetID())
    