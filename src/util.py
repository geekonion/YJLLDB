# -*- coding: UTF-8 -*-

import lldb
import os
import xml.etree.ElementTree as ElementTree
from MachOHelper import get_entitlements
import subprocess

g_arm64_nop_bytes = b'\x1f\x20\x03\xd5'
g_x64_nops = {
    1: b'\x90',
    2: b'\x66\x90',
    3: b'\x0F\x1F\x00',
    4: b'\x0F\x1F\x40\x00',
    5: b'\x0F\x1F\x44\x00\x00',
    6: b'\x66\x0F\x1F\x44\x00\x00',
    7: b'\x0F\x1F\x80\x00\x00\x00\x00',
    8: b'\x0F\x1F\x84\x00\x00\x00\x00\x00',
    9: b'\x66\x0F\x1F\x84\x00\x00\x00\x00\x00',
}


def get_desc_for_address(addr, default_name=None, need_line=True):
    symbol = addr.GetSymbol()

    module = addr.GetModule()
    module_name = "unknown"
    if module:
        module_file_spec = module.GetFileSpec()
        module_name = module_file_spec.GetFilename()

    # 行号
    if need_line:
        line_entry = addr.GetLineEntry()
        if line_entry:
            file_spec = line_entry.GetFileSpec()
            file_name = file_spec.GetFilename()
            return "{}`{} at {}:{}:{}".format(module_name, symbol.GetName(), file_name, line_entry.GetLine(),
                                              line_entry.GetColumn())

    sym_name = symbol.GetName()
    if default_name and '___lldb_unnamed_symbol' in sym_name:
        sym_name = default_name

    return "{}`{}".format(module_name, sym_name)


def try_macho_address(addr, target, verbose, only_sec_name=False):
    return_desc = ""
    section = addr.GetSection()
    if not section.IsValid():
        return ""

    sec_name = section.GetName()
    if not only_sec_name:
        tmp_sec = section
        while tmp_sec.GetParent().IsValid():
            tmp_sec = tmp_sec.GetParent()
            sec_name = "{}.{}".format(tmp_sec.GetName(), sec_name)

        module = addr.GetModule()
        if module.IsValid():
            sec_name = "{}`{}".format(addr.GetModule().GetFileSpec().GetFilename(), sec_name)

        addr_offset = addr.GetLoadAddress(target) - section.GetLoadAddress(target)
        sec_name += " + {}".format(hex(addr_offset))

        symbol = addr.GetSymbol()
        #  Is it a known function?
        if symbol.IsValid():
            return_desc += "  {}    ".format(symbol.GetName())
            start_addr = symbol.GetStartAddress()

            # Symbol address offset, if any
            addr_offset = addr.GetLoadAddress(target) - start_addr.GetLoadAddress(target)
            return_desc += " <+{}>".format(addr_offset)

            # Mangled function
            if verbose:
                if symbol.GetMangledName():
                    return_desc += ", ({})".format(symbol.GetMangledName())

                return_desc += ", External: {}".format("YES" if symbol.IsSynthetic() else "NO")
    else:
        addr_offset = addr.GetLoadAddress(target) - section.GetLoadAddress(target)
        sec_name += " + {}".format(hex(addr_offset))

    return_desc += sec_name

    return return_desc


def exe_script(command_script):
    return exe_command('exp -l objc -O -- ' + command_script)


def exe_command(command, log=True):
    res = lldb.SBCommandReturnObject()
    interpreter = lldb.debugger.GetCommandInterpreter()
    interpreter.HandleCommand(command, res)

    if not res.Succeeded():
        if log:
            print('execute JIT code failed: \n{}'.format(res.GetError()))
        return ''

    response = res.GetOutput()

    response = response.strip()
    # 末尾有两个\n
    if response.endswith('\n\n'):
        response = response[:-2]
    # 末尾有一个\n
    if response.endswith('\n'):
        response = response[:-1]

    return response


def exe_shell_command(cmd, cwd=None):
    """
    执行命令，截获控制台输出
    """
    if "/usr/local/bin" not in os.environ["PATH"]:
        os.environ["PATH"] += os.pathsep + "/usr/local/bin/"

    comps = cmd.split(' ')
    prog = comps[0]
    if subprocess.call(["/usr/bin/which", prog], shell=False) != 0:
        print("Can't find {prog} in PATH or {prog} isn't installed\n"
              "you can determine this in LLDB via \""
              "(lldb) script import os; os.environ['PATH']\"\n"
              "You can persist this via "
              "(lldb) script os.environ['PATH'] += os.pathsep + /path/to/{prog}/folder".
              format(prog=prog))
        return -1, '', '{} not found'.format(prog)

    prog_path = subprocess.Popen(['/usr/bin/which', prog],
                                 shell=False,
                                 stdout=subprocess.PIPE).communicate()[0].rstrip(b'\n\r').decode()
    prog_path = prog_path.replace('//', '/')
    new_cmd = cmd.replace(prog, prog_path, 1)

    obj = subprocess.Popen(new_cmd, shell=True, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = obj.communicate()
    code = obj.wait()

    return code, out.decode(), err.decode()


def try_mkdir(dir_path):
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)


def is_x64():
    platform = lldb.debugger.GetSelectedPlatform()
    triple = platform.GetTriple()

    return triple and 'x86_64' in triple


def gen_nop(size):
    new_bytes = b''
    if is_x64():  # x86_64 ios-simulator
        loop_count = int(size / 4)
        for _ in range(loop_count):
            new_bytes += g_x64_nops[4]
        mod = size % 4
        if mod > 0:
            new_bytes += g_x64_nops[mod]
    else:
        loop_count = int(size / 4)
        for _ in range(loop_count):
            new_bytes += g_arm64_nop_bytes

    return new_bytes


def absolute_path(path_str):
    tmp_path = path_str.replace('\'', '')

    target_dir, rel_path = split_path(tmp_path)
    target_dir = target_dir.lower()
    is_full_path = False
    if target_dir in "bundle":
        full_path = get_bundle_directory()
        dir_type = "bundle"
    elif target_dir in "home":
        full_path = get_home_directory()
        dir_type = "home"
    elif target_dir in "doc":
        full_path = get_doc_directory()
        dir_type = "doc"
    elif target_dir in "lib":
        full_path = get_library_directory()
        dir_type = "lib"
    elif target_dir in "tmp":
        full_path = get_tmp_directory()
        dir_type = "tmp"
    elif target_dir in "caches":
        full_path = get_caches_directory()
        dir_type = "caches"
    elif target_dir in "group":
        full_path = get_group_path()
        dir_type = "group"
    else:
        # arg是经过小写处理的，不能直接使用
        full_path = path_str
        is_full_path = True
        dir_type = 'full'

    if not is_full_path and rel_path:
        full_path = os.path.join(full_path, rel_path)

    return full_path, dir_type


def split_path(path_str):
    if path_str.startswith('/'):
        path_str = path_str[1:]

    pos = path_str.find('/')
    if pos == -1:
        primary_dir = path_str
        rel_path = None
    elif pos == len(path_str) - 1:
        primary_dir = path_str[:-1]
        rel_path = None
    else:
        primary_dir = path_str[:pos]
        rel_path = path_str[pos + 1:]

    return primary_dir, rel_path


def get_bundle_directory():
    command_script = '@import Foundation;'
    command_script += r'''
    (NSString *)[(NSBundle *)[NSBundle mainBundle] bundlePath];
    '''
    ret_str = exe_script(command_script)

    return ret_str


def get_home_directory():
    command_script = '@import Foundation;'
    command_script += r'''
    (NSString *)NSHomeDirectory();
    '''
    ret_str = exe_script(command_script)

    return ret_str


def get_doc_directory():
    command_script = '@import Foundation;'
    command_script += r'''
    (NSString *)[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    '''
    ret_str = exe_script(command_script)

    return ret_str


def get_library_directory():
    command_script = '@import Foundation;'
    command_script += r'''
    (NSString *)[NSHomeDirectory() stringByAppendingPathComponent:@"Library"];
    '''
    ret_str = exe_script(command_script)

    return ret_str


def get_tmp_directory():
    command_script = '@import Foundation;'
    command_script += r'''
    (NSString *)[NSHomeDirectory() stringByAppendingPathComponent:@"tmp"];
    '''
    ret_str = exe_script(command_script)

    return ret_str


def get_caches_directory():
    command_script = '@import Foundation;'
    command_script += r'''
    (NSString *)[NSHomeDirectory() stringByAppendingPathComponent:@"Library/Caches"];
    '''
    ret_str = exe_script(command_script)

    return ret_str


def get_group_path():
    target = lldb.debugger.GetSelectedTarget()
    module_name = target.GetExecutable().GetFilename()
    entitlements = get_entitlements(module_name)
    if not entitlements:
        return entitlements
    elif 'does not contain' in entitlements:
        return entitlements

    ent_dict = parse_info_plist(entitlements)
    group_ids = ent_dict.get('com.apple.security.application-groups')
    ret_str = ''
    if group_ids:
        for group_id in group_ids:
            command_script = '@import Foundation;'
            command_script += 'NSString *groupID = @"' + group_id + '";'
            command_script += r'''
            NSString *result = [(NSURL *)[[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:groupID] path];
            result = [groupID stringByAppendingFormat:@": %@", result];

            result;
            '''
            ret_str += exe_script(command_script) + '\n'
    else:
        ret_str = 'group id not found'

    return ret_str


def read_mem_as_cstring(target, start_addr, addr_size, encoding='utf-8'):
    ret = ''

    error = lldb.SBError()
    data_bytes = target.ReadMemory(lldb.SBAddress(start_addr, target), addr_size, error)
    if not error.Success():
        ret += 'read memory at 0x{:x} failed! {}'.format(start_addr, error.GetCString())
        return ret

    string_list = data_bytes.decode(encoding).replace('\n', '\\n').split('\x00')[:-1]
    offset = 0
    for string in string_list:
        str_addr = start_addr + offset
        ret += '0x{:x}: "{}"\n'.format(str_addr, string)
        offset += 1 + len(string)

    ret += '{} locations found'.format(len(string_list))

    return ret


def find_c_string_from_mem_region(target, start_addr, addr_size, keyword, encoding='utf-8'):
    ret = -1

    error = lldb.SBError()
    data_bytes = target.ReadMemory(lldb.SBAddress(start_addr, target), addr_size, error)
    if not error.Success():
        print('read memory at 0x{:x} failed! {}'.format(start_addr, error.GetCString()))
        return ret

    keyword_bytes = keyword.encode()
    if not keyword_bytes.endswith(b'\0'):
        keyword_bytes += b'\0'

    pos = data_bytes.find(keyword_bytes)
    if pos != -1:
        ret = start_addr + pos

    return ret


# def parse_info_plist_demo():
#     info_plist = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>BuildMachineOSBuild</key><string>23C71</string><key>CFBundleDevelopmentRegion</key><string>en</string><key>CFBundleExecutable</key><string>JITDemo</string><key>CFBundleIdentifier</key><string>com.bangcle.LLDBCode</string><key>CFBundleInfoDictionaryVersion</key><string>6.0</string><key>CFBundleName</key><string>JITDemo</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleShortVersionString</key><string>1.0</string><key>CFBundleSupportedPlatforms</key><array><string>iPhoneOS</string></array><key>CFBundleVersion</key><string>1</string><key>DTCompiler</key><string>com.apple.compilers.llvm.clang.1_0</string><key>DTPlatformBuild</key><string>21C52</string><key>DTPlatformName</key><string>iphoneos</string><key>DTPlatformVersion</key><string>17.2</string><key>DTSDKBuild</key><string>21C52</string><key>DTSDKName</key><string>iphoneos17.2</string><key>DTXcode</key><string>1510</string><key>DTXcodeBuild</key><string>15C65</string><key>LSRequiresIPhoneOS</key><true/><key>MinimumOSVersion</key><string>11.0</string><key>UIApplicationSceneManifest</key><dict><key>UIApplicationSupportsMultipleScenes</key><false/><key>UISceneConfigurations</key><dict><key>UIWindowSceneSessionRoleApplication</key><array><dict><key>UISceneConfigurationName</key><string>Default Configuration</string><key>UISceneDelegateClassName</key><string>SceneDelegate</string><key>UISceneStoryboardFile</key><string>Main</string></dict></array></dict></dict><key>UIApplicationSupportsIndirectInputEvents</key><true/><key>UIDeviceFamily</key><array><integer>1</integer><integer>2</integer></array><key>UILaunchStoryboardName</key><string>LaunchScreen</string><key>UIMainStoryboardFile</key><string>Main</string><key>UIRequiredDeviceCapabilities</key><array><string>arm64</string></array><key>UISupportedInterfaceOrientations~ipad</key><array><string>UIInterfaceOrientationPortrait</string><string>UIInterfaceOrientationPortraitUpsideDown</string><string>UIInterfaceOrientationLandscapeLeft</string><string>UIInterfaceOrientationLandscapeRight</string></array><key>UISupportedInterfaceOrientations~iphone</key><array><string>UIInterfaceOrientationPortrait</string><string>UIInterfaceOrientationLandscapeLeft</string><string>UIInterfaceOrientationLandscapeRight</string></array></dict></plist>'
#     info_dict = util.parse_info_plist(info_plist)
#     info_json = json.dumps(info_dict, indent=2)
#     print(info_json)


def parse_info_plist(input_str):
    xml_dict = None
    root = ElementTree.fromstring(input_str)
    for element in root:
        if element.tag == 'dict':
            xml_dict = xml_to_obj(element)

    return xml_dict


def xml_to_obj(element):
    obj = None
    # print("1 tag {}, text {}, attr {}".format(element.tag, element.text, element.attrib))
    if element.tag == 'dict':
        tmp_dict = {}
        key = None
        for child in element:
            # print("2 tag {}, text {}, attr {}".format(child.tag, child.text, child.attrib))
            if child.tag == 'key':
                key = child.text
            elif child.tag == 'string':
                tmp_dict[key] = child.text
            elif child.tag == 'integer':
                tmp_dict[key] = child.text
            elif child.tag == 'true':
                tmp_dict[key] = True
            elif child.tag == 'false':
                tmp_dict[key] = False
            elif child.tag == 'dict':
                tmp_dict[key] = xml_to_obj(child)
            elif child.tag == 'array':
                tmp_dict[key] = xml_to_obj(child)
            else:
                print("dict need parse tag {}, text {}, attr {}".format(child.tag, child.text, child.attrib))
                key = None

        obj = tmp_dict
    elif element.tag == 'array':
        tmp_array = []
        for child in element:
            # print("3 tag {}, text {}, attr {}".format(child.tag, child.text, child.attrib))
            if child.tag == 'string':
                tmp_array.append(child.text)
            elif child.tag == 'integer':
                tmp_array.append(child.text)
            elif child.tag == 'dict':
                tmp_array.append(xml_to_obj(child))
            else:
                print("array need parse tag {}, text {}, attr {}".format(child.tag, child.text, child.attrib))
        obj = tmp_array
    else:
        print("other need parse tag {}, text {}, attr {}".format(element.tag, element.text, element.attrib))

    return obj


def parse_arg(name_or_var_or_addr):
    cmd_ret = exe_command('p/x {}'.format(name_or_var_or_addr), False)
    is_addr_or_var = len(cmd_ret) > 0

    # 16进制地址
    is_addr = name_or_var_or_addr.startswith("0x")
    # 变量名
    if is_addr_or_var and not is_addr:
        pos = cmd_ret.find('0x')
        if pos >= 0:
            addr_str = cmd_ret[pos:]
        else:
            addr_str = cmd_ret
        name_or_var_or_addr = addr_str
        is_addr = name_or_var_or_addr.startswith("0x")

    return is_addr, name_or_var_or_addr


def get_wifi_ip_address():
    command_script = '@import Foundation;'
    command_script += 'BOOL useIPv6 = NO;'

    command_script += r'''
    NSString *address = @"";
    const char *primaryInterface = "en0";  // WiFi interface on iOS
    
    struct ifaddrs *list;
    if ((int)getifaddrs(&list) >= 0) {
        for (struct ifaddrs *ifap = list; ifap; ifap = ifap->ifa_next) {
            if (strcmp(ifap->ifa_name, primaryInterface)) {
                continue;
            }
            // #define IFF_UP          0x1
            // #define AF_INET         2
            // #define AF_INET6        30
            if ((ifap->ifa_flags & 0x1/*IFF_UP*/) && ((!useIPv6 && (ifap->ifa_addr->sa_family == 2/*AF_INET*/)) || (useIPv6 && (ifap->ifa_addr->sa_family == 30/*AF_INET6*/)))) {
                const struct sockaddr *addr = ifap->ifa_addr;
                BOOL includeService = NO;
                // #define    NI_MAXHOST    1025
                // #define    NI_MAXSERV    32
                char hostBuffer[1025/*NI_MAXHOST*/] = {};
                char serviceBuffer[32/*NI_MAXSERV*/] = {};
                // #define    NI_NUMERICHOST    0x00000002
                // #define    NI_NUMERICSERV    0x00000008
                // #define    NI_NOFQDN    0x00000001
                if ((int)getnameinfo(addr, addr->sa_len, hostBuffer, sizeof(hostBuffer), serviceBuffer, sizeof(serviceBuffer), 0x00000002/*NI_NUMERICHOST*/ | 0x00000008/*NI_NUMERICSERV*/ | 0x00000001/*NI_NOFQDN*/) != 0) {
                    address = @"";
                } else {
                    address = includeService ? [NSString stringWithFormat:@"%s:%s", hostBuffer, serviceBuffer] : (NSString*)[NSString stringWithUTF8String:hostBuffer];
                }
                
                break;
            }
        }
    }
    
    freeifaddrs(list);
    
    address;
    '''
    ret_str = exe_script(command_script)

    return ret_str
