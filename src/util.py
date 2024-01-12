# -*- coding: UTF-8 -*-

import json
import shlex
import lldb
import os
import xml.etree.ElementTree as ElementTree

g_byteorder = 'little'
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


def try_macho_address(addr, target, only_sec_name=False):
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
            if options.verbose:
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


def exe_command(command):
    res = lldb.SBCommandReturnObject()
    interpreter = lldb.debugger.GetCommandInterpreter()
    interpreter.HandleCommand(command, res)

    if not res.HasResult():
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
    command_script = '@import Foundation;'
    command_script += r'''
    struct mach_header_64 {
        uint32_t    magic;        /* mach magic number identifier */
        int32_t        cputype;    /* cpu specifier */
        int32_t        cpusubtype;    /* machine specifier */
        uint32_t    filetype;    /* type of file */
        uint32_t    ncmds;        /* number of load commands */
        uint32_t    sizeofcmds;    /* the size of all the load commands */
        uint32_t    flags;        /* flags */
        uint32_t    reserved;    /* reserved */
    };

    struct segment_command_64 { /* for 64-bit architectures */
        uint32_t    cmd;        /* LC_SEGMENT_64 */
        uint32_t    cmdsize;    /* includes sizeof section_64 structs */
        char        segname[16];    /* segment name */
        uint64_t    vmaddr;        /* memory address of this segment */
        uint64_t    vmsize;        /* memory size of this segment */
        uint64_t    fileoff;    /* file offset of this segment */
        uint64_t    filesize;    /* amount to map from the file */
        int32_t        maxprot;    /* maximum VM protection */
        int32_t        initprot;    /* initial VM protection */
        uint32_t    nsects;        /* number of sections in segment */
        uint32_t    flags;        /* flags */
    };
    #ifdef __LP64__
    typedef struct mach_header_64 mach_header_t;
    #else
    typedef struct mach_header mach_header_t;
    #endif

    struct CS_Blob {
        uint32_t magic;                 // magic number
        uint32_t length;                // total length of blob
    };

    struct CS_BlobIndex {
        uint32_t type;                  // type of entry
        uint32_t offset;                // offset of entry
    };

    struct CS_SuperBlob {
        uint32_t magic;                 // magic number
        uint32_t length;                // total length of SuperBlob
        uint32_t count;                 // number of index entries following
        struct CS_BlobIndex index[];           // (count) entries
        // followed by Blobs in no particular order as indicated by offsets in index
    };
    struct load_command {
        uint32_t cmd;		/* type of load command */
        uint32_t cmdsize;	/* total size of command in bytes */
    };
    struct linkedit_data_command {
        uint32_t	cmd;		/* LC_CODE_SIGNATURE, LC_SEGMENT_SPLIT_INFO,
                       LC_FUNCTION_STARTS, LC_DATA_IN_CODE,
                       LC_DYLIB_CODE_SIGN_DRS,
                       LC_LINKER_OPTIMIZATION_HINT,
                       LC_DYLD_EXPORTS_TRIE, or
                       LC_DYLD_CHAINED_FIXUPS. */
        uint32_t	cmdsize;	/* sizeof(struct linkedit_data_command) */
        uint32_t	dataoff;	/* file offset of data in __LINKEDIT segment */
        uint32_t	datasize;	/* file size of data in __LINKEDIT segment  */
    };
    '''
    command_script += r'''
    char *groupID_c = NULL;
    const mach_header_t *mach_header = NULL;

    NSString *exe_name = [[[NSBundle mainBundle] executablePath] lastPathComponent];
    uint32_t image_count = (uint32_t)_dyld_image_count();
    intptr_t slide       = 0;
    for (uint32_t i = 0; i < image_count; i++) {
        const char *name = (const char *)_dyld_get_image_name(i);
        if (!name) {
            continue;
        }

        NSString *module_name = [[NSString stringWithUTF8String:name] lastPathComponent];
        if ([module_name isEqualToString:exe_name]) {
            mach_header = (const mach_header_t *)_dyld_get_image_header(i);
            slide = (intptr_t)_dyld_get_image_vmaddr_slide(i);
            break;
        }
    }

    uint32_t header_magic = mach_header->magic;
    if (header_magic == 0xfeedfacf) { //MH_MAGIC_64
        uint32_t ncmds = mach_header->ncmds;
        if (ncmds > 0) {
            struct load_command *lc = (struct load_command *)((char *)mach_header + sizeof(mach_header_t));
            struct linkedit_data_command *lc_signature = NULL;
            uint64_t file_offset = 0;
            uint64_t vmaddr      = 0;
            BOOL sig_found = NO;
            for (uint32_t i = 0; i < ncmds; i++) {
                if (lc->cmd == 0x19) { // LC_SEGMENT_64
                    struct segment_command_64 *seg = (struct segment_command_64 *)lc;
                    if (strcmp(seg->segname, "__LINKEDIT") == 0) { //SEG_LINKEDIT
                        file_offset = seg->fileoff;
                        vmaddr      = seg->vmaddr;
                    }
                } else if (lc->cmd == 0x1d) { //LC_CODE_SIGNATURE
                    lc_signature = (struct linkedit_data_command *)lc;
                }
                lc = (struct load_command *)((char *)lc + lc->cmdsize);
            }
            if (lc_signature) {
                sig_found = YES;
                char *sign_ptr = (char *)vmaddr + lc_signature->dataoff - file_offset + slide;
#if __arm64e__
                void *sign = (void *)ptrauth_strip(sign_ptr, ptrauth_key_function_pointer);
#else
                void *sign = (void *)sign_ptr;
#endif

                struct CS_SuperBlob *superBlob = (struct CS_SuperBlob *)sign;
                uint32_t super_blob_magic = _OSSwapInt32(superBlob->magic);
                if (super_blob_magic == 0xfade0cc0) { //CSMAGIC_EMBEDDED_SIGNATURE
                    uint32_t nblob = _OSSwapInt32(superBlob->count);

                    struct CS_BlobIndex *index = superBlob->index;
                    for ( int i = 0; i < nblob; ++i ) {
                        struct CS_BlobIndex blobIndex = index[i];
                        uint32_t offset = _OSSwapInt32(blobIndex.offset);

                        uint32_t *blobAddr = (__uint32_t *)((char *)sign + offset);

                        struct CS_Blob *blob = (struct CS_Blob *)blobAddr;
                        uint32_t magic = _OSSwapInt32(blob->magic);
                        if ( magic == 0xfade7171 ) { //kSecCodeMagicEntitlement
                            uint32_t header_len = 8;
                            uint32_t length = _OSSwapInt32(blob->length) - header_len;
                            if (length <= 0) {
                                break;
                            }
                            const char *mem_start = (char *)blobAddr + header_len;
                            const char *keyword = "com.apple.security.application-groups";
                            char *group_key = (char *)memmem(mem_start, length, keyword, strlen(keyword));
                            if (!group_key) {
                                break;
                            }

                            const char *prefix = "<string>";
                            size_t prefix_len = strlen(prefix);
                            length -= (uint32_t)(group_key - mem_start);
                            char *group_start = (char *)memmem(group_key, length, prefix, prefix_len);
                            if (!group_start) {
                                break;
                            }
                            group_start += prefix_len;
                            length -= prefix_len;
                            const char *suffix = "</string>";
                            char *group_end = (char *)memmem(group_start, length, suffix, strlen(suffix));
                            if (!group_end) {
                                break;
                            }

                            long len = group_end - group_start;
                            groupID_c = (char *)calloc(len + 1, sizeof(char));
                            if (groupID_c) {
                                memcpy(groupID_c, group_start, len);
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    NSString *result = nil;
    if (groupID_c) {
        NSString *groupID = [NSString stringWithUTF8String:groupID_c];
        free(groupID_c);
        result = [(NSURL *)[[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:groupID] path];
        result = [groupID stringByAppendingFormat:@": %@", result];
    }
    result;
    '''
    ret_str = exe_script(command_script)

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


def get_int(base, offset, byteorder=None):
    if byteorder:
        return int.from_bytes(base[offset:offset + 4], byteorder=byteorder)
    else:
        return int.from_bytes(base[offset:offset + 4], byteorder=g_byteorder)


def get_long(base, offset, byteorder=None):
    if byteorder:
        return int.from_bytes(base[offset:offset + 8], byteorder=byteorder)
    else:
        return int.from_bytes(base[offset:offset + 8], byteorder=g_byteorder)


def get_string(base, offset, length=0):
    if length == 0:
        pos = base.find(b'\x00', offset)
        length = pos - offset
    return base[offset:offset + length].strip(b'\x00').decode()


def swap32(num):
    return (((num << 24) & 0xFF000000) |
            ((num << 8) & 0x00FF0000) |
            ((num >> 8) & 0x0000FF00) |
            ((num >> 24) & 0x000000FF))


def get_cs_super_blob(base, offset, byteorder=None):
    magic = swap32(get_int(base, offset, byteorder))
    length = get_int(base, offset + 4, byteorder)
    count = swap32(get_int(base, offset + 8, byteorder))

    return magic, length, count


def get_cs_blob_index(base, offset, byteorder=None):
    data_type = get_int(base, offset, byteorder)
    data_offset = swap32(get_int(base, offset + 4, byteorder))

    return data_type, data_offset


def get_cs_blob(base, offset, byteorder=None):
    magic = swap32(get_int(base, offset, byteorder))
    length = swap32(get_int(base, offset + 4, byteorder))

    return magic, length


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
