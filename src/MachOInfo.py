# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import util
import MachO
import json
import MachOHelper


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -h "print codesign entitlements of the specified module if any."'
                           ' -f MachOInfo.show_entitlements entitlements')

    debugger.HandleCommand('command script add -h "print group id in codesign entitlements of the specified '
                           'module if any." -f MachOInfo.show_group_id group_id')

    debugger.HandleCommand('command script add -h "print bundle id in codesign entitlements of the specified '
                           'module if any." -f MachOInfo.show_bundle_id bundle_id')

    debugger.HandleCommand('command script add -h "print team id in codesign entitlements of the specified '
                           'module if any." -f MachOInfo.show_team_id team_id')

    debugger.HandleCommand(
        'command script add -h "print executable name."'
        ' -f MachOInfo.show_executable_name executable')

    debugger.HandleCommand('command script add -h "parse mach-o of user modules." -f MachOInfo.parse_macho macho')


def show_entitlements(debugger, command, result, internal_dict):
    """
    print codesign entitlements of the specified module if any.
    implemented in YJLLDB/src/MachOInfo.py
    """
    result.AppendMessage(parse_entitlements(debugger, command, result, 'entitlements'))


def show_group_id(debugger, command, result, internal_dict):
    """
    print group id in codesign entitlements of the specified module if any.
    implemented in YJLLDB/src/MachOInfo.py
    """
    result.AppendMessage(parse_entitlements(debugger, command, result, 'group_id'))


def show_bundle_id(debugger, command, result, internal_dict):
    """
    print bundle id in codesign entitlements of the specified module if any.
    implemented in YJLLDB/src/MachOInfo.py
    """
    result.AppendMessage(parse_entitlements(debugger, command, result, 'bundle_id'))


def show_team_id(debugger, command, result, internal_dict):
    """
    print team id in codesign entitlements of the specified module if any.
    implemented in YJLLDB/src/MachOInfo.py
    """
    result.AppendMessage(parse_entitlements(debugger, command, result, 'team_id'))


def parse_entitlements(debugger, command, result, field):
    # 去掉转义符
    command = command.replace('\\', '\\\\')
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

    target = debugger.GetSelectedTarget()
    if args:
        module_name = ''.join(args)
    else:
        module_name = target.GetExecutable().GetFilename()

    module_name = module_name.replace("'", "")
    entitlements = MachOHelper.get_entitlements(module_name)
    # entitlements = get_entitlements(debugger, module_name)
    if not entitlements:
        return entitlements
    elif 'does not contain' in entitlements:
        return entitlements

    if field == 'entitlements':
        return entitlements
    elif field == 'group_id':
        ent_dict = util.parse_info_plist(entitlements)
        group_ids = ent_dict.get('com.apple.security.application-groups')
        if group_ids:
            return '{}'.format(group_ids)
        else:
            return 'group id not found'
    elif field == 'bundle_id':
        ent_dict = util.parse_info_plist(entitlements)
        return '{}'.format(ent_dict.get('application-identifier'))
    elif field == 'team_id':
        ent_dict = util.parse_info_plist(entitlements)
        return '{}'.format(ent_dict.get('com.apple.developer.team-identifier'))


def show_executable_name(debugger, command, result, internal_dict):
    """
    print executable name
    implemented in YJLLDB/src/MachOInfo.py
    """
    target = debugger.GetSelectedTarget()
    result.AppendMessage(target.GetExecutable().GetFilename())


def parse_macho(debugger, command, result, internal_dict):
    """
    parse mach-o of user modules.
    implemented in YJLLDB/src/MachOInfo.py
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

    target = debugger.GetSelectedTarget()

    is_address = False
    addr_str = None
    lookup_module_name = None
    if len(args) == 1:
        is_address, name_or_addr = util.parse_arg(args[0])
        if is_address:
            addr_str = name_or_addr
        else:
            lookup_module_name = name_or_addr
    else:
        file_spec = target.GetExecutable()
        lookup_module_name = file_spec.GetFilename()

    header_data = None
    if is_address:
        header_addr = int(addr_str, 16)
        header_size = 0x4000

        error = lldb.SBError()
        header_data = target.ReadMemory(lldb.SBAddress(header_addr, target), header_size, error)
        if not error.Success():
            result.AppendMessage('read header failed! {}'.format(error.GetCString()))
            return
    else:
        bundle_path = target.GetExecutable().GetDirectory()
        for module in target.module_iter():
            module_file_spec = module.GetFileSpec()
            module_dir = module_file_spec.GetDirectory()
            module_name = module_file_spec.GetFilename()

            if len(lookup_module_name):
                lib_name = lookup_module_name + '.dylib'
                if lookup_module_name != module_name and lib_name != module_name:
                    continue
            else:
                if bundle_path not in module_dir:
                    continue

            print("-----parsing module %s-----" % module_name)
            seg = module.FindSection('__TEXT')
            if not seg:
                result.AppendMessage('seg __TEXT not found')
                continue

            header_addr = seg.GetLoadAddress(target)
            first_sec = seg.GetSubSectionAtIndex(0)
            sec_addr = first_sec.GetLoadAddress(target)

            error = lldb.SBError()
            header_size = sec_addr - header_addr
            header_data = target.ReadMemory(lldb.SBAddress(header_addr, target), header_size, error)
            if not error.Success():
                result.AppendMessage('read header failed! {}'.format(error.GetCString()))
                continue

    info = MachO.parse_header(header_data)
    print(json.dumps(info, indent=2))


# def get_entitlements(debugger, keyword):
#     command_script = '@import Foundation;'
#     command_script += r'''
#     struct mach_header_64 {
#         uint32_t    magic;        /* mach magic number identifier */
#         int32_t        cputype;    /* cpu specifier */
#         int32_t        cpusubtype;    /* machine specifier */
#         uint32_t    filetype;    /* type of file */
#         uint32_t    ncmds;        /* number of load commands */
#         uint32_t    sizeofcmds;    /* the size of all the load commands */
#         uint32_t    flags;        /* flags */
#         uint32_t    reserved;    /* reserved */
#     };
#
#     struct segment_command_64 { /* for 64-bit architectures */
#         uint32_t    cmd;        /* LC_SEGMENT_64 */
#         uint32_t    cmdsize;    /* includes sizeof section_64 structs */
#         char        segname[16];    /* segment name */
#         uint64_t    vmaddr;        /* memory address of this segment */
#         uint64_t    vmsize;        /* memory size of this segment */
#         uint64_t    fileoff;    /* file offset of this segment */
#         uint64_t    filesize;    /* amount to map from the file */
#         int32_t        maxprot;    /* maximum VM protection */
#         int32_t        initprot;    /* initial VM protection */
#         uint32_t    nsects;        /* number of sections in segment */
#         uint32_t    flags;        /* flags */
#     };
#     #define __LP64__ 1
#     #ifdef __LP64__
#     typedef struct mach_header_64 mach_header_t;
#     #else
#     typedef struct mach_header mach_header_t;
#     #endif
#     struct CS_Blob {
#         uint32_t magic;                 // magic number
#         uint32_t length;                // total length of blob
#     };
#
#     struct CS_BlobIndex {
#         uint32_t type;                  // type of entry
#         uint32_t offset;                // offset of entry
#     };
#
#     struct CS_SuperBlob {
#         uint32_t magic;                 // magic number
#         uint32_t length;                // total length of SuperBlob
#         uint32_t count;                 // number of index entries following
#         struct CS_BlobIndex index[];           // (count) entries
#         // followed by Blobs in no particular order as indicated by offsets in index
#     };
#     struct linkedit_data_command {
#         uint32_t	cmd;		/* LC_CODE_SIGNATURE, LC_SEGMENT_SPLIT_INFO,
#                        LC_FUNCTION_STARTS, LC_DATA_IN_CODE,
#                        LC_DYLIB_CODE_SIGN_DRS,
#                        LC_LINKER_OPTIMIZATION_HINT,
#                        LC_DYLD_EXPORTS_TRIE, or
#                        LC_DYLD_CHAINED_FIXUPS. */
#         uint32_t	cmdsize;	/* sizeof(struct linkedit_data_command) */
#         uint32_t	dataoff;	/* file offset of data in __LINKEDIT segment */
#         uint32_t	datasize;	/* file size of data in __LINKEDIT segment  */
#     };
#     struct load_command {
#         uint32_t cmd;		/* type of load command */
#         uint32_t cmdsize;	/* total size of command in bytes */
#     };
#     union lc_str {
#         uint32_t	offset;	/* offset to the string */
#     #ifndef __LP64__
#         char		*ptr;	/* pointer to the string */
#     #endif
#     };
#     struct dylib {
#         union lc_str  name;			/* library's path name */
#         uint32_t timestamp;			/* library's build time stamp */
#         uint32_t current_version;		/* library's current version number */
#         uint32_t compatibility_version;	/* library's compatibility vers number*/
#     };
#     struct dylib_command {
#         uint32_t	cmd;		/* LC_ID_DYLIB, LC_LOAD_{,WEAK_}DYLIB,
#                            LC_REEXPORT_DYLIB */
#         uint32_t	cmdsize;	/* includes pathname string */
#         struct dylib	dylib;		/* the library identification */
#     };
#     '''
#     command_script += 'NSString *keyword = @"' + keyword + '";\n'
#     command_script += r'''
#     uint64_t address = 0;
#     BOOL isAddress = [keyword hasPrefix:@"0x"];
#     if (isAddress) {
#         address = strtoull((const char *)[keyword UTF8String], 0, 16);
#     }
#     char *ent_str = NULL;
#     const mach_header_t *headers[256] = {0};
#     NSMutableArray *module_names = [NSMutableArray array];
#     int name_count = 0;
#     if (!keyword || [@"NULL" isEqualToString:keyword]) {
#         keyword = [[[NSBundle mainBundle] executablePath] lastPathComponent];
#     }
#
#     uint32_t image_count = (uint32_t)_dyld_image_count();
#     for (uint32_t i = 0; i < image_count; i++) {
#         const char *name = (const char *)_dyld_get_image_name(i);
#         if (!name) {
#             continue;
#         }
#         const mach_header_t *mach_header = (const mach_header_t *)_dyld_get_image_header(i);
#         if (isAddress) {
#             if (address != (uint64_t)mach_header) {
#                 continue;
#             }
#         }
#         NSString *module_name = [[NSString stringWithUTF8String:name] lastPathComponent];
#         NSRange range = [module_name rangeOfString:keyword options:NSCaseInsensitiveSearch];
#         if (isAddress || range.location != NSNotFound) {
#             headers[name_count] = mach_header;
#             name_count++;
#             [module_names addObject:module_name];
#         }
#         if (isAddress) {
#             break;
#         }
#     }
#
#     char *lib_path = NULL;
#     if (isAddress && name_count == 0) {
#         headers[name_count] = (const mach_header_t *)address;
#         name_count++;
#     }
#
#     NSMutableString *result = [NSMutableString string];
#     for (int idx = 0; idx < name_count; idx++) {
#         const mach_header_t *mach_header = headers[idx];
#         uint32_t header_magic = mach_header->magic;
#         if (header_magic != 0xfeedfacf) { //MH_MAGIC_64
#             continue;
#         }
#
#         uint32_t ncmds = mach_header->ncmds;
#         if (ncmds == 0) {
#             continue;
#         }
#
#         struct load_command *lc = (struct load_command *)((char *)mach_header + sizeof(mach_header_t));
#         struct linkedit_data_command *lc_signature = NULL;
#         uint64_t text_file_offset = 0;
#         uint64_t text_vmaddr = 0;
#         uint64_t file_offset = 0;
#         uint64_t li_vmaddr = 0;
#         NSString *name = nil;
#         BOOL sig_found = NO;
#         for (uint32_t i = 0; i < ncmds; i++) {
#             if (lc->cmd == 0x19) { // LC_SEGMENT_64
#                 struct segment_command_64 *seg = (struct segment_command_64 *)lc;
#                 if (strcmp(seg->segname, "__LINKEDIT") == 0) { //SEG_LINKEDIT
#                     file_offset = seg->fileoff;
#                     li_vmaddr      = seg->vmaddr;
#                 } else if (strcmp(seg->segname, "__TEXT") == 0) {
#                     text_file_offset = seg->fileoff;
#                     text_vmaddr = seg->vmaddr;
#                 }
#             } else if (lc->cmd == 0xd) { //LC_ID_DYLIB
#                 struct dylib_command *dc = (struct dylib_command *)lc;
#                 char *path = (char *)dc + dc->dylib.name.offset;
#                 if (path) {
#                     lib_path = strdup(path);
#                     name = [[NSString stringWithUTF8String:lib_path] lastPathComponent];
#                 }
#             } else if (lc->cmd == 0x1d) { //LC_CODE_SIGNATURE
#                 lc_signature = (struct linkedit_data_command *)lc;
#             }
#             lc = (struct load_command *)((char *)lc + lc->cmdsize);
#         }
#         if (name.length == 0) {
#             name = module_names[idx];
#         }
#         if (lc_signature) {
#             sig_found = YES;
#             char *sign_ptr = NULL;
#             sign_ptr = (char *)mach_header + (li_vmaddr - text_vmaddr) + lc_signature->dataoff - file_offset;
# #if __arm64e__
#             void *sign = (void *)ptrauth_strip(sign_ptr, ptrauth_key_function_pointer);
# #else
#             void *sign = (void *)sign_ptr;
# #endif
#             struct CS_SuperBlob *superBlob = (struct CS_SuperBlob *)sign;
#             uint32_t super_blob_magic = _OSSwapInt32(superBlob->magic);
#             // 签名段数据被破坏
#             if (super_blob_magic != 0xfade0cc0) { // CSMAGIC_EMBEDDED_SIGNATURE
#                 [result appendFormat:@"invalid signature magic found at %@!0x%x, signature: %p, header at: %p\n", name, lc_signature->dataoff, sign, mach_header];
#                 uint32_t sign_size = lc_signature->datasize;
#                 const char *prefix = "<?xml";
#                 char *ent_ptr = (char *)memmem(sign, sign_size, prefix, strlen(prefix));
#                 if (!ent_ptr) {
#                     break;
#                 }
#                 const char *suffix = "</plist>";
#                 size_t data_len = ent_ptr - (char *)sign;
#                 char *ent_end = (char *)memmem(ent_ptr, data_len, suffix, strlen(suffix));
#                 if (!ent_end) {
#                     break;
#                 }
#                 size_t length = ent_end - ent_ptr + strlen(suffix);
#                 if (length) {
#                     ent_str = (char *)calloc(length + 1, sizeof(char));
#                     if (ent_str) {
#                         memcpy(ent_str, ent_ptr, length);
#                         [result appendFormat:@"entitlements of %@:\n%s", name, ent_str];
#                         free(ent_str);
#                     }
#                 }
#                 break;
#             }
#             uint32_t nblob = _OSSwapInt32(superBlob->count);
#
#             BOOL ent_found = NO;
#             struct CS_BlobIndex *index = superBlob->index;
#             for ( int i = 0; i < nblob; ++i ) {
#                 struct CS_BlobIndex blobIndex = index[i];
#                 uint32_t offset = _OSSwapInt32(blobIndex.offset);
#
#                 uint32_t *blobAddr = (__uint32_t *)((char *)sign + offset);
#
#                 struct CS_Blob *blob = (struct CS_Blob *)blobAddr;
#                 uint32_t magic = _OSSwapInt32(blob->magic);
#                 if ( magic == 0xfade7171 ) { //kSecCodeMagicEntitlement
#
#                     uint32_t header_len = 8;
#                     uint32_t length = _OSSwapInt32(blob->length) - header_len;
#                     if (length <= 0) {
#                         break;
#                     }
#                     char *ent_ptr = (char *)blobAddr + header_len;
#                     ent_str = (char *)calloc(length + 1, sizeof(char));
#                     if (ent_str) {
#                         memcpy(ent_str, ent_ptr, length);
#                         [result appendFormat:@"entitlements of %@:\n%s", name, ent_str];
#                         free(ent_str);
#                         ent_found = YES;
#                     }
#                     break;
#                 }
#             }
#             if (!ent_found) {
#                 [result appendFormat:@"%@ apparently does not contain any entitlements, signature: %p\n", name, sign];
#             }
#         }
#
#         if (!sig_found) {
#             [result appendFormat:@"%@ apparently does not contain code signature\n", name];
#         }
#     }
#     if (lib_path) {
#         free(lib_path);
#     }
#
#     result;
#     '''
#     ret_str = util.exe_script(command_script)
#
#     return ret_str


def generate_option_parser():
    usage = "usage: %prog [module name]\n"

    parser = optparse.OptionParser(usage=usage, prog='entitlements')

    return parser
