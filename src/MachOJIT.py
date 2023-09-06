# -*- coding: UTF-8 -*-

import util


def get_function_starts(module):
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
    #define __LP64__ 1
    #ifdef __LP64__
    typedef struct mach_header_64 mach_header_t;
    #else
    typedef struct mach_header mach_header_t;
    #endif
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
    #ifndef TASK_DYLD_INFO_COUNT
    #define TASK_DYLD_INFO_COUNT    \
                (sizeof(task_dyld_info_data_t) / sizeof(natural_t))
    #endif
    '''
    command_script += 'NSString *x_module_name = @"' + module + '";'
    command_script += r'''
    if (!x_module_name) {
        x_module_name = [[[NSBundle mainBundle] executablePath] lastPathComponent];
    }
    
    const mach_header_t *x_mach_header = NULL;
    intptr_t slide = 0;
    uint32_t image_count = (uint32_t)_dyld_image_count();
    for (uint32_t i = 0; i < image_count; i++) {
        const char *name = (const char *)_dyld_get_image_name(i);
        if (!name) {
            continue;
        }
        const mach_header_t *mach_header = (const mach_header_t *)_dyld_get_image_header(i);
        
        NSString *module_name = [[NSString stringWithUTF8String:name] lastPathComponent];
        if ([module_name isEqualToString:x_module_name] ||
            [module_name isEqualToString:[x_module_name stringByAppendingString:@".dylib"]]) {
            x_mach_header = mach_header;
            slide = (intptr_t)_dyld_get_image_vmaddr_slide(i);
            break;
        }
    }
    
    struct linkedit_data_command *func_starts = NULL;
    uint64_t file_offset = 0;
    uint64_t vmaddr      = 0;
    if (x_mach_header) {
        uint32_t magic = x_mach_header->magic;
        if (magic == 0xfeedfacf) { // MH_MAGIC_64
            uint32_t ncmds = x_mach_header->ncmds;
            if (ncmds > 0) {
                uintptr_t cur = (uintptr_t)x_mach_header + sizeof(mach_header_t);
                struct load_command *sc = NULL;
                for (uint i = 0; i < ncmds; i++, cur += sc->cmdsize) {
                    sc = (struct load_command *)cur;
                    if (sc->cmd == 0x19) { // LC_SEGMENT_64
                        struct segment_command_64 *seg = (struct segment_command_64 *)sc;
                        if (slide == 0 && strcmp(seg->segname, "__TEXT") == 0) {
                            slide = (uint64_t)x_mach_header - seg->vmaddr;
                        }
                        if (strcmp(seg->segname, "__LINKEDIT") == 0) { //SEG_LINKEDIT
                            file_offset = seg->fileoff;
                            vmaddr      = seg->vmaddr;
                        }
                    } else if (sc->cmd == 0x26) { //LC_FUNCTION_STARTS
                        func_starts = (struct linkedit_data_command *)sc;
                        break;
                    }
                }
            }
        }
    }
    
    NSMutableString *addresses = [NSMutableString string];
    if (func_starts) {
        const uint8_t* infoStart = NULL;
        infoStart = (uint8_t*)((uint64_t)vmaddr + func_starts->dataoff - file_offset + slide);
        const uint8_t* infoEnd = &infoStart[func_starts->datasize];
        uint64_t address = (uint64_t)x_mach_header;
        for (const uint8_t *p = infoStart; (*p != 0) && (p < infoEnd); ) {
            uint64_t offset = 0;
            uint32_t bit = 0;
            do {
                uint64_t slice = *p & 0x7f;
                
                if (bit >= 64 || slice << bit >> bit != slice)
                    [NSException raise:@"uleb128 error" format:@"uleb128 too big"];
                else {
                    offset |= (slice << bit);
                    bit += 7;
                }
            } while (*p++ & 0x80);
            
            address += offset;
//            printf("0x%llx %llu\n", address, offset);
            [addresses appendFormat:@"0x%llx;", address];
        }
    }
    NSUInteger len = [addresses length];
    if (len > 0) {
        [addresses replaceCharactersInRange:NSMakeRange(len - 1, 1) withString:@""];
    }
    addresses;
    '''

    ret_str = util.exe_script(command_script)

    return ret_str
