# -*- coding: UTF-8 -*-
import json

import lldb
import optparse
import shlex
import os.path
import shutil
import subprocess
import util
import MachO

script_dir = os.path.dirname(os.path.realpath(__file__))


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "dump app to mac from device" -f '
        'DumpApp.dump_app dapp')


def dump_app(debugger, command, result, internal_dict):
    """
    dump app to mac from device
    implemented in YJLLDB/src/DumpApp.py
    """
    # 去掉转义符
    command = command.replace('\\', '\\\\')
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command_args = shlex.split(command, posix=False)
    # 创建parser
    parser = generate_option_parser('dapp')
    # 解析参数，捕获异常
    try:
        # options是所有的选项，key-value形式，args是其余剩余所有参数，不包含options
        (options, args) = parser.parse_args(command_args)
    except Exception as error:
        print(error)
        result.SetError("\n" + parser.get_usage())
        return

    output_dir = os.path.expanduser('~') + '/lldb_dump_macho'
    util.try_mkdir(output_dir)

    app_info_str = get_app_regions(options.apply_patch)
    if app_info_str:
        app_info = json.loads(app_info_str)
        print('dumping {}, this may take a while'.format(app_info["app_name"]))
        app_name, work_dir, app_path = dump_app_with_info(app_info, output_dir)

        success = create_ipa(work_dir, app_name, options.min_os_version)
        if success:
            result.AppendMessage("dump success, ipa path: {}/{}.ipa".format(work_dir, app_name))
        else:
            result.AppendMessage("dump failure")


def dump_region(addr, size, output_path):
    res = lldb.SBCommandReturnObject()
    interpreter = lldb.debugger.GetCommandInterpreter()
    cmd = 'memory read --force --outfile {} --binary --count {} {}' \
        .format(output_path, size, addr)
    interpreter.HandleCommand(cmd, res)


def dump_app_with_info(app_info, output_dir):
    app_name = app_info["app_name"]
    files = app_info["files"]
    encrypted_images = app_info["encryptedImages"]
    # bundle_path = app_info["bundlePath"]

    work_dir = '{}/{}'.format(output_dir, app_name)
    datas_dir = '{}/datas'.format(work_dir)
    if os.path.exists(work_dir):
        shutil.rmtree(work_dir)
    util.try_mkdir(work_dir)
    util.try_mkdir(datas_dir)

    app_info_write_to_file(app_info, datas_dir)

    output_app_path = datas_dir + '/' + app_name + '.app'

    res = lldb.SBCommandReturnObject()
    interpreter = lldb.debugger.GetCommandInterpreter()
    for file in files:
        rel_path = file["rel_path"]
        print("copy file {}.app{}".format(app_name, rel_path))
        output_filepath = output_app_path + rel_path
        directory = os.path.dirname(output_filepath)
        util.try_mkdir(directory)

        data_info = file["data_info"]
        comps = data_info.split('-')
        data_addr = int(comps[0])
        data_size = int(comps[1])
        cmd = 'memory read --force --outfile {} --binary --count {} {}' \
            .format(output_filepath, data_size, data_addr)
        interpreter.HandleCommand(cmd, res)

    if len(encrypted_images) == 0:
        print("no file need patch")
    else:
        target = lldb.debugger.GetSelectedTarget()
        for idx, region_info in enumerate(encrypted_images):
            # print('{} {}'.format(idx, region_info))
            rel_path = region_info.get("rel_path")
            exe_name = region_info.get("exe_name")
            slide = int(region_info.get("slide"))
            header = int(region_info.get("header"))
            crypt_region = region_info.get("crypt")
            comps = crypt_region.split('-')
            crypt_off = int(comps[0])
            crypt_size = int(comps[1])
            crypt_id_off = int(comps[2], 16)
            decrypted_path = datas_dir + '/' + exe_name + '_text_data'

            error = lldb.SBError()
            header_size = 0x4000
            header_data = target.ReadMemory(lldb.SBAddress(header, target), header_size, error)
            if not error.Success():
                print('read header failed! {}'.format(error.GetCString()))
                continue

            sec_text_off = 0
            sec_text_addr = 0
            sec_text_size = 0
            info = MachO.parse_header(header_data)
            lcs = info['lcs']
            for lc in lcs:
                cmd = lc['cmd']
                if cmd == '19':  # LC_SEGMENT_64
                    seg_name = lc['name']
                    if seg_name != '__TEXT':
                        continue

                sects = lc['sects']
                for sect in sects:
                    sec_name = sect['name']
                    if sec_name != '__text':
                        continue

                    sec_text_addr = int(sect['addr'], 16)
                    sec_text_off = int(sect['offset'], 16)
                    sec_text_size = int(sect['size'], 16)

                    break

                break

            # print(json.dumps(info, indent=2))
            crypt_start = header + crypt_off
            crypt_end = crypt_start + crypt_size
            sec_text_start = slide + sec_text_addr
            sec_text_end = sec_text_start + sec_text_size
            if crypt_start <= sec_text_start and sec_text_start < crypt_end < sec_text_end:
                print("section __text contains crypted region suffix")
                dump_addr = crypt_off
                dump_size = sec_text_size - dump_addr
                patch_off = crypt_off
            elif crypt_start > sec_text_start and crypt_end < sec_text_end:
                print("section __text contains crypted region")
                dump_addr = sec_text_start
                dump_size = sec_text_size
                patch_off = sec_text_off
            else:
                if not (crypt_start <= sec_text_start and crypt_end > sec_text_end):
                    print("unexpected: crypt_off {}, crypt_size {}, text vmaddr {}, text size {}".
                          format(crypt_off, crypt_size, sec_text_addr, sec_text_size))
                dump_addr = crypt_start
                dump_size = crypt_size
                patch_off = crypt_off

            print("patching {}.app{}".format(app_name, rel_path))
            dump_region(dump_addr, dump_size, decrypted_path)

            exe_path = datas_dir + '/' + app_name + '.app' + rel_path
            # thin
            cmd = os.path.join(script_dir, 'thin.sh') + ' ' + exe_path
            subprocess.check_call(cmd, shell=True)
            # patch crypted data
            with open(exe_path, 'rb+') as macho_file:
                with open(decrypted_path, 'rb') as decrypted_file:
                    macho_file.seek(patch_off)
                    macho_file.write(decrypted_file.read())
                    macho_file.flush()

                    decrypted_file.close()

                # patch cryptid
                crypt_id = b'\x00\x00\x00\x00'
                macho_file.seek(crypt_id_off)
                macho_file.write(crypt_id)

                macho_file.close()

    return app_name, work_dir, output_app_path


def app_info_write_to_file(module_info, module_dir):
    module_name = module_info["app_name"].replace(' ', '_')
    json_file_path = module_dir + '/' + module_name + '.json'
    json_fp = open(json_file_path, 'w')
    json.dump(module_info, json_fp, indent=4)
    json_fp.close()


def create_ipa(work_dir, display_name, os_version):
    ipa_filename = display_name + '.ipa'
    app_name = display_name + '.app'
    payload_dir = 'Payload'
    payload_path = os.path.join(work_dir, payload_dir)
    util.try_mkdir(payload_path)

    print('creating "{}"'.format(ipa_filename))
    success = False
    try:
        tmp_app_path = os.path.join(work_dir, 'datas', app_name)
        shutil.move(tmp_app_path, payload_path)

        # patch Info.plist
        app_path = os.path.join(payload_path, app_name)
        if os_version is None:
            fix_args = ('sh', os.path.join(script_dir, 'fixInfoPlist.sh'), app_path)
        else:
            fix_args = ('sh', os.path.join(script_dir, 'fixInfoPlist.sh'), app_path, os_version)

        try:
            subprocess.check_call(fix_args)
        except subprocess.CalledProcessError as err:
            print(err)

        # create ipa
        target_dir = './' + payload_dir
        zip_args = ('zip', '-qr', os.path.join(work_dir, ipa_filename), target_dir)
        subprocess.check_call(zip_args, cwd=work_dir)
        shutil.rmtree(payload_path)
        success = True
    except Exception as e:
        print(e)

    return success


def get_app_regions(apply_patch):
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
    struct encryption_info_command_64 {
       uint32_t	cmd;		/* LC_ENCRYPTION_INFO_64 */
       uint32_t	cmdsize;	/* sizeof(struct encryption_info_command_64) */
       uint32_t	cryptoff;	/* file offset of encrypted range */
       uint32_t	cryptsize;	/* file size of encrypted range */
       uint32_t	cryptid;	/* which enryption system,
                       0 means not-encrypted yet */
       uint32_t	pad;		/* padding to make this struct's size a multiple
                       of 8 bytes */
    };
    '''
    command_script += 'BOOL force = {};'.format('YES' if apply_patch else 'NO')
    command_script += r'''
    NSBundle *mainBundle = [NSBundle mainBundle];
    NSString *bundlePath = mainBundle.bundlePath;
    bundlePath = [bundlePath stringByReplacingOccurrencesOfString:@"/private" withString:@""];

    NSMutableArray *encryptedImages = [NSMutableArray array];
    NSMutableArray *files = [NSMutableArray array];
    
    // 先统计文件，并加载所有动态库
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSArray *subpaths = [fileManager subpathsAtPath:bundlePath];
    
    for (NSString *subpath in subpaths) {
        if ([subpath hasPrefix:@"PlugIns"] ||
            [subpath hasPrefix:@"Watch"]
            ) {
            continue;
        }
        NSString *fullpath = [bundlePath stringByAppendingPathComponent:subpath];
        
        if ([subpath hasSuffix:@".framework"]) {
            NSBundle *framework_bundle = [NSBundle bundleWithPath:fullpath];
            if (![framework_bundle isLoaded]) {
                NSError *error = nil;
                [framework_bundle loadAndReturnError:&error];
                if (error) {
                    NSLog(@"%@", error);
                }
            }
            continue;
        }
        
        BOOL isDirectory = NO;
        [fileManager fileExistsAtPath:fullpath isDirectory:&isDirectory];
        if (isDirectory) {
            continue;
        }
        
        NSString *rel_path = [fullpath stringByReplacingOccurrencesOfString:bundlePath withString:@""];
        NSData *data = [NSData dataWithContentsOfFile:fullpath];
        NSUInteger len = [data length];
        const void *bytes = (const void *)[data bytes];
        NSString *data_info = [NSString stringWithFormat:@"%lu-%lu", (NSUInteger)bytes, len];
        [files addObject:@{
            @"rel_path": rel_path,
            @"data_info": data_info
        }];
    }
    
    NSString *(^getCryptRegion)(const mach_header_t *) = ^(const mach_header_t *mach_header) {
        NSString *ret = nil;
        uint32_t magic = mach_header->magic;
        if (magic != 0xfeedfacf) { // MH_MAGIC_64
            return ret;
        }
        uint32_t ncmds = mach_header->ncmds;
        if (ncmds <= 0) {
            return ret;
        }
        
        uintptr_t cur = (uintptr_t)mach_header + sizeof(mach_header_t);
        struct load_command *sc = NULL;
        for (uint i = 0; i < ncmds; i++, cur += sc->cmdsize) {
            sc = (struct load_command *)cur;
            if (sc->cmd == 0x2C) { //LC_ENCRYPTION_INFO_64
                struct encryption_info_command_64 *eic = (struct encryption_info_command_64 *)sc;
                if (eic->cryptid != 0 || force) {
                    ret = [NSString stringWithFormat:@"%d-%d-0x%lx", eic->cryptoff, eic->cryptsize, (uintptr_t)eic - (uintptr_t)mach_header + 4 * sizeof(uint32_t)];
                }
                break;
            }
        }
        
        return ret;
    };
    
    uint32_t image_count = (uint32_t)_dyld_image_count();
    for (uint32_t i = 0; i < image_count; i++) {
        const char *name = (const char *)_dyld_get_image_name(i);
        if (!name) {
            continue;
        }
        const mach_header_t *mach_header = (const mach_header_t *)_dyld_get_image_header(i);
        
        NSString *image_path = [NSString stringWithUTF8String:name];
        image_path = [image_path stringByReplacingOccurrencesOfString:@"/private" withString:@""];
        if (![image_path hasPrefix:bundlePath]) {
            continue;
        }
        NSString *cryptRegion = getCryptRegion(mach_header);
        if (!cryptRegion.length) {
            continue;
        }
        intptr_t slide = (intptr_t)_dyld_get_image_vmaddr_slide(i);
        NSString *rel_path = [image_path stringByReplacingOccurrencesOfString:bundlePath withString:@""];
        NSString *exe_name = [rel_path.lastPathComponent stringByDeletingPathExtension];
        NSDictionary *image_info = @{@"rel_path": rel_path,
                                @"exe_name": exe_name,
                                @"slide": @(slide),
                                @"header": @((uint64_t)mach_header),
                                @"crypt": cryptRegion
        };
        [encryptedImages addObject:image_info];
    }
    
    NSString *app_name = [bundlePath.lastPathComponent stringByDeletingPathExtension];
    NSDictionary *app_info = @{
        @"encryptedImages": encryptedImages,
        @"files": files,
        @"app_name": app_name,
        @"bundlePath": bundlePath
    };
    
    NSData *data = [NSJSONSerialization dataWithJSONObject:app_info options:kNilOptions error:nil];
    // 4 NSUTF8StringEncoding
    NSString *json_str = [[NSString alloc] initWithData:data encoding:4];
    json_str;
    '''

    ret_str = util.exe_script(command_script)

    return ret_str


def generate_option_parser(prog):
    usage = "usage: %prog\n"

    parser = optparse.OptionParser(usage=usage, prog=prog)
    parser.add_option("-v", "--min_os_version",
                      dest="min_os_version",
                      help="min deployment os version")
    parser.add_option("-p", "--apply_patch",
                      action="store_true",
                      default=False,
                      dest="apply_patch",
                      help="apply patch")

    return parser
