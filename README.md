## YJLLDB

一些用于调试iOS应用的lldb命令。Some very useful lldb commands for iOS debugging and reverse engineering.



## Commands list

Breakpoint:

​     \* [bab - break at bytes](#bab---break-at-bytes)

​     \* [baf - break all functions in module](#baf---break-all-functions-in-module)

​     \* [bdc - breakpoint disable current](#bdc---breakpoint-disable-current)

​     \* [bda - breakpoint disable at class](#bda---breakpoint-disable-at-class)

​     \* [bdr - breakpoint disable in range](#bdr---breakpoint-disable-in-range)

​     \* [bblocks - break blocks (arm64 only)](#bblocks---break-blocks-arm64-only)

​     \* [binitfunc - break mod init func](#binitfunc---break-mod-init-func)

​     \* [bmethod - break method](#bmethod---break-method)

​     \* [bmain - break main function](#bmain---break-main-function)

Search:

​     \* [slookup - lookup string](#slookup---lookup-string)

​     \* [blookup - lookup bytes](#blookup---lookup-bytes)

​     \* [fblock - find block (arm64 only)](#fblock---find-block-arm64-only)

​     \* [blocks - find blocks (arm64 only)](#blocks---find-blocks-arm64-only)

​     \* [ffunc - find function](#ffunc---find-function)

Trace:

​     \* [mtrace - trace module](#mtrace---trace-module)

​     \* [rtrace](#rtrace)

​     \* [notifier](#notifier)

Patch:

​     \* [patch (private)](#patch-(private))

Dump:

​     \* [dmodule - dump module (private)](#dmodule---dump-module-private)

​     \* [dapp - dump App (private)](#dapp---dump-app-private)

Shell command

​     \* [addcmd](#addcmd)

​     \* [delcmd](#delcmd)

​     \* [pwd](#pwd)

​     \* [cd](#cd)

​     \* [ls](#ls)

File:

​     \* [commads to get common directory](#commads-to-get-common-directory)

​     \* [ils](#ils)

​     \* [dfile - download file](#dfile---download-file)

​     \* [ddir - download directory](#ddir---download-directory)

​     \* [ufile - upload local file to device](#ufile---upload-local-file-to-device)

​     \* [irm - remove file](#irm---remove-file)

Module:

​     \* [image_list](#image_list)

​     \* [info_plist](#info_plist---print-Info.plist)

​     \* [executable - print main executable name](#executable---print-main-executable-name)

​     \* [bundle_id](#bundle_id)

​     \* [group_id](#group_id)

​     \* [team_id](#team_id)

​     \* [appdelegate](#appdelegate)

​     \* [mname - module name](#mname---module-name)

​     \* [segments - print segments](#segments---print-segments)

​     \* [main](#main)

​     \* [initfunc - print mod init func](#initfunc---print-mod-init-func)

​     \* [func_starts - function starts](#func_starts---function-starts)

​     \* [got - print __got section](#got---print-__got-section)

​     \* [lazy_sym - print __la_symbol_ptr section](#lazy_sym---print-__la_symbol_ptr-section)

​     \* [entitlements - dump entitlements](#entitlements---dump-entitlements)

​     \* [classes - print class names](#classes---print-class-names)

Assembly:

​     \* [inst2bytes](#inst2bytes)

​     \* [bytes2inst](#bytes2inst)

Memory:

​     \* [read_mem_as_addr](#read_mem_as_addr)

​     \* [read_cstring - read memory as c style string](#read_cstring---read-memory-as-c-style-string)

Others:

​     \* [symbolize](#symbolize)

​     \* [find_el - find endless loop](#find_el---find-endless-loop)

​     \* [thread_eb - extended backtrace of thread](#thread_eb---extended-backtrace-of-thread)

## Installation

1. Clone this repo
2. Open up (or create) **~/.lldbinit**
3. Add the following command to your ~/.lldbinit file: `command script import /path/to/YJLLDB/src/yjlldb.py`

## Usage

### Breakpoint:

#### bab - break at bytes

Set breakpoints at the specified bytes in user modules.

```stylus
// for example, break at ret
(lldb) bab c0 03 5f d6
Breakpoint 1: where = LLDBCode`-[ViewController viewDidLoad] + 240 at ViewController.m:29:1, address = 0x1029b3008
...
set 728 breakpoints

(lldb) x 0x1029b3008
0x1029b3008: c0 03 5f d6 ff 03 03 d1 fd 7b 0b a9 fd c3 02 91  .._......{......
0x1029b3018: e8 03 01 aa e1 03 02 aa e3 0f 00 f9 a0 83 1f f8  ................
(lldb) dis -s 0x1029b3008 -c 1
LLDBCode`-[ViewController viewDidLoad]:
    0x1029b3008 <+240>: ret
```

[back to commands list](#Commands-list)



#### baf - break all functions in module

Break all functions and methods in the specified module.

For example，break Foundation:

```stylus
(lldb) baf Foundation
-----break functions in Foundation-----
will set breakpoint for 13880 names
Breakpoint 4: 13961 locations
```



#### bdc - breakpoint disable current

Disable current breakpoint and continue.

```stylus
(lldb) thread info
thread #1: tid = 0x2cb739, 0x000000018354f950 libsystem_kernel.dylib`open, queue = 'com.apple.main-thread', stop reason = breakpoint 5.13

(lldb) bdc
disable breakpoint 5.13 [0x18354f950]libsystem_kernel.dylib`open
and continue
```

[back to commands list](#Commands-list)



#### bda - breakpoint disable at class

Disable breakpoint(s) at the specified class.

```stylus
(lldb) bda -i ViewController
disable breakpoint 1.8: where = LLDBCode`__41-[ViewController touchesBegan:withEvent:]_block_invoke_4 at ViewController.m:57, address = 0x00000001040e32f8, unresolved, hit count = 1  Options: disabled 
...
disable breakpoint 1.27: where = LLDBCode`__41-[ViewController touchesBegan:withEvent:]_block_invoke at ViewController.m:45, address = 0x00000001040e318c, unresolved, hit count = 1  Options: disabled 

(lldb) bda -i ViewController(extension)
disable breakpoint 1.23: where = LLDBCode`-[ViewController(extension) test] at ViewController.m:20, address = 0x0000000102ec2e7c, unresolved, hit count = 0  Options: disabled 
```



#### bdr - breakpoint disable in range

Disable breakpoint(s) in the specified range.

```stylus
(lldb) bdr 980~992
disable breakpoint 980.1: where = LLDBCode`-[Test .cxx_destruct] at Test.m:22, address = 0x00000001049fa1b0, unresolved, hit count = 0  Options: disabled 
...
disable breakpoint 991.1: where = LLDBCode`func1 at Test.m:42, address = 0x00000001049faaf8, unresolved, hit count = 0  Options: disabled 
```

[back to commands list](#Commands-list)



#### bblocks - break blocks (arm64 only)

Break all blocks in user modules

```stylus
(lldb) bblocks
-----try to lookup block in JITDemo-----
break block: 0x104a78150 with Breakpoint 4: JITDemo`globalBlock_block_invoke at ViewController.m:16:0, address = 0x104a74990
...
break stack block with Breakpoint 9: JITDemo`__41-[ViewController touchesBegan:withEvent:]_block_invoke_4 at ViewController.m:75:0, address = 0x104a74f08
...
-----try to lookup block in LLDBJIT-----
break block: 0x104b341c0 with Breakpoint 82: LLDBJIT`__22+[MachoTool findMacho]_block_invoke at MachoTool.m:110:0, address = 0x104b2b130
...
find a stack block @0x104b32080 in LLDBJIT`+[Image getBlocksInfo:] at Image.m:0:0
break stack block with Breakpoint 88: LLDBJIT`None, address = 0x104b34d40
set 85 breakpoints
(lldb) 
```

or

```stylus
(lldb) bblocks JITDemo
-----try to lookup block in JITDemo-----
break block: 0x1026ac140 with Breakpoint 87: JITDemo`___lldb_unnamed_symbol75, address = 0x1026a92f4
...
find a stack block @0x1026a9694 in JITDemo`___lldb_unnamed_symbol82
break stack block with Breakpoint 93: JITDemo`___lldb_unnamed_symbol83, address = 0x1026a9700
set 7 breakpoints
```

[back to commands list](#Commands-list)



#### binitfunc - break mod init func

Break module init function(s) in user modules.

```stylus
(lldb) binitfunc
-----try to lookup init function in JITDemo-----
Breakpoint 6: JITDemo`entry1 at main.m:708:0, address = 0x100e08cb0
Breakpoint 7: JITDemo`entry2 at main.m:740:0, address = 0x100e0960c
```



#### bmethod - break method

Break the specified method(s) in user modules

```stylus
(lldb) bmethod load
-----try to method in JITDemo-----
Breakpoint 3: JITDemo`+[ViewController load] at ViewController.m:26:0, address = 0x1024f89bc
Breakpoint 4: JITDemo`+[AppDelegate load] at AppDelegate.m:16:0, address = 0x1024f96a4
-----try to method in LLDBJIT-----
set 2 breakpoints
```

[back to commands list](#Commands-list)



#### bmain - break main function

```stylus
(lldb) bmain
Breakpoint 9: BasicSyntax`___lldb_unnamed_symbol266, address = 0x10017c3fc
```

[back to commands list](#Commands-list)



### Search:

#### slookup - lookup string

Lookup the specified string, between start addr and end addr.

```stylus
(lldb) image_list -c 8
index   load addr(slide)       vmsize path
--------------------------------------------------------
[  0] 0x1022e4000(0x0022e4000)  81.9K /var/containers/Bundle/Application/C134E909-CC52-4A93-9557-37BA808854D3/LLDBCode.app/LLDBCode
...
[  6] 0x18406f000(0x004044000)   8.7K /usr/lib/libSystem.B.dylib
[  7] 0x184071000(0x004044000) 394.1K /usr/lib/libc++.1.dylib
  
(lldb) slookup PROGRAM 0x18406f000 0x184071000
found at 0x184070f7c where = [0x000000018002cf78-0x000000018002cfb8) libSystem.B.dylib.__TEXT.__const
1 locations found

(lldb) x 0x184070f7c -c 64
0x184070f7c: 50 52 4f 47 52 41 4d 3a 53 79 73 74 65 6d 2e 42  PROGRAM:System.B
0x184070f8c: 20 20 50 52 4f 4a 45 43 54 3a 4c 69 62 73 79 73    PROJECT:Libsys
0x184070f9c: 74 65 6d 2d 31 32 35 32 2e 35 30 2e 34 0a 00 00  tem-1252.50.4...
0x184070fac: 00 00 00 00 00 00 00 00 00 92 93 40 01 00 00 00  ...........@....
```

[back to commands list](#Commands-list)



#### blookup - lookup bytes

Lookup the specified bytes in user modules.

```stylus
(lldb) blookup c0 03 5f d6
-----try to lookup bytes in LLDBCode-----
0x104961018
...
0x104969ab8
32 locations found
```

[back to commands list](#Commands-list)



#### fblock - find block (arm64 only)

Find the specified block(s) in user modules.

```stylus
(lldb) po $x0
<__NSGlobalBlock__: 0x100f18210>
(lldb) x/4g 0x100f18210
0x100f18210: 0x00000001b57df288 0x0000000050000000
0x100f18220: 0x00000001043b9724 0x00000001043bc1f0
(lldb) info 0x00000001043b9724
0x00000001043b9724,   ___lldb_unnamed_symbol77     <+0> `JITDemo`__TEXT.__text + 0x290

(lldb) fblock 0x100f18210
-----try to lookup block in JITDemo-----
find a block: 0x100f18210 in JITDemo`-[ViewController touchesBegan:withEvent:]
1 block(s) resolved
```

[back to commands list](#Commands-list)



#### blocks - find blocks (arm64 only)

Find blocks in user modules and save block symbols to block_symbol.json

```stylus
(lldb) blocks
-----try to lookup block in JITDemo-----
* using global block var: 0x104a78150 in JITDemo`-[ViewController viewDidLoad] at ViewController.m:39:5
find a block: 0x104a78190 in JITDemo`-[ViewController viewDidLoad] at ViewController.m:0:0
...
find a stack block @0x104a74e7c in JITDemo`__41-[ViewController touchesBegan:withEvent:]_block_invoke_3 at ViewController.m:0:0
	stack block func addr 0x104a74f08 JITDemo`__41-[ViewController touchesBegan:withEvent:]_block_invoke_4 at ViewController.m:75:0
...
-----try to lookup block in LLDBJIT-----
find a block: 0x104b341c0 in LLDBJIT`+[MachoTool findMacho] at MachoTool.m:0:0
...
find a stack block @0x104b32080 in LLDBJIT`+[Image getBlocksInfo:] at Image.m:0:0
	stack block func addr 0x104b34d40 LLDBJIT`None
85 block(s) resolved
```

[back to commands list](#Commands-list)



#### ffunc - find function

find function by callee function name

```stylus
(lldb) ffunc -n open -i 5900
-----parsing module Demo-----
	function call found at: 0x1057c09b0, where = Demo`___lldb_unnamed_symbol255344 + 88
```

find function by callee funcation address

```stylus
(lldb) ffunc -a 0x1005106a0 -i 5000
-----parsing module Demo-----
	function call found at: 0x10050dcd8, where = Demo`test_func + 2360
```

find function by c string

```stylus
(lldb) ffunc -k test -i 700 -x 800
-----parsing module Demo-----
	keyword test found at 0x105bb5227
```

[back to commands list](#Commands-list)



#### overridden_method

```stylus
(lldb) overridden_method
```

[back to commands list](#Commands-list)



### Trace:

#### mtrace - trace module

Trace all functions in the specified module. By default, only OC methods are traced. To trace swift module, you need to add the -a option.

```stylus
// begin trace
(lldb) mtrace LLDBCode
-----trace functions in LLDBCode-----
will trace 35 names
begin trace with Breakpoint 1: 35 locations
(lldb) c

// trace log
frame #0: 0x0000000102dd2fb8 LLDBCode`-[ViewController touchesBegan:withEvent:](self=0x00000001d4108040, _cmd="touchesBegan:withEvent:", touches=0x000000015fd0fff0, event=1 element) at ViewController.m:35
...
frame #0: 0x0000000102dd318c LLDBCode`__41-[ViewController touchesBegan:withEvent:]_block_invoke(.block_descriptor=0x0000000102ec1500) at ViewController.m:45
```

[back to commands list](#Commands-list)



#### **rtrace**

trace functions using regular expressions

```stylus
(lldb) rtrace -i GetDeviceInfo
begin trace with Breakpoint 4: where = CoreTelephony`_CTServerConnectionPhoneServicesGetDeviceInfo, address = 0x1bab0f6a0
...
begin trace with Breakpoint 8: where = MediaRemote`MRMediaRemoteGetDeviceInfo, address = 0x1c85b4c84
begin trace with 5 breakpoint(s)
```



#### notifier

trace notificaton posting action

```stylus
(lldb) notifier
begin trace -[NSNotificationCenter postNotification:] with Breakpoint 8
begin trace -[NSNotificationCenter postNotificationName:object:userInfo:] with Breakpoint 9
begin trace CFNotificationCenterPostNotificationWithOptions with Breakpoint 10
```

[back to commands list](#Commands-list)



### Patch:

#### patch (private)

Patch bytes in user modules.

```stylus
(lldb) patch c0 03 5f d6
-----try to patch bytes in LLDBCode-----
patch 32 locations
```

[back to commands list](#Commands-list)



### Dump:

#### dmodule - dump module (private)

Dump the specified module from memory.

```stylus
(lldb) dmodule UIKit
dumping UIKit, this may take a while
ignore __DATA.__bss
ignore __DATA.__common
ignore __DATA_DIRTY.__bss
ignore __DATA_DIRTY.__common
924057600 bytes dump to ~/lldb_dump_macho/UIKit/macho_UIKit
```

> 注意：加载时被修改的数据未恢复

[back to commands list](#Commands-list)



#### dapp - dump App (private)

Dump current iOS App (arm64 only). Typically, dump decrypted ipa from jailbreak device.

```stylus
(lldb) dapp
dumping JITDemo, this may take a while
copy file JITDemo.app/Base.lproj/LaunchScreen.storyboardc/01J-lp-oVM-view-Ze5-6b-2t3.nib
...
copy file JITDemo.app/embedded.mobileprovision
no file need patch
Generating "JITDemo.ipa"
dump success, ipa path: /Users/xxx/lldb_dump_macho/JITDemo/JITDemo.ipa
```

[back to commands list](#Commands-list)



### Shell command

#### addcmd

Add a lldb command for mac command line tool.

```stylus
(lldb) addcmd which
Add command script successfully, try using it
(lldb) which
usage: which [-as] program ...
(lldb) which ls
/bin/ls
```

#### delcmd

Delete lldb command added by addcmd.

```stylus
(lldb) delcmd which
command "which" has been deleted
(lldb) which
error: 'which' is not a valid command.
```

[back to commands list](#Commands-list)



#### pwd

```stylus
(lldb) pwd
/Users/xxx
```

#### cd

```stylus
(lldb) cd /
(lldb) pwd
/
```

[back to commands list](#Commands-list)



#### ls

List directory contents on Mac.

```stylus
(lldb) ls -l
total 10
drwxrwxr-x  61 root  admin  1952 Jul  4 12:28 Applications
drwxr-xr-x  71 root  wheel  2272 May 21 09:49 Library
drwxr-xr-x@ 10 root  wheel   320 May  7 15:01 System
drwxr-xr-x   5 root  admin   160 May 21 09:48 Users
drwxr-xr-x   4 root  wheel   128 Jul  4 12:29 Volumes
drwxr-xr-x@ 39 root  wheel  1248 May  7 15:01 bin
drwxr-xr-x   2 root  wheel    64 Jul 14  2022 cores
dr-xr-xr-x   3 root  wheel  4982 Jul  2 16:28 dev
lrwxr-xr-x@  1 root  wheel    11 May  7 15:01 etc -> private/etc
lrwxr-xr-x   1 root  wheel    25 Jul  2 16:29 home -> /System/Volumes/Data/home
drwxr-xr-x   4 root  wheel   128 May 16 14:10 opt
drwxr-xr-x   6 root  wheel   192 Jul  2 16:29 private
drwxr-xr-x@ 64 root  wheel  2048 May  7 15:01 sbin
lrwxr-xr-x@  1 root  wheel    11 May  7 15:01 tmp -> private/tmp
drwxr-xr-x@ 11 root  wheel   352 May  7 15:01 usr
lrwxr-xr-x@  1 root  wheel    11 May  7 15:01 var -> private/var
```



### File:

#### commads to get common directory

```stylus
(lldb) bundle_dir
/var/containers/Bundle/Application/63954B0E-79FA-42F2-A7EA-3568026008A1/Interlock.app
(lldb) home_dir
/var/mobile/Containers/Data/Application/1161FDFD-5D69-47CD-B5C6-C2724B8E2F28
(lldb) doc_dir
/var/mobile/Containers/Data/Application/1161FDFD-5D69-47CD-B5C6-C2724B8E2F28/Documents
(lldb) caches_dir
/var/mobile/Containers/Data/Application/1161FDFD-5D69-47CD-B5C6-C2724B8E2F28/Library/Caches
(lldb) lib_dir
/var/mobile/Containers/Data/Application/1161FDFD-5D69-47CD-B5C6-C2724B8E2F28/Library
(lldb) tmp_dir
/var/mobile/Containers/Data/Application/1161FDFD-5D69-47CD-B5C6-C2724B8E2F28/tmp
(lldb) group_dir
/private/var/mobile/Containers/Shared/AppGroup/9460EA21-AE6A-4220-9BB3-6EC8B971CDAE
```

[back to commands list](#Commands-list)



#### ils

List directory contents on remote device, just like `ls -lh` on Mac.

```stylus
(lldb) ils bu
/var/containers/Bundle/Application/D0419A6E-053C-4E35-B422-7C0FD6CAB060/Interlock.app
drwxr-xr-x        128B 1970-01-01 00:00:00 +0000 Base.lproj
drwxr-xr-x         96B 1970-01-01 00:00:00 +0000 _CodeSignature
drwxr-xr-x         64B 1970-01-01 00:00:00 +0000 META-INF
-rw-r--r--        1.5K 2023-05-16 03:17:32 +0000 Info.plist
-rwxr-xr-x      103.0K 2023-05-19 11:07:02 +0000 Interlock
-rw-r--r--          8B 2023-05-16 03:17:32 +0000 PkgInfo
-rw-r--r--      194.7K 2023-05-16 03:17:31 +0000 embedded.mobileprovision
(lldb) ils home
/var/mobile/Containers/Data/Application/09E63130-623F-4124-BCBB-59E20BD28964
drwxr-xr-x         96B 2023-05-19 07:28:01 +0000 Documents
drwxr-xr-x        128B 2023-05-16 04:51:14 +0000 Library
drwxr-xr-x         64B 1970-01-01 00:00:00 +0000 SystemData
drwxr-xr-x         64B 2023-05-16 04:51:14 +0000 tmp
(lldb) ils /var/mobile/Containers/Data/Application/09E63130-623F-4124-BCBB-59E20BD28964/Documents
-rw-r--r--         18B 2023-05-16 05:36:05 +0000 report.txt
```

[back to commands list](#Commands-list)



#### dfile - download file

Download file from home, bundle or group path.

```stylus
(lldb) dfile /var/containers/Bundle/Application/7099B2B8-39BE-4204-9BEB-5DF6A75BAA29/JITDemo.app/Info.plist
dumping Info.plist, this may take a while
1464 bytes written to '/Users/xxx/Info.plist'
```

or

```stylus
(lldb) dfile bundle/Info.plist
dumping Info.plist, this may take a while
1464 bytes written to '/Users/xxx/Info.plist'
```

[back to commands list](#Commands-list)



#### ddir - download directory

Download dir from home, bundle or group path.

```stylus
(lldb) ddir /var/containers/Bundle/Application/7099B2B8-39BE-4204-9BEB-5DF6A75BAA29/JITDemo.app
dumping JITDemo.app, this may take a while
1197 bytes written to '/Users/xxx/JITDemo.app/Base.lproj/LaunchScreen.storyboardc/01J-lp-oVM-view-Ze5-6b-2t3.nib'
...
8 bytes written to '/Users/xxx/JITDemo.app/PkgInfo'
196731 bytes written to '/Users/xxx/JITDemo.app/embedded.mobileprovision'
```

[back to commands list](#Commands-list)



#### ufile - upload local file to device

Upload local file to the specified directory or path on device.

```stylus
(lldb) doc
/var/mobile/Containers/Data/Application/1171F451-C2DC-47E6-B6E3-74A0FE5A6572/Documents
(lldb) ufile /Users/xxx/uploadfile /var/mobile/Containers/Data/Application/1171F451-C2DC-47E6-B6E3-74A0FE5A6572/Documents
uploading uploadfile, this may take a while
upload success
(lldb) ufile /Users/xxx/uploadfile /var/mobile/Containers/Data/Application/1171F451-C2DC-47E6-B6E3-74A0FE5A6572/Documents/test
uploading uploadfile, this may take a while
upload success
(lldb) ils doc
/var/mobile/Containers/Data/Application/1171F451-C2DC-47E6-B6E3-74A0FE5A6572/Documents
-rw-r--r--       12.1K 2023-08-10 07:11:29 +0000 test
-rw-r--r--       12.1K 2023-08-10 07:11:22 +0000 uploadfile
```

[back to commands list](#Commands-list)



#### irm - remove file

Remove file or directory on remote device.

```stylus
(lldb) ils doc
/var/mobile/Containers/Data/Application/B142040E-B1A0-4E97-8E76-03357585BFF8/Documents
-rw-r--r--       12.1K 2023-08-10 07:32:05 +0000 test
-rw-r--r--       12.1K 2023-08-10 08:22:40 +0000 uploadfile
(lldb) irm /var/mobile/Containers/Data/Application/B142040E-B1A0-4E97-8E76-03357585BFF8/Documents/uploadfile
remove success
(lldb) ils doc
/var/mobile/Containers/Data/Application/B142040E-B1A0-4E97-8E76-03357585BFF8/Documents
-rw-r--r--       12.1K 2023-08-10 07:32:05 +0000 test
```

[back to commands list](#Commands-list)



### Module:

#### image_list

List current executable and dependent shared library images, sorted by load address.

```stylus
(lldb) image_list
index     load addr(slide)     vmsize path
------------------------------------------------------------
[  0] 0x1048dc000(0x0048dc000) 655.4K /private/var/containers/Bundle/Application/D5752641-F291-4170-9576-67D8011C88D3/JITDemo.app
[  1] 0x10497c000(0x10497c000) 131.1K /Users/xxx/Library/Developer/Xcode/DerivedData/LLDBJIT-xxx/Build/Products/Debug-iphoneos/JITDemo.app/Frameworks/LLDBJIT.framework/LLDBJIT
...
```

```stylus
(lldb) image_list -v
index    load addr - end addr(slide)         vmsize arch  uuid   path
------------------------------------------------------------
[  0] 0x1048dc000 - 0x10497c000(0x0048dc000) 655.4K arm64 5B4BAB05-B614-339D-909E-1877AA53AD11 /private/var/containers/Bundle/Application/D5752641-F291-4170-9576-67D8011C88D3/JITDemo.app
[  1] 0x10497c000 - 0x10499c000(0x10497c000) 131.1K arm64 E8938575-D438-3175-B846-B60CF9DE0304 /Users/xxx/Library/Developer/Xcode/DerivedData/LLDBJIT-xxx/Build/Products/Debug-iphoneos/JITDemo.app/Frameworks/LLDBJIT.framework/LLDBJIT
...
```

[back to commands list](#Commands-list)



#### info_plist - print Info.plist

```stylus
(lldb) info_plist
-----parsing module Demo-----
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	...
</dict>
</plist>
```

[back to commands list](#Commands-list)



#### executable - print main executable name

Print main executable name.

```stylus
(lldb) executable
LLDBCode
```



#### bundle_id

Print bundle identifer

```stylus
(lldb) bundle_id
xxx.com.test.xxx
```

[back to commands list](#Commands-list)



#### group_id

Print group id

```stylus
(lldb) group_id
group id not found
```



#### team_id

Print team identifer

```stylus
(lldb) team_id
xxxxxxxxxx
```

[back to commands list](#Commands-list)



#### appdelegate

Find the class that conforms to the UIApplicationDelegate protocol.

```stylus
(lldb) appdelegate
AppDelegate
```



#### mname - module name

Get module name with header address.

```stylus
(lldb) mname 0x1043e8000
LLDBCode
```

[back to commands list](#Commands-list)



#### segments - print segments

Print segments and section info of macho.

```stylus
(lldb) segments JITDemo
-----parsing module JITDemo-----
       [start - end)			size		name
------------------------------------------------------------
[0x497c000  -0x10497c000)		0x100000000 __PAGEZERO
------------------------------------------------------------
[0x10497c000-0x104984000)		0x8000      __TEXT
	[0x104980000-0x1049811b0)	0x11b0        __text
	[0x1049811b0-0x104981270)	0xc0          __stubs
	[0x104981270-0x104981348)	0xd8          __stub_helper
	[0x104981348-0x1049815a8)	0x260         __objc_stubs
	[0x1049815a8-0x1049824e5)	0xf3d         __objc_methname
	[0x1049824e5-0x104982736)	0x251         __cstring
	[0x104982736-0x1049827b5)	0x7f          __objc_classname
	[0x1049827b5-0x1049832de)	0xb29         __objc_methtype
	[0x1049832e0-0x104983360)	0x80          __unwind_info
------------------------------------------------------------
[0x104984000-0x104988000)		0x4000      __DATA
	[0x104984000-0x104984030)	0x30          __got
	[0x104984030-0x1049840b0)	0x80          __la_symbol_ptr
	[0x1049840b0-0x1049841f0)	0x140         __cfstring
	[0x1049841f0-0x104984210)	0x20          __objc_classlist
	[0x104984210-0x104984218)	0x8           __objc_nlclslist
	[0x104984218-0x104984238)	0x20          __objc_protolist
	[0x104984238-0x104984240)	0x8           __objc_imageinfo
	[0x104984240-0x104985408)	0x11c8        __objc_const
	[0x104985408-0x1049854a8)	0xa0          __objc_selrefs
	[0x1049854a8-0x1049854e0)	0x38          __objc_classrefs
	[0x1049854e0-0x1049854e8)	0x8           __objc_superrefs
	[0x1049854e8-0x1049854f0)	0x8           __objc_ivar
	[0x1049854f0-0x104985630)	0x140         __objc_data
	[0x104985630-0x1049857c0)	0x190         __data
	[0x1049857c0-0x104985800)	0x40          __common
	[0x104985800-0x104985818)	0x18          __bss
------------------------------------------------------------
[0x104988000-0x104994000)		0xc000      __LINKEDIT
	[0x1049887c0-0x1049887f0)	0x30          Function Starts
	[0x1049887f0-0x104989d10)	0x1520        Symbol Table
	[0x1049887f0-0x1049887f0)	0x0           Data In Code Entries
	[0x104989d10-0x104989da8)	0x98          Dynamic Symbol Table
	[0x104989da8-0x10498b470)	0x16c8        String Table
	[0x10498b470-0x104990140)	0x4cd0        Code Signature
```

[back to commands list](#Commands-list)



#### main

Print the address of main function.

```stylus
(lldb) main
function main at 0x102911b70, fileoff: 0x5b70
```



#### initfunc - print mod init func

Dump module init function(s) in user modules.

```stylus
(lldb) initfunc
-----try to lookup init function in JITDemo-----
address = 0x100e08cb0 JITDemo`entry1 at main.m:708:0
address = 0x100e0960c JITDemo`entry2 at main.m:740:0
```

[back to commands list](#Commands-list)



#### func_starts - function starts

Print function starts

```stylus
(lldb) func_starts
-----parsing module JITDemo-----
address = 0x1021bc5c8 where = JITDemo`globalBlock_block_invoke at ViewController.m:17
address = 0x1021bc608 where = JITDemo`+[ViewController load] at ViewController.m:27
...
address = 0x1021bdae0 where = JITDemo`-[SceneDelegate .cxx_destruct] at SceneDelegate.m:14
(lldb) 
```



#### got - print `__got` section

```stylus
(lldb) got
-----parsing module JITDemo-----
address = 0x1ac734ce0 where = Foundation`NSFileModificationDate
...
address = 0x180d44900 where = libobjc.A.dylib`objc_msgSend
address = 0x1814ce1c0 where = libdyld.dylib`dyld_stub_binder
13 location(s) found
```

[back to commands list](#Commands-list)



#### lazy_sym - print `__la_symbol_ptr` section

```stylus
(lldb) lazy_sym
-----parsing module JITDemo-----
address = 0x104c7fe14 where = JITDemo`my_NSHomeDirectory at ViewController.m:63 -> NSHomeDirectory
...
address = 0x1815fb950 where = libsystem_kernel.dylib`open -> open
36 location(s) found
```



#### entitlements - dump entitlements

Dump codesign entitlements of the specified module if any.

```stylus
(lldb) ent
Interlock:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>application-identifier</key>
	<string>XXXX.com.xxx.Interlock</string>
	<key>com.apple.developer.team-identifier</key>
	<string>XXXX</string>
	<key>com.apple.security.application-groups</key>
	<array/>
	<key>get-task-allow</key>
	<true/>
</dict>
</plist>
```

```stylus
(lldb) ent UIKit
UIKit apparently does not contain code signature
```

[back to commands list](#Commands-list)



#### classes - print class names

Print class names in the specified module.

```stylus
(lldb) classes
AppDelegate <0x10468e378>
SceneDelegate <0x10468e418>
ViewController <0x10468e260>
```

[back to commands list](#Commands-list)



### Assembly

#### inst2bytes

Convert assembly instructions to machine code.

```stylus
(lldb) inst2bytes 'mov    x9, sp;mov    x8, x0'
disassembly: 
       0: 910003e9     	mov	x9, sp
       4: aa0003e8     	mov	x8, x0
machine code: e9030091e80300aa
```



#### bytes2inst

Convert machine code to assembly instructions.

```stylus
(lldb) bytes2inst e9030091e80300aa
<+0>:	mov	x9, sp
<+4>:	mov	x8, x0
```

[back to commands list](#Commands-list)



### Memory:

#### read_mem_as_addr

```stylus
(lldb) seg
...
------------------------------------------------------------
[0x102ee0000-0x102ee4000)		0x4000      __DATA
	[0x102ee0000-0x102ee0000)	0x68          __got
...
	[0x102ee02e0-0x102ee0560)	0x280         __cfstring
...

// read __got section
(lldb) read_mem_as_addr 0x102ee0000 0x102ee0068
0x102ee0000: 0x00000001ac734ce0 Foundation`NSFileModificationDate
...
0x102ee0058: 0x0000000180d44900 libobjc.A.dylib`objc_msgSend
0x102ee0060: 0x00000001814ce1c0 libdyld.dylib`dyld_stub_binder

// read __cfstring section
(lldb) read_mem_as_addr 0x102ee02e0 0x102ee0560
0x102ee02e0: 0x00000001b40b2610 (void *)0x00000001b40b25c0: __NSCFConstantString
0x102ee02e8: 0x00000000000007c8
0x102ee02f0: 0x0000000102ede156 "%s"
0x102ee02f8: 0x0000000000000002
...
0x102ee0540: 0x00000001b40b2610 (void *)0x00000001b40b25c0: __NSCFConstantString
0x102ee0548: 0x00000000000007c8
0x102ee0550: 0x0000000102ede2cc "Default Configuration"
0x102ee0558: 0x0000000000000015
```

[back to commands list](#Commands-list)



#### read_cstring - read memory as c style string

```stylus
(lldb) seg
...
	[0x10077b3ae-0x10077b424)	0x76          __objc_classname
....
	[0x100782898-0x1007857f0)	0x2f58        String Table
...

// read __TEXT.__objc_classname
(lldb) read_cstring 0x10077b3ae 0x10077b424
0x10077b3ae: "ViewController"
...
0x10077b414: "UISceneDelegate"
9 locations found

// read String Table
(lldb) read_cstring 0x100782898 0x1007857f0
0x100782898: " "
0x10078289a: "_JITDemoVersionNumber"
...
0x1007857c8: "__OBJC_PROTOCOL_$_UIWindowSceneDelegate"
338 locations found
```

[back to commands list](#Commands-list)



### Others:

#### symbolize

Symbolize address, uncaught exception addresses list or crash report file.

Symbolize address

```stylus
(lldb) dis -c 1 -a 0x1045843d4
JITDemo`___lldb_unnamed_symbol302:
    0x1045843d4 <+0>: sub    sp, sp, #0x1f0
(lldb) symbolize 0x1045843d4
0x1045843d4: JITDemo`-[ViewController ls_dir:] + 0
```



Symbolize uncaught exception addresses list

```stylus
(lldb) symbolic (0x1845aed8c 0x1837685ec 0x18450a448 0x104360f78 0x18e4fd83c 0x18e3a3760 0x18e39d7c8 0x18e392890 0x18e3911d0 0x18eb72d1c 0x18eb752c8 0x18eb6e368 0x184557404 0x184556c2c 0x18455479c 0x184474da8 0x186459020 0x18e491758 0x104361da0 0x183f05fc0)
backtrace: 
frame #0: 0x1845aed8c CoreFoundation`__exceptionPreprocess + 228
frame #1: 0x1837685ec libobjc.A.dylib`objc_exception_throw + 56
frame #2: 0x18450a448 CoreFoundation`-[__NSArray0 objectEnumerator] + 0
frame #3: 0x104360f78 JITDemo`-[ViewController touchesBegan:withEvent:] + at ViewController.m:51:5
...
```

or

```stylus
(lldb) symbolic 0x1845aed8c 0x1837685ec 0x18450a448 0x104360f78 0x18e4fd83c 0x18e3a3760 0x18e39d7c8 0x18e392890 0x18e3911d0 0x18eb72d1c 0x18eb752c8 0x18eb6e368 0x184557404 0x184556c2c 0x18455479c 0x184474da8 0x186459020 0x18e491758 0x104361da0 0x183f05fc0
backtrace: 
frame #0: 0x1845aed8c CoreFoundation`__exceptionPreprocess + 228
frame #1: 0x1837685ec libobjc.A.dylib`objc_exception_throw + 56
frame #2: 0x18450a448 CoreFoundation`-[__NSArray0 objectEnumerator] + 0
frame #3: 0x104360f78 JITDemo`-[ViewController touchesBegan:withEvent:] + at ViewController.m:51:5
...
```



Symbolize crash report file.

```stylus
(lldb) symbolize /Users/xxx/test/JITDemo-2024-07-29-163051.ips
```

or

```stylus
(lldb) symbolize /Users/xxx/Desktop/JITDemo.crash
```

[back to commands list](#Commands-list)



#### find_el - find endless loop

Detects endless loop in all threads at this point.

```objective-c
- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    int a = 1;
    NSLog(@"%s", __PRETTY_FUNCTION__);
    while (a) {
        a++;
    }
}
```

```stylus
# touch device screen
2023-05-20 12:29:52.604910+0800 Interlock[56660:1841567] -[ViewController touchesBegan:withEvent:]
# pause program execution, then execute find_el in lldb
(lldb) find_el
Breakpoint 1: where = Interlock`-[ViewController touchesBegan:withEvent:] + 136 at ViewController.mm:34:5, address = 0x109dd8d48
Breakpoint 2: where = Interlock`main + 110 at main.m:17:5, address = 0x109dd911e
delete breakpoint 2
call Interlock`-[ViewController touchesBegan:withEvent:] + 136 at ViewController.m:34:5, 22 times per second, hit_count: 100
...
```

[back to commands list](#Commands-list)



#### thread_eb - extended backtrace of thread

Get extended backtrace of thread.

```stylus
(lldb) bt
* thread #2, queue = 'com.apple.root.default-qos', stop reason = breakpoint 6.1
  * frame #0: 0x0000000104ab58f8 Concurrency`__41-[ViewController touchesBegan:withEvent:]_block_invoke(.block_descriptor=0x0000000104ab80f8) at ViewController.m:29:13
    frame #1: 0x0000000104df51dc libdispatch.dylib`_dispatch_call_block_and_release + 24
    frame #2: 0x0000000104df519c libdispatch.dylib`_dispatch_client_callout + 16
    frame #3: 0x0000000104e01200 libdispatch.dylib`_dispatch_queue_override_invoke + 968
    frame #4: 0x0000000104e067c8 libdispatch.dylib`_dispatch_root_queue_drain + 604
    frame #5: 0x0000000104e06500 libdispatch.dylib`_dispatch_worker_thread3 + 136
    frame #6: 0x0000000181fc3fac libsystem_pthread.dylib`_pthread_wqthread + 1176
    frame #7: 0x0000000181fc3b08 libsystem_pthread.dylib`start_wqthread + 4

(lldb) thread_eb
thread #4294967295: tid = 0x190c, 0x0000000104e907cc libdispatch.dylib`_dispatch_root_queue_push_override + 160, queue = 'com.apple.main-thread'
    frame #0: 0x0000000104e907cc libdispatch.dylib`_dispatch_root_queue_push_override + 160
    frame #1: 0x0000000104ded884 Concurrency`-[ViewController touchesBegan:withEvent:](self=<unavailable>, _cmd=<unavailable>, touches=<unavailable>, event=<unavailable>) at ViewController.m:25:5
    frame #2: 0x000000018bb1583c UIKit`forwardTouchMethod + 340
    frame #3: 0x000000018b9bb760 UIKit`-[UIResponder touchesBegan:withEvent:] + 60
...
```

[back to commands list](#Commands-list)



## Credits

https://github.com/DerekSelander/LLDB

https://github.com/facebook/chisel

https://github.com/aaronst/macholibre

## License

YJLLDB is released under the Apache License 2.0. See LICENSE file for details.

