# YJLLDB

一些常用的 LLDB 命令，用于 iOS 调试与逆向工程。
Some commonly used LLDB commands for iOS debugging and reverse engineering.

## Documentation

- [Installation](#installation)
- [Available Commands](##-available-commands)
  - [Breakpoint Commands](#breakpoint-commands)
  - [Search Commands](#search-commands)
  - [Trace Commands](#trace-commands)
  - [Patch Commands](#patch-commands)
  - [Dump Commands](#dump-commands)
  - [Shell Commands](#shell-commands)
  - [File Operations](#file-operations)
  - [Module Analysis](#module-analysis)
  - [Objective-C Commands](#objective-c-commands)
  - [Assembly Commands](#assembly-commands)
  - [Memory Commands](#memory-commands)
  - [Symbolize Commands](#symbolize-commands)
  - [DebugKit Commands](#debugkit-commands)
  - [Other Commands](#other-commands)
- [Commands in Detail](#commands-in-detail)
- [Credits](#credits)
- [License](#license)

## Available Commands

### Breakpoint Commands
- [bab - break at bytes](#bab---break-at-bytes)
- [baf - break all functions in module](#baf---break-all-functions-in-module)
- [bdc - breakpoint disable current](#bdc---breakpoint-disable-current)
- [bda - breakpoint disable at class](#bda---breakpoint-disable-at-class)
- [bdr - breakpoint disable in range](#bdr--breakpoint-disable-in-range)
- [bdelr - breakpoint delete in range](#bdelr---breakpoint-delete-in-range)
- [bblocks - break blocks (arm64 only)](#bblocks---break-blocks-arm64-only)
- [binitfunc - break init func](#binitfunc---break-init-func)
- [bmethod - break method](#bmethod---break-method)
- [bmain - break main function](#bmain---break-main-function)
- [bsave - save breakpoints](#bsave---save-breakpoints)
- [bload - restore breakpoints](#bload---restore-breakpoints)
- [bclear - clear unresolved breakpoints](#bclear---clear-unresolved-breakpoints)

### Search Commands
- [slookup - lookup string](#slookup---lookup-string)
- [blookup - lookup bytes](#blookup---lookup-bytes)
- [fblock - find block (arm64 only)](#fblock---find-block-arm64-only)
- [blocks - find blocks (arm64 only)](#blocks---find-blocks-arm64-only)
- [ffunc - find function](#ffunc---find-function)
- [ilookup - find instructions](#ilookup---find-instructions)
- [finlinehooked (private)](#finlinehooked-private)

### Trace Commands
- [mtrace - trace module](#mtrace---trace-module)
- [rtrace](#rtrace)
- [notifier](#notifier)

### Patch Commands
- [patch (private)](#patch-private)

### Dump Commands
- [dmodule - dump module (private)](#dmodule---dump-module-private)
- [dapp - dump App (private)](#dapp---dump-app-private)
- [denv - dump env](#denv---dump-env)

### Shell Commands
- [addcmd](#addcmd)
- [delcmd](#delcmd)
- [pwd](#pwd)
- [cd](#cd)
- [ls](#ls)

### File Operations
- [commads to get common directory](#commads-to-get-common-directory)
- [ils](#ils)
- [dfile - download file](#dfile---download-file)
- [ddir - download directory](#ddir---download-directory)
- [ufile - upload local file to device](#ufile---upload-local-file-to-device)
- [irm - remove file](#irm---remove-file)

### Module Analysis
- [image_list](#image_list---list-loaded-modules)
- [info_plist](#info_plist---print-infoplist)
- [executable - print main executable name](#executable---print-main-executable-name)
- [appdelegate](#appdelegate)
- [mname - module name](#mname---module-name)
- [lcs - print load commands](#lcs---print-load-commands)
- [libs - print shared libraries used](#libs---print-shared-libraries-used)
- [segments - print segments](#segments---print-segments)
- [main](#main)
- [initfunc - print init func](#initfunc---print-init-func)
- [func_starts - function starts](#func_starts---function-starts)
- [got - print __got section](#got---print-__got-section)
- [lazy_sym - print __la_symbol_ptr section](#lazy_sym---print-__la_symbol_ptr-section)
- [entitlements - dump entitlements](#entitlements---dump-entitlements)
- [offset - get file offset for address](#offset---get-file-offset-for-address)
- [dcls - class dump](#dcls---class-dump)
- [dependency - list dependencies](#dependency---list-dependencies)

### Objective-C Commands
- [classes - print class names](#classes---print-class-names)
- [dmethods](#dmethods)
- [divars](#divars)
- [duplicate_class](#duplicate_class)
- [overridden_method](#overridden_method)

### Assembly Commands
- [inst2bytes](#inst2bytes---instructions-to-bytes)
- [bytes2inst](#bytes2inst---bytes-to-instructions)

### Memory Commands
- [read_mem_as_addr](#read_mem_as_addr)
- [read_cstring - read memory as c style string](#read_cstring---read-memory-as-c-style-string)
- [jit_mem](#jit_mem---read-memory-with-JIT-code)

### Symbolize Commands
- [load_dSYM](#load_dSYM)
- [symbolize](#symbolize)

### DebugKit Commands
- [UIControl extension](#uicontrol-extension)
- [NSObject extension](#NSObject-extension)
- [NSBlock extension](#NSBlock-extension)
- [iOS Sandbox Explorer](#iOS-Sandbox-Explorer)
- [vmmap](#vmmap)

### Other Commands
- [find_el - find endless loop](#find_el---find-endless-loop)
- [thread_eb - extended backtrace of thread](#thread_eb---extended-backtrace-of-thread)

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/geekonion/YJLLDB.git
   cd YJLLDB
   ```

2. **Locate or create the LLDB initialization file**

   The LLDB initialization file is located at `~/.lldbinit`. If it doesn't exist, create it:
   ```bash
   touch ~/.lldbinit
   ```

3. **Add YJLLDB to your LLDB configuration**

   Open `~/.lldbinit` in your preferred text editor and add the following line:
   ```bash
   command script import /path/to/YJLLDB/src/yjlldb.py
   ```

   **Replace `/path/to/YJLLDB` with the actual path where you cloned the repository.**

   For example, if you cloned it to your home directory:
   ```bash
   command script import ~/YJLLDB/src/yjlldb.py
   ```

4. **Verify the installation**

   Start LLDB and check if YJLLDB commands are available:
   ```bash
   lldb
   (lldb) help
   ```

   You should see YJLLDB commands listed in the help output.

---

## Commands in Detail

### Breakpoint Commands

#### `bab` - break at bytes

Set breakpoints at specific byte patterns in user modules.
Useful for locating instructions such as `ret`, `nop`, etc. across your application.

```bash
# Break at all 'ret' instructions (ARM64: c0 03 5f d6)
(lldb) bab c0 03 5f d6
Breakpoint 1: where = LLDBCode`-[ViewController viewDidLoad] + 240 at ViewController.m:29:1, address = 0x1029b3008
...
set 728 breakpoints

# Verify the breakpoint location
(lldb) x 0x1029b3008
0x1029b3008: c0 03 5f d6 ff 03 03 d1 fd 7b 0b a9 fd c3 02 91  .._......{......

(lldb) dis -s 0x1029b3008 -c 1
LLDBCode`-[ViewController viewDidLoad]:
    0x1029b3008 <+240>: ret
```

[⬆ Back to Breakpoint Commands](#Breakpoint-Commands)



#### `baf` - break all functions in-module

Set breakpoints on all functions and methods in the specified module.
Extremely useful for comprehensive tracing and understanding program flow.

```bash
# Break all functions in Foundation framework
(lldb) baf Foundation
-----break functions in Foundation-----
will set breakpoint for 13880 names
Breakpoint 4: 13961 locations
```

[⬆ Back to Breakpoint Commands](#Breakpoint-Commands)



#### `bdc` - breakpoint disable current

Disable current breakpoint and continue execution.
Quick way to bypass a breakpoint without deleting it.

```bash
(lldb) thread info
thread #1: tid = 0x2cb739, 0x000000018354f950 libsystem_kernel.dylib`open, queue = 'com.apple.main-thread', stop reason = breakpoint 5.13

(lldb) bdc
disable breakpoint 5.13 [0x18354f950]libsystem_kernel.dylib`open
and continue
```

[⬆ Back to Breakpoint Commands](#Breakpoint-Commands)



#### `bda` - breakpoint disable at class

Disable breakpoint(s) at the specified class.

```bash
(lldb) bda -i ViewController
disable breakpoint 1.8: where = LLDBCode`__41-[ViewController touchesBegan:withEvent:]_block_invoke_4 at ViewController.m:57, address = 0x00000001040e32f8, unresolved, hit count = 1  Options: disabled
...
disable breakpoint 1.27: where = LLDBCode`__41-[ViewController touchesBegan:withEvent:]_block_invoke at ViewController.m:45, address = 0x00000001040e318c, unresolved, hit count = 1  Options: disabled

(lldb) bda -i ViewController(extension)
disable breakpoint 1.23: where = LLDBCode`-[ViewController(extension) test] at ViewController.m:20, address = 0x0000000102ec2e7c, unresolved, hit count = 0  Options: disabled
```

[⬆ Back to Breakpoint Commands](#Breakpoint-Commands)



#### `bdr`- breakpoint disable in range

Disable breakpoint(s) in the specified range.

```bash
(lldb) bdr 980~992
disable breakpoint 980.1: where = LLDBCode`-[Test .cxx_destruct] at Test.m:22, address = 0x00000001049fa1b0, unresolved, hit count = 0  Options: disabled
...
disable breakpoint 991.1: where = LLDBCode`func1 at Test.m:42, address = 0x00000001049faaf8, unresolved, hit count = 0  Options: disabled
```

[⬆ Back to Breakpoint Commands](#Breakpoint-Commands)



#### `bdelr` - breakpoint delete in range

Delete breakpoint(s) in the specified range.

```stylus
(lldb) br list 9
9: name = 'dlopen', locations = 1, resolved = 1, hit count = 0
  9.1: where = libdyld.dylib`dlopen, address = 0x00000001e9c6cc04, resolved, hit count = 0 

(lldb) bdelr 9-9
delete breakpoint 9

(lldb) br list 9
error: '9' is not a currently valid breakpoint ID.
error: Invalid breakpoint ID.
```

[⬆ Back to Breakpoint Commands](#Breakpoint-Commands)



#### `bblocks` - break blocks (arm64 only)

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

[⬆ Back to Breakpoint Commands](#Breakpoint-Commands)



#### `binitfunc` - break init func

Break module init function(s) of specified module.

```stylus
(lldb) binitfunc
-----try to lookup init function in JITDemo-----
mod init func pointers found: __DATA,__mod_init_func
Breakpoint 6: JITDemo`entry1 at main.m:708:0, address = 0x100e08cb0
Breakpoint 7: JITDemo`entry2 at main.m:740:0, address = 0x100e0960c
```



#### `bclass` - break class

Break methods of a stripped Objective-C class

```stylus
(lldb) bclass ApplicationProxy
Breakpoint 101: where = appstored`+[ApplicationProxy proxyMatchingBundleID:orItemID:], address = 0x104c34a64
Breakpoint 102: where = appstored`+[ApplicationProxy proxyForBundle:], address = 0x104c351e0
...
Breakpoint 200: where = appstored`-[ApplicationProxy .cxx_destruct], address = 0x104c36e68
set 100 breakpoints
```



#### `bmethod` - break method

Break the specified method(s) in user modules

```stylus
(lldb) bmethod load
-----try to method in JITDemo-----
Breakpoint 3: JITDemo`+[ViewController load] at ViewController.m:26:0, address = 0x1024f89bc
Breakpoint 4: JITDemo`+[AppDelegate load] at AppDelegate.m:16:0, address = 0x1024f96a4
-----try to method in LLDBJIT-----
set 2 breakpoints
```

[⬆ Back to Breakpoint Commands](#Breakpoint-Commands)



#### `bmain` - break main function

```stylus
(lldb) bmain
Breakpoint 9: BasicSyntax`___lldb_unnamed_symbol266, address = 0x10017c3fc
```

[⬆ Back to Breakpoint Commands](#Breakpoint-Commands)



#### `bsave` - save breakpoints

Save breakpoints (set by address) to a file.

List breakpoints

```stylus
(lldb) br list
Current breakpoints:
1: name = '_platform_memmove', locations = 1, resolved = 1, hit count = 3
  1.1: where = libsystem_platform.dylib`_platform_memmove, address = 0x00000001dc558e60, resolved, hit count = 3 
2: address = libsystem_platform.dylib[0x00000001d09d4e68], locations = 1, resolved = 1, hit count = 0
  2.1: where = libsystem_platform.dylib`_platform_memmove + 8, address = 0x00000001dc558e68, resolved, hit count = 0
```

save breakpoints

```stylus
(lldb) bsave
Breakpoints saved to /Users/xxx/YJLLDB/Caches/ACEObject.json
```



#### `bload` - restore breakpoints

```stylus
(lldb) bload
Breakpoint 3: where = libsystem_platform.dylib`_platform_memmove + 8, address = 0x1dc558e68
```



#### `bclear` - clear unresolved breakpoints

```stylus
(lldb) bclear
```

[⬆ Back to Breakpoint Commands](#Breakpoint-Commands)



### Search Commands

#### `slookup` - Lookup String

Search for a specific string within a memory range.
Useful for finding hardcoded strings, API keys, or other text data in memory.

```bash
# First, get module information
(lldb) image_list -c 8
index   load addr(slide)       vmsize path
--------------------------------------------------------
[  0] 0x1022e4000(0x0022e4000)  81.9K /var/containers/Bundle/Application/C134E909-CC52-4A93-9557-37BA808854D3/LLDBCode.app/LLDBCode
...
[  6] 0x18406f000(0x004044000)   8.7K /usr/lib/libSystem.B.dylib
[  7] 0x184071000(0x004044000) 394.1K /usr/lib/libc++.1.dylib

# Search for "PROGRAM" string in libSystem.B.dylib
(lldb) slookup PROGRAM 0x18406f000 0x184071000
found at 0x184070f7c where = [0x000000018002cf78-0x000000018002cfb8) libSystem.B.dylib.__TEXT.__const
1 locations found

# Examine the found location
(lldb) x 0x184070f7c -c 64
0x184070f7c: 50 52 4f 47 52 41 4d 3a 53 79 73 74 65 6d 2e 42  PROGRAM:System.B
0x184070f8c: 20 20 50 52 4f 4a 45 43 54 3a 4c 69 62 73 79 73    PROJECT:Libsys
0x184070f9c: 74 65 6d 2d 31 32 35 32 2e 35 30 2e 34 0a 00 00  tem-1252.50.4...
0x184070fac: 00 00 00 00 00 00 00 00 00 92 93 40 01 00 00 00  ...........@....
```

[⬆ Back to Search Commands](#Search-Commands)



#### `blookup` - lookup bytes

Lookup the specified bytes in user modules.

```stylus
(lldb) blookup c0 03 5f d6
-----try to lookup bytes in LLDBCode-----
0x104961018
...
0x104969ab8
32 locations found
```

[⬆ Back to Search Commands](#Search-Commands)



#### `fblock` - find block (arm64 only)

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

[⬆ Back to Search Commands](#Search-Commands)



#### `blocks` - find blocks (arm64 only)

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

[⬆ Back to Search Commands](#Search-Commands)



#### `ffunc` - find function

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

[⬆ Back to Search Commands](#Search-Commands)



#### `ilookup` - find instructions

```stylus
(lldb) ilookup svc
lookup instructions, this may take a while
-----try to lookup instructions in Demo-----
Demo[0x102ea83c8, 0x343c8]: svc    #0x80
Demo[0x102ea841c, 0x3441c]: svc    #0x80
...
15 locations found
```

[⬆ Back to Search Commands](#Search-Commands)



#### `finlinehooked` (private)

```stylus
(lldb) finlinehooked -s
-----parse functions in libBacktraceRecording.dylib-----
...
-----parse functions in libsystem_kernel.dylib-----
__execve 0x1d6efc094 is Dopamine inline hooked
...
necp_session_open 0x1d6efb1e4 is Dopamine inline hooked
-----parse functions in libc++abi.dylib-----
...

(lldb) dis -a 0x1d6efc094
libsystem_kernel.dylib`__execve:
    0x1d6efc094 <+0>:  movk   x16, #0xd240
    0x1d6efc098 <+4>:  movk   x16, #0x1f, lsl #16
    0x1d6efc09c <+8>:  movk   x16, #0x1, lsl #32
    0x1d6efc0a0 <+12>: movk   x16, #0x0, lsl #48
    0x1d6efc0a4 <+16>: br     x16
    0x1d6efc0a8 <+20>: bl     0x1d6ef1b30               ; cerror_nocancel
    0x1d6efc0ac <+24>: mov    sp, x29
    0x1d6efc0b0 <+28>: ldp    x29, x30, [sp], #0x10
    0x1d6efc0b4 <+32>: ret    
    0x1d6efc0b8 <+36>: ret    
```

[⬆ Back to Search Commands](#Search-Commands)



### Trace Commands

#### `mtrace` - trace module

Trace all functions in the specified module. By default, only OC methods are traced. To trace swift module, you need to add the -a option.

```bash
# Begin trace
(lldb) mtrace LLDBCode
-----trace functions in LLDBCode-----
will trace 35 names
begin trace with Breakpoint 1: 35 locations
(lldb) c

# Trace log
frame #0: 0x0000000102dd2fb8 LLDBCode`-[ViewController touchesBegan:withEvent:](self=0x00000001d4108040, _cmd="touchesBegan:withEvent:", touches=0x000000015fd0fff0, event=1 element) at ViewController.m:35
...
frame #0: 0x0000000102dd318c LLDBCode`__41-[ViewController touchesBegan:withEvent:]_block_invoke(.block_descriptor=0x0000000102ec1500) at ViewController.m:45
```



#### `rtrace`

trace functions using regular expressions

```stylus
(lldb) rtrace -i GetDeviceInfo
begin trace with Breakpoint 4: where = CoreTelephony`_CTServerConnectionPhoneServicesGetDeviceInfo, address = 0x1bab0f6a0
...
begin trace with Breakpoint 8: where = MediaRemote`MRMediaRemoteGetDeviceInfo, address = 0x1c85b4c84
begin trace with 5 breakpoint(s)
```



#### `notifier`

trace notificaton posting action

```stylus
(lldb) notifier
begin trace -[NSNotificationCenter postNotification:] with Breakpoint 8
begin trace -[NSNotificationCenter postNotificationName:object:userInfo:] with Breakpoint 9
begin trace CFNotificationCenterPostNotificationWithOptions with Breakpoint 10
```

[⬆ Back to Trace Commands](#Trace-Commands)



### Patch:

#### `patch` (private)

Patch bytes in user modules.

```stylus
(lldb) patch c0 03 5f d6
-----try to patch bytes in LLDBCode-----
patch 32 locations
```

[⬆ Back to Patch Commands](#Patch-Commands)



### Dump Commands

#### `dmodule` - dump module (private)

Dump the specified module from memory.

```bash
(lldb) dmodule UIKit
dumping UIKit, this may take a while
ignore __DATA.__bss
ignore __DATA.__common
ignore __DATA_DIRTY.__bss
ignore __DATA_DIRTY.__common
924057600 bytes dump to ~/lldb_dump_macho/UIKit/macho_UIKit
```

**Note:** Data modified during loading is not restored.



#### `dapp` - dump App (private)

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

[⬆ Back to Dump Commands](#Dump-Commands)



#### `denv` - dump env

```stylus
(lldb) denv
CFFIXED_USER_HOME=/private/var/mobile/Containers/Data/Application/72ACA6D5-EC32-4774-90A4-9C7C0C0981A4
HOME=/private/var/mobile/Containers/Data/Application/72ACA6D5-EC32-4774-90A4-9C7C0C0981A4
TMPDIR=/private/var/mobile/Containers/Data/Application/72ACA6D5-EC32-4774-90A4-9C7C0C0981A4/tmp/
XPC_SERVICE_NAME=UIKitApplication:com.xxx.JITDemo[fa82][rb-legacy]
PATH=/usr/bin:/bin:/usr/sbin:/sbin
XPC_FLAGS=0x0
LOGNAME=mobile
USER=mobile
SHELL=/bin/sh
	
hidden envs:
executable_path=/var/containers/Bundle/Application/1CE672BD-2B29-48C3-B8E7-C1CCA3CAB4B2/JITDemo.app/JITDemo
MallocNanoZone=1
ptr_munge=
main_stack=
executable_file=0x1a01000007,0xce2f8f
dyld_file=0x1a01000009,0x26089
executable_cdhash=8b9ae8cd0fda83160427d2eac822afe97fbaac44
executable_boothash=cbc87e2356dd5d5514484b2d950ed787e1da125e
th_port=
```

[⬆ Back to Dump Commands](#Dump-Commands)



### Shell Commands

#### `addcmd`

Add a lldb command for mac command line tool.

```bash
(lldb) addcmd which
Add command script successfully, try using it
(lldb) which
usage: which [-as] program ...
(lldb) which ls
/bin/ls
```

#### `delcmd`

Delete lldb command added by addcmd.

```bash
(lldb) delcmd which
command "which" has been deleted
(lldb) which
error: 'which' is not a valid command.
```

[⬆ Back to Shell Commands](#Shell-Commands)



#### `pwd`

```stylus
(lldb) pwd
/Users/xxx
```

#### `cd`

```stylus
(lldb) cd /
(lldb) pwd
/
```



#### `ls`

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

[⬆ Back to Shell Commands](#Shell-Commands)



### File Operations

#### commads to get common directory

Get common iOS app directories.

```bash
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



#### `ils`

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

[⬆ Back to File Operations](#File-Operations)



#### `dfile` - Download File

Download files from the iOS device to your local machine.
Supports both absolute paths and convenient shortcuts.

Using absolute path:

```bash
(lldb) dfile /var/containers/Bundle/Application/7099B2B8-39BE-4204-9BEB-5DF6A75BAA29/JITDemo.app/Info.plist
dumping Info.plist, this may take a while
1464 bytes written to '/Users/xxx/Info.plist'
```

Using convenient shortcuts:
```bash
# Download from bundle directory
(lldb) dfile bundle/Info.plist
dumping Info.plist, this may take a while
1464 bytes written to '/Users/xxx/Info.plist'

# Download from documents directory
(lldb) dfile doc/data.sqlite

# Download from home directory
(lldb) dfile home/Library/Preferences/com.app.plist
```

> Available Shortcuts
>
> - `bundle/` - App bundle directory
> - `home/` - App home directory
> - `doc/` - Documents directory
> - `lib/` - Library directory
> - `tmp/` - Temporary directory
>

[⬆ Back to File Operations](#File-Operations)



#### `ddir` - download directory

Download dir from home, bundle or group path.

```stylus
(lldb) ddir /var/containers/Bundle/Application/7099B2B8-39BE-4204-9BEB-5DF6A75BAA29/JITDemo.app
dumping JITDemo.app, this may take a while
1197 bytes written to '/Users/xxx/JITDemo.app/Base.lproj/LaunchScreen.storyboardc/01J-lp-oVM-view-Ze5-6b-2t3.nib'
...
8 bytes written to '/Users/xxx/JITDemo.app/PkgInfo'
196731 bytes written to '/Users/xxx/JITDemo.app/embedded.mobileprovision'
```

[⬆ Back to File Operations](#File-Operations)



#### `ufile` - upload local file to device

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

[⬆ Back to File Operations](#File-Operations)



#### `irm` - remove file

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

[⬆ Back to File Operations](#File-Operations)



### Module Analysis

#### `image_list` - list loaded modules

List current executable and dependent shared library images, sorted by load address.

```bash
(lldb) image_list
index     load_addr(slide)     vmsize path
------------------------------------------------------------
[  0] 0x1048dc000(0x0048dc000) 655.4K /private/var/containers/Bundle/Application/D5752641-F291-4170-9576-67D8011C88D3/JITDemo.app
[  1] 0x10497c000(0x10497c000) 131.1K /Users/xxx/Library/Developer/Xcode/DerivedData/LLDBJIT-xxx/Build/Products/Debug-iphoneos/JITDemo.app/Frameworks/LLDBJIT.framework/LLDBJIT
...
```

```bash
(lldb) image_list -v
index    load_addr - end_addr(slide)         vmsize arch  uuid   path
------------------------------------------------------------
[  0] 0x1048dc000 - 0x10497c000(0x0048dc000) 655.4K arm64 5B4BAB05-B614-339D-909E-1877AA53AD11 /private/var/containers/Bundle/Application/D5752641-F291-4170-9576-67D8011C88D3/JITDemo.app
[  1] 0x10497c000 - 0x10499c000(0x10497c000) 131.1K arm64 E8938575-D438-3175-B846-B60CF9DE0304 /Users/xxx/Library/Developer/Xcode/DerivedData/LLDBJIT-xxx/Build/Products/Debug-iphoneos/JITDemo.app/Frameworks/LLDBJIT.framework/LLDBJIT
...
```

```bash
(lldb) image_list -u
index     load_addr(slide)     vmsize path
------------------------------------------------------------
[  0] 0x1022f8000(0x0022f8000)  98.3K /private/var/containers/Bundle/Application/5DD99AF7-20FE-4369-AD0B-6A898DB12171/JITDemo.app
[  1] 0x1024cc000(0x1024cc000) 147.5K /Users/xxx/Library/Developer/Xcode/DerivedData/LLDBJIT-bwkzhcqdptajftbnezhkwkpwqlqb/Build/Products/Debug-iphoneos/JITDemo.app/Frameworks/LLDBJIT.framework/LLDBJIT
[  2] 0x1027a0000(0x1027a0000) 655.4K /Users/xxx/Library/Developer/Xcode/DerivedData/LLDBJIT-bwkzhcqdptajftbnezhkwkpwqlqb/Build/Products/Debug-iphoneos/JITDemo.app/JITDemo.debug.dylib
```

[⬆ Back to Module Analysis](#Module-Analysis)



#### `info_plist` - print Info.plist

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

[⬆ Back to Module Analysis](#Module-Analysis)



#### `executable` - print main executable name

Print main executable name.

```stylus
(lldb) executable
LLDBCode
```

[⬆ Back to Module Analysis](#Module-Analysis)



#### `appdelegate`

Find the class that conforms to the UIApplicationDelegate protocol.

```stylus
(lldb) appdelegate
AppDelegate
```



#### `mname` - module name

Get module name with header address.

```stylus
(lldb) p/x header
(const mach_header *) 0x1043e8000

(lldb) mname 0x1043e8000
LLDBCode

(lldb) mname header
LLDBCode
```

[⬆ Back to Module Analysis](#Module-Analysis)



#### `lcs` - print load commands

```stylus
(lldb) lcs
-----parsing module JITDemo-----
LC 00: LC_SEGMENT_64		Mem: 0x0005f4000-0x1005f4000	__PAGEZERO
LC 01: LC_SEGMENT_64		Mem: 0x1005f4000-0x1005fc000	__TEXT
	Mem: 0x1005f8000-0x1005f8708		__text				S_REGULAR S_ATTR_PURE_INSTRUCTIONS S_ATTR_SOME_INSTRUCTIONS
	...
	Mem: 0x1005fa328-0x1005fa398		__unwind_info		S_REGULAR
LC 02: LC_SEGMENT_64		Mem: 0x1005fc000-0x100600000	__DATA
	Mem: 0x1005fc000-0x1005fc018		__got				S_NON_LAZY_SYMBOL_POINTERS
	...
	Mem: 0x1005fd470-0x1005fd5f8		__data				S_REGULAR
LC 03: LC_SEGMENT_64		Mem: 0x100600000-0x100608000	__LINKEDIT
LC 04: LC_DYLD_INFO
LC 05: LC_SYMTAB
	Symbol table is at offset 0xc570 (50544), 274 entries
	String table is at offset 0xd520 (54560), 7440 bytes
LC 06: LC_SYMTAB
	209 local symbols at index 0
	11 external symbols at index 209
	24 undefined symbols at index 220
	No TOC
	No modtab
	28 indirect symbols at offset 0xd4b0
LC 07: LC_LOAD_DYLINKER			/usr/lib/dyld
...
LC 21: LC_CODE_SIGNATURE		Offset: 59232 Size: 20192
```

[⬆ Back to Module Analysis](#Module-Analysis)



#### `libs` - print shared libraries used

```stylus
(lldb) libs
-----parsing module JITDemo-----
/System/Library/Frameworks/UIKit.framework/UIKit
/System/Library/Frameworks/Foundation.framework/Foundation
/usr/lib/libobjc.A.dylib
/usr/lib/libSystem.B.dylib
/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation
```

[⬆ Back to Module Analysis](#Module-Analysis)



#### `segments` - print segments

Print segments and section info of macho.

```stylus
(lldb) segments JITDemo
-----parsing module JITDemo-----
       [start - end)			size		name				prot/flags
----------------------------------------------------------------------------------------------------
[0x4570000  -0x104570000)		0x100000000 __PAGEZERO			---/---
----------------------------------------------------------------------------------------------------
[0x104570000-0x104578000)		0x8000      __TEXT				r-x/r-x
	[0x104574000-0x104574708)	0x708         __text			S_REGULAR S_ATTR_PURE_INSTRUCTIONS S_ATTR_SOME_INSTRUCTIONS
	[0x104574708-0x1045747a4)	0x9c          __stubs			S_SYMBOL_STUBS S_ATTR_PURE_INSTRUCTIONS S_ATTR_SOME_INSTRUCTIONS
	[0x1045747a4-0x10457484c)	0xa8          __stub_helper		S_REGULAR S_ATTR_PURE_INSTRUCTIONS S_ATTR_SOME_INSTRUCTIONS
	[0x104574860-0x104574920)	0xc0          __objc_stubs		S_REGULAR S_ATTR_PURE_INSTRUCTIONS S_ATTR_SOME_INSTRUCTIONS
	[0x104574920-0x104574954)	0x34          __cstring			S_CSTRING_LITERALS
	[0x104574954-0x1045749ce)	0x7a          __objc_classname	S_CSTRING_LITERALS
	[0x1045749ce-0x1045757fd)	0xe2f         __objc_methname	S_CSTRING_LITERALS
	[0x1045757fd-0x104576326)	0xb29         __objc_methtype	S_CSTRING_LITERALS
	[0x104576328-0x104576398)	0x70          __unwind_info		S_REGULAR
----------------------------------------------------------------------------------------------------
[0x104578000-0x10457c000)		0x4000      __DATA				rw-/rw-
	[0x104578000-0x104578018)	0x18          __got				S_NON_LAZY_SYMBOL_POINTERS
	[0x104578018-0x104578078)	0x60          __la_symbol_ptr	S_LAZY_SYMBOL_POINTERS
	[0x104578078-0x1045780d8)	0x60          __cfstring		S_REGULAR
	[0x1045780d8-0x1045780f8)	0x20          __objc_classlist	S_REGULAR S_ATTR_NO_DEAD_STRIP
	[0x1045780f8-0x104578118)	0x20          __objc_protolist	S_COALESCED
	[0x104578118-0x104578120)	0x8           __objc_imageinfo	S_REGULAR
	[0x104578120-0x1045792d0)	0x11b0        __objc_const		S_REGULAR
	[0x1045792d0-0x104579308)	0x38          __objc_selrefs	S_LITERAL_POINTERS S_ATTR_NO_DEAD_STRIP
	[0x104579308-0x104579320)	0x18          __objc_classrefs	S_REGULAR S_ATTR_NO_DEAD_STRIP
	[0x104579320-0x104579328)	0x8           __objc_superrefs	S_REGULAR S_ATTR_NO_DEAD_STRIP
	[0x104579328-0x104579330)	0x8           __objc_ivar		S_REGULAR
	[0x104579330-0x104579470)	0x140         __objc_data		S_REGULAR
	[0x104579470-0x1045795f8)	0x188         __data			S_REGULAR
----------------------------------------------------------------------------------------------------
[0x10457c000-0x104584000)		0x8000      __LINKEDIT			r--/r--
	[0x10457c550-0x10457c570)	0x20          Function Starts
	[0x10457c570-0x10457d4b0)	0xf40         Symbol Table
	[0x10457c570-0x10457c570)	0x0           Data In Code Entries
	[0x10457d4b0-0x10457d520)	0x70          Dynamic Symbol Table
	[0x10457d520-0x10457e760)	0x1240        String Table
	[0x10457e760-0x104583640)	0x4ee0        Code Signature
```

[⬆ Back to Module Analysis](#Module-Analysis)



#### `main`

Print the address of main function.

```stylus
(lldb) main
function main at 0x102911b70, fileoff: 0x5b70
```



#### `initfunc` - print init func

Dump module init function(s) of specified module.

```stylus
(lldb) initfunc
-----try to lookup init function in JITDemo-----
mod init func pointers found: __DATA,__mod_init_func
address = 0x100e08cb0 JITDemo`entry1 at main.m:708:0
address = 0x100e0960c JITDemo`entry2 at main.m:740:0
```

[⬆ Back to Module Analysis](#Module-Analysis)



#### `func_starts` - function starts

Print function starts

```stylus
(lldb) func_starts
-----parsing module JITDemo-----
address = 0x1021bc5c8 size = 64 where = JITDemo`globalBlock_block_invoke at ViewController.m:17
address = 0x1021bc608 size = 20 where = JITDemo`+[ViewController load] at ViewController.m:27
...
address = 0x1021bdae0 size = 56 where = JITDemo`-[SceneDelegate .cxx_destruct] at SceneDelegate.m:14
(lldb) 
```



#### `got` - print `__got` section

```stylus
(lldb) got
-----parsing module JITDemo-----
address = 0x1ac734ce0 where = where = Foundation`NSFileModificationDate -> NSFileModificationDate (not a function)
...
address = 0x180d44900 where = libobjc.A.dylib`objc_msgSend (matched)
address = 0x1814ce1c0 where = libdyld.dylib`dyld_stub_binder (matched)
13 location(s) found
```

[⬆ Back to Module Analysis](#Module-Analysis)



#### `lazy_sym` - print `__la_symbol_ptr` section

```stylus
(lldb) lazy_sym
-----parsing module JITDemo-----
address = 0x104c7fe14 where = JITDemo`my_NSHomeDirectory at ViewController.m:63 -> Foundation`NSHomeDirectory
...
address = 0x1815fb950 where = libsystem_kernel.dylib`open (matched)
36 location(s) found
```



#### `entitlements` - dump entitlements

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

Dump bundle ID in the codesign entitlements.

```stylus
(lldb) ent -b
TeamID.com.xxx.LLDBCode
```

Dump team ID in the codesign entitlements.

```stylus
(lldb) ent -t
TeamID
```

Dump group ID(s) in the codesign entitlements.

```stylus
(lldb) ent -g
['group.com.xxx.JITDemo']
```

[⬆ Back to Module Analysis](#Module-Analysis)



#### `offset` - get file offset for address

```stylus
(lldb) offset
addr: 0x104dc45f0 -> file offset: 0x85f0
(lldb) offset 0x104dc45f0
addr: 0x104dc45f0 -> file offset: 0x85f0
```



#### dcls - class dump

```objective-c
(lldb) dcls ViewController
@interface ViewController : UIViewController{
    UITableView * _tableView;
    ...
}
...
@property(nonatomic, readwrite, getter = tableView, setter = setTableView:) UITableView *tableView;
...
-[ViewController .cxx_destruct]
@end
```



#### dependency - list dependencies

List the dependencies of a binary.

```stylus
(lldb) dep
[
  {
    "/usr/lib/libc++.1.dylib": []
  },
  {
    "/usr/lib/libz.1.dylib": []
  },
 	...
  {
    "@rpath/Framework.framework/Framework": [
      {
        "/System/Library/Frameworks/Foundation.framework/Foundation": []
      },
      ...
      {
        "@rpath/Test.dylib (weak)": [
          {
            "/System/Library/Frameworks/Foundation.framework/Foundation": []
          },
          ...
          {
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation": []
          }
        ]
      }
    ]
  },
  ...
]
```

[⬆ Back to Module Analysis](#Module-Analysis)



### Objective-C Commands

#### `classes` - print class names

Print class names in the specified module.

```stylus
(lldb) classes
AppDelegate <0x10468e378>
SceneDelegate <0x10468e418>
ViewController <0x10468e260>
```



#### `dmethods`

Dumps all methods implemented by the NSObject subclass, supporting both iOS and MacOS.

```stylus
(lldb) dmethods ViewController
<ViewController: 0x1021c9b48>:
in ViewController:
	Properties:
		@property unsigned long test;  (@synthesize test = _test;)
	Instance Methods:
		- (void) setRepresentedObject:(id)arg1; (0x1021c7020)
		- (void) setTest:(unsigned long)arg1; (0x1021c7190)
		- (unsigned long) test; (0x1021c7170)
		- (void) viewDidLoad; (0x1021c6e90)
(NSViewController ...)
```



#### `divars`

Dumps all ivars for an instance of a particular class which inherits from NSObject, supporting both iOS and MacOS.

```stylus
(lldb) divars ViewController
in ViewController:
	_test (unsigned long): {length = 8, bytes = 0x5a00ab0000000000}
```

```stylus
(lldb) divars -j self
in ViewController: (JIT)
	8: _test
in NSObject:
	0: isa
```



#### `duplicate_class`

```stylus
(lldb) duplicate_class
class DDContextAllowlistFilterLogFormatter is implemented in:
	/JITDemo.app/Frameworks/LLDBJIT.framework/LLDBJIT
	/JITDemo.app/Frameworks/LLDBLog.framework/LLDBLog
...
class DDLoggingContextSet is implemented in:
	/JITDemo.app/Frameworks/LLDBJIT.framework/LLDBJIT
	/JITDemo.app/Frameworks/LLDBLog.framework/LLDBLog
24 duplicate classes were found
```

#### `overridden_method`

```stylus
(lldb) overridden_method
```

[⬆ Back to Objective-C Commands](#Objective-C-Commands)



### Assembly Commands

#### `inst2bytes` - instructions to bytes

Convert assembly instructions to machine code.
Useful for understanding instruction encoding and creating byte patterns.

```stylus
(lldb) inst2bytes 'mov    x9, sp;mov    x8, x0'
disassembly:
       0: 910003e9     	mov	x9, sp
       4: aa0003e8     	mov	x8, x0
machine code: e9030091e80300aa
```

[⬆ Back to Assembly Commands](#Assembly-Commands)



#### `bytes2inst` - bytes to instructions

Convert machine code to assembly instructions.
Useful for disassembling raw bytes and understanding their meaning.

```stylus
(lldb) bytes2inst e9030091e80300aa
<+0>:	mov	x9, sp
<+4>:	mov	x8, x0
```

[⬆ Back to Assembly Commands](#Assembly-Commands)



### Memory Commands

#### `read_mem_as_addr`

Read memory and interpret as addresses with symbol information.

```bash
(lldb) seg
...
------------------------------------------------------------
[0x102ee0000-0x102ee4000)		0x4000      __DATA
	[0x102ee0000-0x102ee0000)	0x68          __got
...
	[0x102ee02e0-0x102ee0560)	0x280         __cfstring
...

# Read __got section
(lldb) read_mem_as_addr 0x102ee0000 0x102ee0068
0x102ee0000: 0x00000001ac734ce0 Foundation`NSFileModificationDate
...
0x102ee0058: 0x0000000180d44900 libobjc.A.dylib`objc_msgSend
0x102ee0060: 0x00000001814ce1c0 libdyld.dylib`dyld_stub_binder

# Read __cfstring section
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



#### `read_cstring` - read memory as c style string

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

[⬆ Back to Memory Commands](#Memory-Commands)



#### `jit_mem` - read memory with JIT code

```stylus
(lldb) x 0x1c40a8008 -c 4
0x1c40a8008: c0 03 5f d6

(lldb) jit_mem 0x1c40a8008 4
0x1c40a8008: 00 00 20 d4
```

- lldb给_swift_runtime_on_report设置了断点

- 但是内置的lldb指令不体现这种变化

- 使用JIT代码可以读取到真实内存

[⬆ Back to Memory Commands](#Memory-Commands)



### Symbolize Commands

#### `load_dSYM`

Add debug symbol file(s) to corresponding module(s).

**Load single dSYM:**
```st
(lldb) load_dSYM /path/to/dSYMs/Alamofire.framework.dSYM
1 dSYM file(s) loaded
```

**Load multiple dSYMs from directory:**
```stylus
(lldb) load_dSYM /path/to/dSYMs
16 dSYM file(s) loaded
```



#### `symbolize`

Symbolize address, uncaught exception address list or crash report file.

Symbolize address

```stylus
(lldb) dis -c 1 -a 0x1045843d4
JITDemo`___lldb_unnamed_symbol302:
    0x1045843d4 <+0>: sub    sp, sp, #0x1f0
(lldb) symbolize 0x1045843d4
0x1045843d4: JITDemo`-[ViewController ls_dir:] + 0
```

[⬆ Back to Symbolize Commands](#Symbolize-Commands)



Symbolize uncaught exception address list

```stylus
(lldb) symbolize (0x1845aed8c 0x1837685ec 0x18450a448 0x104360f78 0x18e4fd83c 0x18e3a3760 0x18e39d7c8 0x18e392890 0x18e3911d0 0x18eb72d1c 0x18eb752c8 0x18eb6e368 0x184557404 0x184556c2c 0x18455479c 0x184474da8 0x186459020 0x18e491758 0x104361da0 0x183f05fc0)
backtrace: 
frame #0: 0x1845aed8c CoreFoundation`__exceptionPreprocess + 228
frame #1: 0x1837685ec libobjc.A.dylib`objc_exception_throw + 56
frame #2: 0x18450a448 CoreFoundation`-[__NSArray0 objectEnumerator] + 0
frame #3: 0x104360f78 JITDemo`-[ViewController touchesBegan:withEvent:] + at ViewController.m:51:5
...
```

or

```stylus
(lldb) symbolize 0x1845aed8c 0x1837685ec 0x18450a448 0x104360f78 0x18e4fd83c 0x18e3a3760 0x18e39d7c8 0x18e392890 0x18e3911d0 0x18eb72d1c 0x18eb752c8 0x18eb6e368 0x184557404 0x184556c2c 0x18455479c 0x184474da8 0x186459020 0x18e491758 0x104361da0 0x183f05fc0
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

[⬆ Back to Symbolize Commands](#Symbolize-Commands)



### DebugKit Commands

Debugkit is a framework for debugging, it is not loaded by default.

**Loading DebugKit:**

```bash
(lldb) debugkit
loading DebugKit, this may take a while
[INFO] GCDWebUploader started on port 80 and reachable at http://xxx.xxx.xxx.xxx/
DebugKit loaded
```



#### `UIControl` Extension

Enhanced UIControl debugging that shows all target-action pairs for UI controls.
Helps you quickly understand what happens when a button is tapped or other control events occur.

```bash
(lldb) po btn
<UIButton: 0x107d2eaf0; frame = (100 100; 200 30); opaque = NO; layer = <CALayer: 0x282f4ee20>>
    control events list:
        target: <ViewController: 0x107e2ac90>, action: -[ViewController clicked:], event: UIControlEventTouchUpInside
```

#### `NSObject` extension

UIKit provides debugging methods in `NSObject(IvarDescription)`，It works on iOS but not on macOS.Debugkit provides several alternative solutions for this.

Here's one solution in DebugKit:

```stylus
(lldb) divars self
(FP)
in ViewController:
    _test (unsigned long): {length = 8, bytes = 0x5a00ab0000000000}
```

```stylus
(lldb) dmethods self
<ViewController: 0x1063c7c10>: (FP)
in ViewController:
    Class Methods:
        + (void) ivar_description:(id)arg1; (0x1063c4d10)
        + (void) method_description:(id)arg1; (0x1063c4870)
    Properties:
        @property unsigned long test;  (@synthesize test = _test;)
    Instance Methods:
        - (void) setRepresentedObject:(id)arg1; (0x1063c4800)
        - (void) setTest:(unsigned long)arg1; (0x1063c5120)
        - (unsigned long) test; (0x1063c5100)
        - (void) viewDidLoad; (0x1063c4790)
(NSViewController ...)
```

Here's another solution in DebugKit (Powered by [pookjw/IvarDescription](https://github.com/pookjw/IvarDescription)):

```stylus
(lldb) divars ofile
<CDMachOFile: 0x600002580000>: (DK)
in CDMachOFile:
    <+ 32> _byteOrder (unsigned long): 0
...
    <+ 24> _searchPathState (CDSearchPathState*): nil
in NSObject:
    <+  0> isa (Class): CDMachOFile(isa, 0x23d8001000711c5)
```

```stylus
(lldb) dmethods ofile
<CDMachOFile: 0x1000711c0>: (DK)
in CDMachOFile:
    Properties:
        @property (readonly) unsigned long byteOrder;
...
        @property (readonly, nonatomic) Class processorClass;
    Instance Methods:
        - (int) cputype; (0x10002b310)
...
        - (id) segmentWithName:(id)arg1; (0x100028f00)
(CDFile ...)
```

[⬆ Back to DebugKit Commands](#DebugKit-Commands)



#### `NSBlock` extension

block code sample

```stylus
^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
    NSLog(@"%@ %d", self, fd);
}
```

Here is the official block description.

```stylus
(lldb) po $x0
<__NSMallocBlock__: 0x282090ab0>
 signature: "v24@?0@"NSURLSessionDataTask"8@"NSError"16"
 invoke   : 0x102fe4a4c (/private/var/containers/Bundle/Application/3AF6DA13-4E66-4E8F-89D0-BDD268A430A7/JITDemo.app/JITDemo.debug.dylib`__41-[ViewController touchesBegan:withEvent:]_block_invoke_2)
 copy     : 0x102fe4bc8 (/private/var/containers/Bundle/Application/3AF6DA13-4E66-4E8F-89D0-BDD268A430A7/JITDemo.app/JITDemo.debug.dylib`__copy_helper_block_e8_32s)
 dispose  : 0x102fe4c00 (/private/var/containers/Bundle/Application/3AF6DA13-4E66-4E8F-89D0-BDD268A430A7/JITDemo.app/JITDemo.debug.dylib`__destroy_helper_block_e8_32s)
```

Here is DebugKit's block description, it's clearer and more straightforward.

```stylus
(lldb) po [$x0 description]
<__NSMallocBlock__: 0x282090ab0>
    - size: 44
    - func_addr: <0x102fe4a4c>
    - func_prototype: void (*)(id(block) , NSURLSessionDataTask * , NSError * )
    - variable or captured variable:
        - <ViewController: 0x107e2ac90>
        - int 20
```

[⬆ Back to DebugKit Commands](#DebugKit-Commands)



#### iOS Sandbox Explorer

Powered by [GCDWebServer](https://github.com/swisspol/GCDWebServer).The server starts along with DebugKit, and once it's running, you can access sandbox files via a web browser.

```stylus
[INFO] GCDWebUploader started on port 80 and reachable at http://xxx.xxx.xxx.xxx/
(lldb) c
Process 4569 resuming
[INFO] GCDWebUploader now locally reachable at http://iPhone-8.local/
```



#### `vmmap`

show vm map info of address

```stylus
(lldb) po self
<ViewController: 0x105329a40>

(lldb) vmmap self
pid: 4713
path: /private/var/containers/Bundle/Application/08326E5F-4DEB-41CC-8320-4417B1649E7F/JITDemo.app/JITDemo
 
0000000105300000-0000000105400000 [   1.0M] rw-/rwx SM=PRIVATE <MALLOC_TINY>
    (offset 0) /usr/share/icu/icudt70l.dat
```

show vm map info of current process

```stylus
(lldb) vmmap
pid: 4713
path: /private/var/containers/Bundle/Application/08326E5F-4DEB-41CC-8320-4417B1649E7F/JITDemo.app/JITDemo
 
DYLD all image info: 0000000104cd0000 + 170 format = 1
0000000104c00000-0000000104c04000 [    16K] r-x/r-x SM=COW
    104c00000-104c0c000: __TEXT r-x (/private/var/containers/Bundle/Application/08326E5F-4DEB-41CC-8320-4417B1649E7F/JITDemo.app/JITDemo) slide=4c00000
    (offset 0) /private/var/containers/Bundle/Application/08326E5F-4DEB-41CC-8320-4417B1649E7F/JITDemo.app/JITDemo
0000000104c04000-0000000104c08000 [    16K] r-x/rwx SM=PRIVATE
    104c00000-104c0c000: __TEXT r-x (/private/var/containers/Bundle/Application/08326E5F-4DEB-41CC-8320-4417B1649E7F/JITDemo.app/JITDemo) slide=4c00000
    (offset 0) /private/var/containers/Bundle/Application/08326E5F-4DEB-41CC-8320-4417B1649E7F/JITDemo.app/JITDemo
...
    221e4c000-235b08000: __LINKEDIT r-- (/System/Library/PrivateFrameworks/AppSSOCore.framework/AppSSOCore) slide=c204000
    221e4c000-235b08000: __LINKEDIT r-- (/System/Library/Frameworks/Accelerate.framework/Frameworks/vImage.framework/Libraries/libCGInterfaces.dylib) slide=c204000
0000000280000000-00000002a0000000 [ 512.0M] rw-/rwx SM=PRIVATE <MALLOC_NANO>
0000000fc0000000-0000001000000000 [   1.0G] ---/--- SM=EMPTY
0000001000000000-0000007000000000 [ 384.0G] ---/--- SM=EMPTY
```

[⬆ Back to DebugKit Commands](#DebugKit-Commands)



### Other Commands

#### `find_el` - Find Endless Loop

Detects endless loops in all threads at the current execution point.
Useful for identifying performance issues and infinite loops.

**Example code with endless loop:**
```objective-c
- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    int a = 1;
    NSLog(@"%s", __PRETTY_FUNCTION__);
    while (a) {
        a++;
    }
}
```

**Detection process:**
```bash
# Touch device screen
2023-05-20 12:29:52.604910+0800 Interlock[56660:1841567] -[ViewController touchesBegan:withEvent:]
# Pause program execution, then execute find_el in lldb
(lldb) find_el
Breakpoint 1: where = Interlock`-[ViewController touchesBegan:withEvent:] + 136 at ViewController.mm:34:5, address = 0x109dd8d48
Breakpoint 2: where = Interlock`main + 110 at main.m:17:5, address = 0x109dd911e
delete breakpoint 2
call Interlock`-[ViewController touchesBegan:withEvent:] + 136 at ViewController.m:34:5, 22 times per second, hit_count: 100
...
```

[⬆ Back to Other Commands](#Other-Commands)



#### `thread_eb` - extended backtrace of thread

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

[⬆ Back to Other Commands](#Other-Commands)



---

## Tips and Best Practices

### Common Workflows

**1. Initial App Analysis:**
```bash
(lldb) image_list -u          # List user modules
(lldb) classes                # List Objective-C classes
(lldb) executable             # Get main executable name
(lldb) appdelegate           # Find app delegate class
```

**2. Function Analysis:**
```bash
(lldb) func_starts           # List all function starts
(lldb) segments YourApp      # Analyze memory segments
(lldb) got                   # Check Global Offset Table
```

**3. Dynamic Analysis:**
```bash
(lldb) mtrace YourApp        # Trace all app functions
(lldb) bmethod viewDidLoad   # Break on specific methods
(lldb) debugkit              # Load enhanced debugging tools
```

---

## Credits

This project builds upon and is inspired by several excellent open-source projects:

- [DerekSelander/LLDB](https://github.com/DerekSelander/LLDB) - LLDB debugging scripts
- [facebook/chisel](https://github.com/facebook/chisel) - Collection of LLDB commands
- [aaronst/macholibre](https://github.com/aaronst/macholibre) - Mach-O analysis library
- [swisspol/GCDWebServer](https://github.com/swisspol/GCDWebServer) - Lightweight HTTP server
- [pookjw/IvarDescription](https://github.com/pookjw/IvarDescription) - Instance variable description
- [yulingtianxia/BlockHook](https://github.com/yulingtianxia/BlockHook) - Block hooking (for private data)
- [comex/myvmmap](https://github.com/comex/myvmmap) - Virtual memory mapping
- [jtool](http://newosxbook.com/tools/jtool.html)

## License

YJLLDB is released under the Apache License 2.0. See [LICENSE](LICENSE) file for details.

