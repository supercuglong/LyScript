# x64dbg 自动化控制插件

<div align=center>
  <img width="100" src="https://cdn.lyshark.com/archive/LyScript/bug_black.png"/> <tr> <img width="100" src="https://cdn.lyshark.com/archive/LyScript/python.png"/>
 <br> <br> <br>

[![BountySource](https://cdn.lyshark.com/archive/LyScript/team.svg)](https://github.com/lyshark/LyScript) [![Build status](https://cdn.lyshark.com/archive/LyScript/build.svg)](https://github.com/lyshark/LyScript) [![Open Source Helpers](https://cdn.lyshark.com/archive/LyScript/users.svg)](https://github.com/lyshark/LyScript) [![Crowdin](https://cdn.lyshark.com/archive/LyScript/email.svg)](mailto:me@lyshark.com) [![Download x64dbg](https://cdn.lyshark.com/archive/LyScript/x64dbg.svg)](https://sourceforge.net/projects/x64dbg/files/latest/download)

<br><br>
一个 X64dbg 自动化控制插件，通过Python控制X64dbg，实现远程调试，解决逆向工作者分析漏洞，寻找指令片段，原生脚本不够强大的问题，与Python结合利用Python的灵活性，提高分析效率，通过自动化控制调试器分析代码。
  
</div>


安装插件:
 - 对应Python包安装 `pip install LyScript32==1.0.5` 或者 `pip install lyscript64` 安装对应包
 
 - 32位插件下载地址: https://cdn.lyshark.com/software/LyScript32.zip
 - 64位插件下载地址: https://cdn.lyshark.com/software/LyScript64.zip

插件下载好以后，请将该插件复制到x64dbg目录下的plugins目录下即可。

![](https://img2022.cnblogs.com/blog/1379525/202203/1379525-20220327190905044-1815692787.png)

当插件加载成功后，会在日志位置看到具体的绑定信息，输出调试，插件并不会在插件栏显示：

![](https://img2022.cnblogs.com/blog/1379525/202203/1379525-20220327135100677-722954367.png)

安装好以后，你需要运行x64dbg程序并手动载入需要分析的可执行文件，然后就可以在Pycharm中编程控制它了。

简单的链接测试代码如下：
 - 连接到调试器: connect()
 - 检测连接状态: is_connect()

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    # 初始化
    dbg = MyDebug()

    # 连接到调试器
    connect_flag = dbg.connect()
    print("连接状态: {}".format(connect_flag))

    # 检测套接字是否还在
    ref = dbg.is_connect()
    print("是否在连接: ", ref)

    dbg.close()
```

链接成功返回1，失败返回0
<br>

### 寄存器类

**get_register() 函数:** 该函数主要用于实现，对特定寄存器的获取操作，用户需传入需要获取的寄存器名字即可。

 - 参数1：传入寄存器字符串

可用范围："DR0", "DR1", "DR2", "DR3", "DR6", "DR7", "EAX", "AX", "AH", "AL", "EBX", "BX", "BH", "BL", "ECX", "CX", "CH", "CL", "EDX", "DX", "DH", "DL", "EDI", "DI", "ESI", "SI", "EBP", "BP", "ESP", "SP", "EIP"

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()
    print("连接状态: {}".format(connect_flag))

    eax = dbg.get_register("eax")
    ebx = dbg.get_register("ebx")

    print("eax = {}".format(hex(eax)))
    print("ebx = {}".format(hex(ebx)))

    dbg.close()
```
如果您使用的是64位插件，则寄存器的支持范围将变为E系列加R系列。

可用范围扩展： "DR0", "DR1", "DR2", "DR3", "DR6", "DR7", "EAX", "AX", "AH", "AL", "EBX", "BX", "BH", "BL", "ECX", "CX", "CH", "CL", "EDX", "DX", "DH", "DL", "EDI", "DI", "ESI", "SI", "EBP", "BP", "ESP", "SP", "EIP", "RAX", "RBX", "RCX", "RDX", "RSI", "SIL", "RDI", "DIL", "RBP", "BPL", "RSP", "SPL", "RIP", "R8", "R8D", "R8W", "R8B", "R9", "R9D", "R9W", "R9B", "R10", "R10D", "R10W", "R10B", "R11", "R11D", "R11W", "R11B", "R12", "R12D", "R12W", "R12B", "R13", "R13D", "R13W", "R13B", "R14", "R14D", "R14W", "R14B", "R15", "R15D", "R15W", "R15B"

```Python
from LyScript64 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    rax = dbg.get_register("rax")
    eax = dbg.get_register("eax")
    ax = dbg.get_register("ax")

    print("rax = {} eax = {} ax ={}".format(hex(rax),hex(eax),hex(ax)))

    r8 = dbg.get_register("r8")
    print("获取R系列寄存器: {}".format(hex(r8)))

    dbg.close()
```

**set_register() 函数:** 该函数实现设置指定寄存器参数，同理64位将支持更多寄存器的参数修改。

 - 参数1：传入寄存器字符串
 - 参数2：十进制数值

可用范围："DR0", "DR1", "DR2", "DR3", "DR6", "DR7", "EAX", "AX", "AH", "AL", "EBX", "BX", "BH", "BL", "ECX", "CX", "CH", "CL", "EDX", "DX", "DH", "DL", "EDI", "DI", "ESI", "SI", "EBP", "BP", "ESP", "SP", "EIP"

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()
    print("连接状态: {}".format(connect_flag))

    eax = dbg.get_register("eax")
    
    dbg.set_register("eax",100)

    print("eax = {}".format(hex(eax)))

    dbg.close()
```

**get_flag_register() 函数:** 用于获取某个标志位参数，返回值只有真或者假。

 - 参数1：寄存器字符串

可用寄存器范围："ZF", "OF", "CF", "PF", "SF", "TF", "AF", "DF", "IF" 

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()
    print("连接状态: {}".format(connect_flag))

    cf = dbg.get_flag_register("cf")
    print("标志: {}".format(cf))
    
    dbg.close()
```

**set_flag_register() 函数:** 用于设置某个标志位参数，返回值只有真或者假。
 
 - 参数1：寄存器字符串
 - 参数2：[ 设置为真 True] / [设置为假 False]

可用寄存器范围："ZF", "OF", "CF", "PF", "SF", "TF", "AF", "DF", "IF" 

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()
    zf = dbg.get_flag_register("zf")
    print(zf)

    dbg.set_flag_register("zf",False)

    zf = dbg.get_flag_register("zf")
    print(zf)

    dbg.close()
```
<br>

### 调试类

**set_debug() 函数:** 用于影响调试器，例如前进一次，后退一次，暂停调试，终止等。

 - 参数1: 传入需要执行的动作

可用动作范围：[暂停 Pause] [运行 Run] [步入 StepIn]  [步过 StepOut] [到结束 StepOver] [停止 Stop] [等待 Wait]

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()
    print("连接状态: {}".format(connect_flag))

    while True:
        dbg.set_debug("StepIn")
        
        eax = dbg.get_register("eax")
        
        if eax == 0:
            print("找到了")
            break
        
    dbg.close()
```

**set_debug_count() 函数:** 该函数是`set_debug()`函数的延续，目的是执行自动步过次数。

 - 参数1：传入需要执行的动作
 - 参数2：执行重复次数

可用动作范围：[暂停 Pause] [运行 Run] [步入 StepIn]  [步过 StepOut] [到结束 StepOver] [停止 Stop] [等待 Wait]

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()
    print("连接状态: {}".format(connect_flag))

    dbg.set_debug_count("StepIn",10)

    dbg.close()
```

**set_breakpoint() 函数:** 该函数可实现在指定内存区域内下断点操作，有两个参数需要传入。

 - 参数1：需要设置断点的地址
 - 参数2：[取消断点 True] [设置断点 False]

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    for index in range(0,10):
        eip = dbg.get_register("eip")

        ref = dbg.set_breakpoint(eip,True)
        print("断点设置状态: {}".format(ref))

        dbg.set_debug("StepIn")
        time.sleep(0.3)

    dbg.close()
```

**set_hardware_breakpoint() 函数:** 用于设置一个硬件断点，硬件断点在32位系统中最多设置4个。

 - 参数1：内存地址（十进制）
 - 参数2：断点类型

断点类型可用范围：[类型 0 = HardwareAccess / 1 = HardwareWrite / 2 = HardwareExecute]

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug(address="127.0.0.1",port=6666)
    connect_flag = dbg.connect()

    eip = dbg.get_register("eip")

    ref = dbg.set_hardware_breakpoint(eip,2)
    print(ref)

    dbg.close()
```

**delete_hardware_breakpoint() 函数** 用于删除一个硬件断点，只需要传入地址即可，无需传入类型。

 - 参数1：内存地址（十进制）

断点类型可用范围：[类型 0 = HardwareAccess / 1 = HardwareWrite / 2 = HardwareExecute]

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug(address="127.0.0.1",port=6666)
    connect_flag = dbg.connect()

    eip = dbg.get_register("eip")

    ref = dbg.set_hardware_breakpoint(eip,2)
    print(ref)

    # 删除断点
    ref = dbg.delete_hardware_breakpoint(eip)
    print(ref)

    dbg.close()
```
<br>

### 模块类

**get_module_base() 函数:** 该函数可用于获取程序载入的指定一个模块的基地址。

 - 参数1：模块名字符串

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()
    
    user32_base = dbg.get_module_base("user32.dll")
    print(user32_base)

    dbg.close()
```

**get_all_module() 函数:** 用于输出当前加载程序的所有模块信息，以字典的形式返回。

 - 参数：无参数

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    ref = dbg.get_all_module()

    for i in ref:
        print(i)

    print(ref[0])
    print(ref[1].get("name"))
    print(ref[1].get("path"))

    dbg.close()
```

**get_local_() 系列函数:** 获取当前EIP所在模块基地址，长度，以及内存属性，此功能无参数传递，获取的是当前EIP所指向模块的数据。

 - dbg.get_local_base()    获取模块基地址
 - dbg.get_local_size()    获取模块长度
 - dbg.get_local_protect() 获取模块保护属性

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    ref = dbg.get_local_base()
    print(hex(ref))

    ref2 = dbg.get_local_size()
    print(hex(ref2))

    ref3 = dbg.get_local_protect()
    print(ref3)

    dbg.close()
```

**get_module_from_function() 函数:** 获取指定模块中指定函数的内存地址，可用于验证当前程序在内存中指定函数的虚拟地址。

 - 参数1：模块名
 - 参数2：函数名

成功返回地址，失败返回false

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    ref = dbg.get_module_from_function("user32.dll","MessageBoxW")
    print(hex(ref))

    ref2 = dbg.get_module_from_function("kernel32.dll","test")
    print(ref2)

    dbg.close()
```

**get_module_from_import() 函数:** 获取当前程序中指定模块的导入表信息，输出为列表嵌套字典。

 - 参数1：传入模块名称

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    ref = dbg.get_module_from_import("ucrtbase.dll")
    print(ref)

    ref1 = dbg.get_module_from_import("win32project1.exe")

    for i in ref1:
        print(i.get("name"))

    dbg.close()
```

**get_module_from_export() 函数:** 该函数用于获取当前加载程序中的导出表信息。

 - 参数1：传入模块名

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    ref = dbg.get_module_from_export("msvcr120d.dll")

    for i in ref:
        print(i.get("name"), hex(i.get("va")))

    dbg.close()
```

**get_section() 函数:** 该函数用于输出主程序中的节表信息。

 - 无参数传递

 ```Python
 from LyScript32 import MyDebug
 
if __name__ == "__main__":
    dbg = MyDebug(address="127.0.0.1",port=6666)
    connect_flag = dbg.connect()

    ref = dbg.get_section()
    print(ref)

    dbg.close()
```
<br>

### 内存类

**read_memory_() 系列函数:** 读内存系列函数，包括 ReadByte,ReadWord,ReadDword 三种格式，在64位下才支持Qword

 - 参数1：需要读取的内存地址（十进制）

目前支持：
 - read_memory_byte() 读字节
 - read_memory_word() 读word
 - read_memory_dword() 读dword
 - read_memory_qword() 读qword （仅支持64位）
 - read_memory_ptr() 读指针

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()


    eip = dbg.get_register("eip")

    ref = dbg.read_memory_byte(eip)
    print(hex(ref))

    ref2 = dbg.read_memory_word(eip)
    print(hex(ref2))

    ref3 = dbg.read_memory_dword(eip)
    print(hex(ref3))

    ref4 = dbg.read_memory_ptr(eip)
    print(hex(ref4))

    dbg.close()
```

**write_memory_() 系列函数:** 写内存系列函数，WriteByte,WriteWord,WriteDWORD,WriteQword

 - 参数1：需要写入的内存
 - 参数2：需要写入的byte字节

目前支持：
 - write_memory_byte() 写字节
 - write_memory_word() 写word
 - write_memory_dword() 写dword
 - write_memory_qword() 写qword （仅支持64位）
 - write_memory_ptr() 写指针

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    addr = dbg.create_alloc(1024)
    print(hex(addr))

    ref = dbg.write_memory_byte(addr,10)

    print(ref)

    dbg.close()
```

**scan_memory_one() 函数:** 实现了内存扫描，当扫描到第一个符合条件的特征时，自动输出。

 - 参数1：特征码字段

 这个函数需要注意，如果我们的x64dbg工具停在系统领空，则会默认搜索系统领空下的特征，如果像搜索程序里面的，需要先将EIP切过去在操作。
```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()
    ref = dbg.scan_memory_one("ff 25")
    print(ref)
    dbg.close()
```

**scan_memory_all() 函数:** 实现了扫描所有符合条件的特征字段，找到后返回一个列表。

 - 参数1：特征码字段

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    ref = dbg.scan_memory_all("ff 25")

    for index in ref:
        print(hex(index))

    dbg.close()
```
<br>

### 堆栈类

**create_alloc() 函数：** 函数`CreateRemoteAlloc()`可在远程开辟一段堆空间，成功返回内存首地址。

 - 参数1：开辟的堆长度（十进制）

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    ref = dbg.create_alloc(1024)
    print("开辟地址: ", hex(ref))

    dbg.close()
```

**delete_alloc() 函数：** 函数`delete_alloc()`用于注销一个远程堆空间。

 - 参数1：传入需要删除的堆空间内存地址。

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    ref = dbg.create_alloc(1024)
    print("开辟地址: ", hex(ref))

    flag = dbg.delete_alloc(ref)
    print("删除状态: ",flag)

    dbg.close()
```

**push_stack() 函数:** 将一个十进制数压入堆栈中，默认在堆栈栈顶。

 - 参数1：十进制数据

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    ref = dbg.push_stack(10)

    print(ref)

    dbg.close()
```

**pop_stack() 函数:** pop函数用于从堆栈中推出一个元素，默认从栈顶弹出。

 - 无参数传递

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    tt = dbg.pop_stack()
    print(tt)

    dbg.close()
```

**peek_stack() 函数:** peek则用于检查堆栈内的参数，可设置偏移值，不设置则默认检查第一个也就是栈顶。

 - 参数1：十进制偏移

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    # 无参数检查
    check = dbg.peek_stack()
    print(check)

    # 携带参数检查
    check_1 = dbg.peek_stack(2)
    print(check_1)

    dbg.close()
```
<br>

### 进程线程类

**get_thread_list() 函数:** 该函数可输出当前进程所有在运行的线程信息。

 - 无参数传递

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    ref = dbg.get_thread_list()
    print(ref[0])
    print(ref[1])

    dbg.close()
```

**get_process_handle() 函数:** 用于获取当前进程句柄信息。

 - 无参数传递

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    ref = dbg.get_process_handle()
    print(ref)

    dbg.close()
```

**get_process_id() 函数:** 用于获取当前加载程序的PID

 - 无参数传递

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    ref = dbg.get_process_id()
    print(ref)

    dbg.close()
```

**get_teb_address() / get_peb_address() 系列函数:** 用于获取当前进程环境块，和线程环境快。

 - get_teb_address()  传入参数是线程ID
 - get_peb_address() 传入参数是进程ID

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    ref = dbg.get_teb_address(6128)
    print(ref)

    ref = dbg.get_peb_address(9012)
    print(ref)

    dbg.close()
```
<br>

### 其他函数

**set_comment_notes() 函数:** 给指定位置代码增加一段注释，如下演示在eip位置增加注释。

 - 参数1：注释内存地址
 - 参数2：注释内容

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    eip = dbg.get_register("eip")
    ref = dbg.set_comment_notes(eip,"hello lyshark")
    print(ref)

    dbg.close()
```

**run_command_exec() 函数:** 执行内置命令，例如bp,dump等。

 - 参数1：命令语句

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    ref = dbg.run_command_exec("bp MessageBoxA")
    print(ref)

    dbg.close()
```

**set_loger_output() 函数:** 日志的输出尤为重要，该模块提供了自定义日志输出功能，可将指定日志输出到x64dbg日志位置。

 - 参数1：日志内容

```Pythohn
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    for i in range(0,100):
        ref = dbg.set_loger_output("hello lyshark -> {} \n".format(i))
        print(ref)

    dbg.close()
```

**get_disasm_code() 函数:** 该函数主要用于对特定内存地址进行反汇编，传入两个参数。

 - 参数1：需要反汇编的地址(十进制) 
 - 参数2：需要向下反汇编的长度

```Python
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()
    print("连接状态: {}".format(connect_flag))

    # 得到EIP位置
    eip = dbg.get_register("eip")

    # 反汇编前100行
    disasm_dict = dbg.get_disasm_code(eip,100)

    for ds in disasm_dict:
        print("地址: {} 反汇编: {}".format(hex(ds.get("addr")),ds.get("opcode")))

    dbg.close()
```
<br>

## LyScript 32位 1.0.7

新版本与旧版本API有少许区别，在安装pip包时应指定版本为`pip install LyScript32==1.0.7`安装。

 - 32位驱动下载地址：

### 新功能

1.设置普通断点与取消分离
2.新增断点命中检测函数
3.新增读入一条汇编指令
4.新增获取操作数
5.新增得到机器码长度
6.获取内存属性需要传值
7.新增设置内存属性函数
8.完全支持远程调试

**set_breakpoint() 函数:** 与低版本不同，本次更新将设置断点与取消断点进行了分离，设置断点只需要传入十进制内存地址。
```Python
if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    eip = dbg.get_register("eip")
    ref = dbg.set_breakpoint(eip)

    print("设置状态: {}".format(ref))
    dbg.close()
```

**delete_breakpoint() 函数:** 该函数是新增函数，传入一个内存地址，可取消一个内存断点。
```Python
if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    eip = dbg.get_register("eip")
    ref = dbg.set_breakpoint(eip)
    print("设置状态: {}".format(ref))

    del_ref = dbg.delete_breakpoint(eip)
    print("取消状态: {}".format(del_ref))

    dbg.close()
```

**check_breakpoint() 函数:** 用于检查下过的断点是否被命中，命中返回True否则返回False.
```Python
if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    eip = dbg.get_register("eip")
    ref = dbg.set_breakpoint(eip)
    print("设置状态: {}".format(ref))

    is_check = dbg.check_breakpoint(4134331)
    print("是否命中: {}".format(is_check))

    dbg.close()
```

读入一条汇编指令
```Python
if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    eip = dbg.get_register("eip")
    print("EIP = {}".format(eip))

    disasm = dbg.get_disasm_one_code(eip)
    print("反汇编一条: {}".format(disasm))

    dbg.close()
```

获取操作数
```Python
if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    eip = dbg.get_register("eip")
    print("EIP = {}".format(eip))

    opcode = dbg.get_disasm_operand_code(eip)
    print("操作数: {}".format(hex(opcode)))

    dbg.close()
```

得到机器码长度
```Python
if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()

    eip = dbg.get_register("eip")
    print("EIP = {}".format(eip))

    opcode = dbg.get_disasm_operand_size(eip)

    print("机器码长度: {}".format(hex(opcode)))

    dbg.close()
```


GetLocalProtect 获取内存属性传值（更新）
```Python
if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()


    eip = dbg.get_register("eip")
    print(eip)

    ref = dbg.get_local_protect(eip)
    print(ref)
```

setlocalprote 设置内存属性
```Python
if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()
    
    eip = dbg.get_register("eip")
    print(eip)

    b = dbg.set_local_protect(eip,32,1024)
    print("设置属性状态: {}".format(b))

    dbg.close()
```
