# Write-up for assignment 2

## Guest Kernel Requirements

Kprobes need to be enabled for this `rootkit` to work. Please use this command to configure the kernel module first.

```
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- menuconfig
```

Go to the submenu `General architecture-dependent options  --->` and enable `Kprobes`.

And then, recompile the kernel:

```
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j$(nproc)
```

## Compilation

To compile the kernel module, please run the following commands.

```
make CROSS=aarch64-linux-gnu- KDIR=[path to the kernel source]
```

The kernel module `rootkit.ko` will be produced.

For user space programs for testing, please compile them on the arm64 VM to make sure that the glibc version is compatible.

## Load the kernel module

Put the compiled kernel module `rootkit.ko` to the VM, or mount the shared folder, and run the following commands to load the kernel module.

```
# insmod rootkit.ko
```

Replase `rootkit.ko` to the path to the kernel module.

Then, run the command `dmesg | tail` to see the major number of the device.

```
# dmesg | tail
.....
[   47.561167] rootkit: loading out-of-tree module taints kernel.
[   47.635255] The major number for your device is 511 <- The major number will be here.
```

You can see that the major number is 511.
Then, create the device node using `mknod`.

```
# mknod /dev/rootkit c 511
```

You need to change the number `511` to match the major number you see at the previous step.

## Handling ioctl

When an `ioctl` is call for the rootkit device, the function `rootkit_ioctl` in the `rootkit.c` template will be called.
We use a simple switch-case statements to jump to the operation that the user space program want to perform and perform that operations.

## Function 1: Hide/Show Module

### Implementation Details

The `list_head` of the current module can be accessed using `THIS_MODULE->list`.

To hide the kernel module, the previous module's `list_head`, which can be accessed by `THIS_MODULE->list.prev` to a static variable `previous_module` I defined is saved, and then I uses `list_del_init(&THIS_MODULE->list)` to remove the kernel module from the module list.

To show the kernel module, simply use `list_add(&THIS_MODULE->list, previous_module)` to add the module back to the module list.

### The Test Program

`hide_mod.c` is the test program to test the function, hide/show module. It will open the device `/dev/rootkit` and issue the ioctl `IOCTL_MOD_HIDE`.

### How to Test

To test the hide and unhide function, please compile `hide_mod.c` in the VM:

```
# gcc hide_mod.c -o hide_mod
```

The executable `hide_mod` will be produced.

Use the command `lsmod` to check whether the module is hidden or not:

```
# lsmod
Module                  Size  Used by
rootkit                16384  0
```

The module is not hidden. Then execute the executable `hide_mod`:

```
# ./hide_mod
```

The module will now be hidden. You can check that with `lsmod`:

```
# lsmod
Module                  Size  Used by
```

To show the module, just execute `hide_mod` again:

```
# ./hide_mod
```

And then, the module will be shown:

```
# lsmod
Module                  Size  Used by
rootkit                16384  0
```

## Masquerade process name

### Implementation Details

First, we need to access the buffer user provided to know the rules to change the process name. `copy_from_user()` is used to access the buffer in the user space.

Before copying the buffer from the user to the kernel, we need to allocate buffers in the kernel to hold the data, `kmalloc()` is used to allocate the buffer, and `kfree()` is used to free the buffer.

Then `for_each_process()` macro is used to iterate all the tasks' `task_struct`. The name of the process will be in the member `comm` of the `task_struct`. Just compare the name in `comm` to determine whether to change the process name, and change the name by directly write the new name to `comm`.

### The Test Program

`masq.c` contains the code to test this function. It will read the command line arguments to know the rules to masquerade process names and fill the stuctures that will be passed to the kernel with the rules, and issue the ioctl `IOCTL_MOD_MASQ`.

The arguments should be `<orig_name> <new_name> <orig_name> <new_name> ...`

### How to Test

First, compile the test program in the VM:

```
# gcc masq.c -o masq
```

Then, check the currently running processes:

```
# ps ao pid,comm
    PID COMMAND
    280 login
    286 agetty
    421 bash
    535 ps
```

Find the process names you want to replaces. For example:

```
login -> sh
agetty -> vim
bash -> bashbash (this will fail as the new name is longer than the old name)
```

Execute `masq login sh agetty vim bash bashbash` to change the process names. The name `bash` will not be changed as `bashbash` is longer than `bash`. The assignment spec says that we only need to process the case where the new name is shorter than the old name.

```
# masq login sh agetty vim bash bashbash
```

check the name of the processes again:

```
# ps ao pid,comm
    PID COMMAND
    280 sh
    286 vim
    421 bash
    549 ps
```

You will see that the names of the processes have been replaced.

## Syscall hooking

### Implementation Details

To hook the system call, the system call table `sys_call_table` need to be modified. Unfortunately, `sys_call_table` is not exported to the kernel module, and because it is placed in the rodata section, we cannot modify it without changing the permission bits of the page table.

There are two problems we need to solve before we can change the system call table:
* symbol lookup
* change the permission bits

#### Symbol Lookup

We can lookup symbols using the function `kallsyms_lookup_name()`. Unfortunately, it is also not exported to the kernel modules. We need to (ab)use kprobes to lookup the symbol `kallsyms_lookup_name` first.

Use `register_kprobe()` to register a kprobe for `kallsyms_lookup_name`, and look into the structure `struct kprobe` to obtain the address of `kallsyms_lookup_name`, and then use `unregister_kprobe()` to unregister the kprobe.

Now, we get the address of `kallsyms_lookup_name`, and we can use it to lookup symbols.

#### Change the Permission of `rodata` to RW

[The source code](https://elixir.bootlin.com/linux/v5.15/source/arch/arm64/mm/mmu.c#L558) is used as a sample. It change `rodata` (the pages between `__start_rodata`, `__init_begin`) to readonly by using `update_mapping_prot()`.

I copid this code to my `rootkit` module, and change `PAGE_KERNEL_RO` to `PAGE_KERNEL`, so that the permissions of `rodata` is changed to RW. The symbols, `__start_rodata`, `__init_begin` and `update_mapping_prot` are not exported to the kernel module, `kallsyms_lookup_name` is used to lookup those missing symbols.

#### Changing the System Call Table

`kallsyms_lookup_name` is used to lookup the symbol `sys_call_table` to get the address of the system call table. Before changing the entries of the system call table, the original addresses of the system call functions are saved so that the new system call function can call the original system call function and the system calls can also be restored when the module is unload.

#### Hook the System Call, `kill`

User space registers stored in the `struct pt_regs` are passed as an argument to the system call function.
In this function, we check whether the second argument passed by the user space, which is stored in `regs->regs[1]`, is 9 or not. If it is 9 (SIGKILL), do nothing and return 0. For other cases, just call the original system call function of `kill`.

#### `reboot`

Check whether `regs->regs[2]` (the third argument of the system call) is `LINUX_REBOOT_CMD_POWER_OFF` (0x4321fedc). If it is true, enter infinite loop with `mdelay(10000)` in it (to avoid wasting too much CPU cycles). If it is not the case, the original reboot system call function is called.

#### `getdent64`

The filename to hide is stored in a static variable `hided_file`.
The original system call function is called first, and the user provided buffer will be filled in the `struct dirent`s'.
Then, we copy the whole buffer into kernel space, and check each entris.
If the entries contains the filename that need to be hidden, delete the hidden entry and change the buffer size to reflect that the entry is deleted.
Then copid the updated buffer back to the user and return the updated buffer size.

Also, the ioctl `IOCTL_MOD_HIDE` is implemented. It will update the static variable with the desired filename to be hidden.

### The Test Program

The program `hook.c` can be used to issue the ioctl `IOCTL_MOD_HOOK` to tell the kernel module to hook the system call.
The program `hide_file.c` can be used to issue the ioctl `IOCTL_MOD_HIDE` to tell the kernel the filename to be hidden.

### How to Test

To compile the test programs, run the following commands in the VM:

```
gcc hook.c -o hook
gcc hide_file.c -o hide_file
```

Then, execute the program `hook` to hook the system call table.

```
./hook
```

#### Test the system call `kill`

1. Execute a test program `sleep`:

```
sleep 100000&
```

2. Check that the process `sleep` is running, and check the PID of it.

```
# ps a
    PID TTY      STAT   TIME COMMAND
    280 ttyAMA0  Ss     0:00 /bin/login -p --
    286 tty1     Ss+    0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
    411 ttyAMA0  S      0:01 -bash
    582 ttyAMA0  S      0:00 sleep 100000
    584 ttyAMA0  R+     0:00 ps a
```

The PID is 582.

3. Send SIGKILL to the process

```
# kill -9 582`
```

Please replace `582` to the PID you see in the previous step.

4. Run `ps a` again, and you can see that the process is still running:

```
# ps a
    PID TTY      STAT   TIME COMMAND
    280 ttyAMA0  Ss     0:00 /bin/login -p --
    286 tty1     Ss+    0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
    411 ttyAMA0  S      0:01 -bash
    582 ttyAMA0  S      0:00 sleep 100000
    585 ttyAMA0  R+     0:00 ps a
```

#### Test the system call `getdent64`

1. Execute the test program `hide_file` to tell the rookit to hide the file `bin`

```
# ./hide_file bin
```

2.  List the files at `/` with `ls /` and you will see that `bin` is hidden:

```
# ls /
boot  etc   media  opt   root  snap  sys  usr
dev   home  mnt    proc  run   srv   tmp  var
```

#### Test the system call `reboot`

1. Poweroff the VM using `poweroff`, and you will see that the VM cannot be powered off.

```
# poweroff
...
[  OK  ] Stopped target Local File Systems (Pre).
[  OK  ] Reached target Unmount All Filesystems.
         Stopping Monitoring of LVM…meventd or progress polling...
[  OK  ] Stopped Create Static Device Nodes in /dev.
[  OK  ] Stopped Create System Users.
[  OK  ] Stopped Monitoring of LVM2… dmeventd or progress polling.
[  OK  ] Reached target Shutdown.
[  OK  ] Reached target Final Step.
[  OK  ] Finished Power-Off.
[  OK  ] Reached target Power-Off.
 <-- Stuck here
```

## Bonus

Sometime, we want to disable debugging support of a system for security purposes.

For the bonus part, the system call `ptrace` is hooked. Once the system call is hooked, debugger cannot attach to new and existing processes. However, existing debugging session can continue.

### Implemention Details

The first argument of the `ptrace` is the type of request. If the first argument (the value stored in `regs->regs[0]`) is `PTRACE_TRACEME`, `PTRACE_ATTACH` and `PTRACE_SEIZE`, return -EPERM. If it is not the case, call the original system call to allow existing debugging session.

### How to Test

Please unload the kernel module `rootkit` or reboot the system to ensure that the system table is not hooked before testing this. And then, load the kernel module and recreate the device file /dev/rootkit.

1. Install gdb:

```
# apt-get install gdb
```

2. The test program `hook.c` should be used to hook the system call first. Please compile it:

```
# gcc hook.c -o hook
```

3. Start a gdb session to debug `ls` by using the following commands:

```
# gdb ls
...
(gdb) starti            <-- start the program in the paused state.
Starting program: /usr/bin/ls

Program stopped.
0x0000fffff7fcd100 in _start () from /lib/ld-linux-aarch64.so.1
```

4. Start another terminal and hook the system call table:

```
# ./hook
```

5. Check that we cannot debug new program.

```
# gdb ls
...
(gdb) starti
Starting program: /usr/bin/ls
warning: Could not trace the inferior process.
warning: ptrace: Operation not permitted
During startup program exited with code 127.
```

6. Go back to the original terminal where the gdb is debugging `ls`, and type `si` to see that the existing debugging session can continue.

```
(gdb) si
0x0000fffff7fcd104 in _start () from /lib/ld-linux-aarch64.so.1
(gdb) si
_dl_start (arg=0xfffffffffb00) at rtld.c:463
463     rtld.c: No such file or directory.
(gdb) si
0x0000fffff7fcdb84      463     in rtld.c
(gdb) si
0x0000fffff7fcdb88      463     in rtld.c
(gdb) si
0x0000fffff7fcdb8c      463     in rtld.c
(gdb)
```
