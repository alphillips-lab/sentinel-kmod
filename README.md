# Sentinel Linux
This is the landing page for the sentinel documentation for linux. Sentinel serves as a custom loadable kernel module (LKM) that hooks common syscalls and looks for common IOCs/TTPs seen in RvB competitions.

## Distro Specific Setup Notes
Fedora does not come with kernel headers installed (kernel-devel/kernel-headers package)
```$ sudo yum install "kernel-devel-uname-r == $(uname -r)"```

Currently, this module should work on x64 linux above kernel version 4.17. Hook skeleton code is there for previous kernel versions, and the file would have to be remade using x86 registers for an x86 version of the module.

## Setup ##

Setup is done by calling the makefile in the src directory for the kernel type (linux/bsd).

Also make sure to review the distro specific setup notes section in case there are certain caveats to installation.

Installing the module can be done currently by running `insmod sentinel.ko` as a privileged user.

The module will NOT be persistent across reboots currently, but it can be removed manually via `rmmod sentinel.ko`

In preparation for the RvB game it will be important to have a way to build the kernel object for the system without access to make on the host. This should probably be done via dockerfiles with the appropriate kernel version and packages required to build the object.

## Usage ##

The existing functionality of Sentinel is blocking IOCTL syscalls for the immutable flag update. This means, if you were to set the immutable flag for a file (via chattr for example) and then enable Sentinel, nobody would be able to update the immutable flag and edit the file without re-hooking the IOCTL syscall.

Example:
```
~# chattr +i flag.txt
~# insmod sentinel.ko
~# chattr -i flag.txt
ioctl error
~# lsattr flag.txt
----i----------- flag.txt
```