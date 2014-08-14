#include <asm/cacheflush.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/nsproxy.h>
#include <linux/poll.h>
#include <linux/debugfs.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "binder.h"

#define CONBINDER_GET_CURRENT_CONTAINER _IOR('b', 11, int)

unsigned int binder_poll(struct file *filp, struct poll_table_struct *wait);

long binder_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);

int binder_mmap(struct file *filp, struct vm_area_struct *vma);

int binder_open(struct inode *nodp, struct file *filp);

int binder_flush(struct file *filp, fl_owner_t id);

int binder_release(struct inode *nodp, struct file *filp);
