// SPDX-License-Identifier: GPL-2.0
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/sched/signal.h>
#include <linux/pid.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/rcupdate.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/mm.h>

/*
 * pidfiles(pid, ubuf, ubuf_len)
 * ret: -ESRCH if no PID, else count of open fds
 * if ubuf && ubuf_len: write newline-separated paths into ubuf (truncated if needed)
 */
SYSCALL_DEFINE3(pidfiles, pid_t, pid, char __user *, ubuf, size_t, ubuf_len)
{
 long ret = 0;                     /* single return value */
 struct task_struct *task;
 struct files_struct *files;
 struct fdtable *fdt;
 char *kbuf = NULL, *tmp = NULL;   /* kbuf = output text, tmp = d_path scratch */
 size_t pos = 0;

 if (!ubuf && ubuf_len) { ret = -EINVAL; goto out; }

 rcu_read_lock();
 task = pid_task(find_vpid(pid), PIDTYPE_PID);
 if (!task) { ret = -1; goto out_rcu; }

 files = rcu_dereference(task->files);
 if (!files) { ret = 0; goto out_rcu; }

 if (ubuf && ubuf_len) {
  kbuf = kvmalloc(ubuf_len, GFP_KERNEL);
  tmp  = (char *)__get_free_page(GFP_KERNEL);
 }

 spin_lock(&files->file_lock);
 fdt = files_fdtable(files);
 if (fdt && fdt->fd) {
  unsigned int i, max = fdt->max_fds;
  for (i = 0; i < max; i++) {
   struct file *f = rcu_dereference_raw(fdt->fd[i]);
   if (!f) continue;
   ret++;

   if (kbuf && tmp && pos < ubuf_len - 1) {
    get_file(f);
    spin_unlock(&files->file_lock);
    rcu_read_unlock();

    /* stringify path */
    {
     struct path p = f->f_path;
     char *pstr;
     path_get(&p);
     pstr = d_path(&p, tmp, PAGE_SIZE);
     if (!IS_ERR(pstr))
      pos += scnprintf(kbuf + pos, ubuf_len - pos, "%s\n", pstr);
     path_put(&p);
    }

    rcu_read_lock();
    spin_lock(&files->file_lock);
    fput(f);
   }
  }
 }
 spin_unlock(&files->file_lock);
out_rcu:
 rcu_read_unlock();

 if (kbuf) {
  if (pos < ubuf_len) kbuf[pos] = '\0'; else kbuf[ubuf_len - 1] = '\0';
  if (copy_to_user(ubuf, kbuf, min_t(size_t, pos + 1, ubuf_len))!= 0 && ret == 0)
  {
        ret = -EFAULT;
  }
 }
 if (tmp)  free_page((unsigned long)tmp);
 if (kbuf) kvfree(kbuf);
out:
 return ret;
}
