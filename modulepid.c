#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/fdtable.h> //Add this header for error
#include <linux/dcache.h>
#include <linux/err.h>

static int pid = -1;
module_param(pid, int, 0);
MODULE_PARM_DESC(pid, "Process ID to inspect open files");

static int __init pidfiles_init(void)
{
    struct task_struct *task;
    struct files_struct *files = NULL;
    int count = 0;
    int ret = 0;              /* single return value */
    bool found = false;

    if (pid < 0) {
        pr_info("Invalid PID provided.\n");
        ret = -EINVAL;
        goto out;
    }

    /* Look for the process */
    for_each_process(task) {
        if (task->pid == pid) {
            struct fdtable *fdt;
            int i;

            found = true;
            files = task->files;

            if (!files) {
                pr_info("Process %d exists but has no open files.\n", pid);
                goto out; /* success (module loads), nothing to list */
            }

            fdt = files_fdtable(files);
            if (!fdt) {
                pr_info("Process %d: could not get fdtable.\n", pid);
                goto out; /* treat as success: module loads, nothing to list */
            }

            for (i = 0; i < fdt->max_fds; i++) {
                struct file *f = fdt->fd[i];
                if (f) {
                    char buf[256];
                    char *path = d_path(&f->f_path, buf, sizeof(buf));
                    if (!IS_ERR(path)) {
                        pr_info("Open file: %s\n", path);
                    } else {
                        pr_info("Open file: <path error %ld>\n", PTR_ERR(path));
                    }
                    count++;
                }
            }

            pr_info("Process %d has %d open files.\n", pid, count);
            goto out; /* success */
        }
    }

    if (!found) {
        pr_info("Process with PID %d not found.\n", pid);
        ret = -1; /* not found */
    }

out:
    return ret; /* single return */
}

static void __exit pidfiles_exit(void)
{
    pr_info("Module unloaded.\n");
}

module_init(pidfiles_init);
module_exit(pidfiles_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Susan");
MODULE_DESCRIPTION("Kernel module to count and list open files for a given PID (single-return style)");
