#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/rwsem.h>
#include <linux/timekeeping.h>  
#include <linux/sched.h>     
#include <linux/time.h>    

#define MAX_LOG_ENTRY 512  // define a max size per log entry
#define DEVICE_NAME "logger"
#define BUFFER_SIZE 4096

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OS PROJECT");
MODULE_DESCRIPTION("KERNEL_LEVEL_LOGGING_SUBSYSTEM (READER-WRITER MODEL)");

static char log_buffer[BUFFER_SIZE];  // Fixed: added space between char and log_buffer
static int write_pos = 0;

static struct rw_semaphore log_rwlock;

static dev_t dev_number;
static struct cdev logger_cdev;
static struct class *logger_class;

static ssize_t logger_write(struct file *file, const char __user *user_buf, size_t count, loff_t *ppos)
{
    pr_info("logger: write called, count=%zu\n", count);
    if (count == 0)
        return 0;

    down_write(&log_rwlock); // Acquire write lock

    char msg[256];
    struct timespec64 ts;
    struct tm tm;
    char final_entry[MAX_LOG_ENTRY];
    pid_t pid;
    int log_len;

    // Limit count to avoid overflow
    if (count >= sizeof(msg))
        count = sizeof(msg) - 1;

    // Copy message from user space
    if (copy_from_user(msg, user_buf, count)) {
        up_write(&log_rwlock);
        return -EFAULT;
    }
    msg[count] = '\0';  // Null-terminate

    // Get time and convert to tm
    ktime_get_real_ts64(&ts);
    time64_to_tm(ts.tv_sec, 0, &tm);

    // Get PID, Process Name, CPU Core
    pid = current->pid;
    const char *proc_name = current->comm;
    int cpu = smp_processor_id();
    const char *log_level = "INFO"; // Optional: parse from input for custom level

    // Format final log entry with extras
    log_len = snprintf(final_entry, sizeof(final_entry),
        "[%04ld-%02d-%02d %02d:%02d:%02d] [PID:%d, Process:%s, CPU:%d, Level:%s, Func:%s] %s\n",
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
        tm.tm_hour, tm.tm_min, tm.tm_sec,
        pid, proc_name, cpu, log_level, __func__, msg);

    if (log_len > BUFFER_SIZE)
        log_len = BUFFER_SIZE;

    // Circular buffer write
    if (write_pos + log_len > BUFFER_SIZE) {
        size_t first_part = BUFFER_SIZE - write_pos;
        memcpy(&log_buffer[write_pos], final_entry, first_part);
        memcpy(log_buffer, final_entry + first_part, log_len - first_part);
        write_pos = log_len - first_part;
    } else {
        memcpy(&log_buffer[write_pos], final_entry, log_len);
        write_pos += log_len;
    }

    up_write(&log_rwlock); // Release write lock
    return count;
}


static ssize_t logger_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos)
{
    ssize_t ret;
    down_read(&log_rwlock); // shared reader
    
    if (*ppos >= write_pos) {
        up_read(&log_rwlock);
        return 0;
    }
    
    if (count > write_pos - *ppos) {
        count = write_pos - *ppos;
    }
    
    if (copy_to_user(user_buf, &log_buffer[*ppos], count)) {
        up_read(&log_rwlock);
        return -EFAULT;
    }
    
    *ppos += count;
    ret = count;
    up_read(&log_rwlock);
    return ret;
}

static int logger_open(struct inode *inode, struct file *file)
{
    pr_info("logger: device opened\n");
    return 0;
}

static int logger_release(struct inode *inode, struct file *file)
{
    pr_info("logger: device closed\n");
    return 0;
}

static struct file_operations fops = {  // Fixed typo: filr_operations -> file_operations
    .owner = THIS_MODULE,
    .read = logger_read,
    .write = logger_write,
    .open = logger_open,
    .release = logger_release
};

static int __init logger_init(void)
{
    // Fixed: proper alloc_chrdev_region call with 4 parameters
    if (alloc_chrdev_region(&dev_number, 0, 1, DEVICE_NAME) < 0)
        return -1;

    cdev_init(&logger_cdev, &fops);
    if (cdev_add(&logger_cdev, dev_number, 1) < 0)
        return -1;

    // Fixed: class_create takes only name parameter
    logger_class = class_create(DEVICE_NAME);
    if (IS_ERR(logger_class)) {
        cdev_del(&logger_cdev);
        unregister_chrdev_region(dev_number, 1);
        return PTR_ERR(logger_class);
    }

    device_create(logger_class, NULL, dev_number, NULL, DEVICE_NAME);
    init_rwsem(&log_rwlock);  // Fixed typo: init_rwesm -> init_rwsem
    pr_info("logger: module loaded\n");
    return 0;
}

static void __exit logger_exit(void)
{
    device_destroy(logger_class, dev_number);
    class_destroy(logger_class);
    cdev_del(&logger_cdev);
    unregister_chrdev_region(dev_number, 1);
    pr_info("logger: module unloaded\n");
}

module_init(logger_init);
module_exit(logger_exit);
