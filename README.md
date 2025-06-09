# Kernel Logging Subsystem - Linux Kernel Module

This is a custom Linux kernel module that implements a **character device-based logging subsystem**. It allows user space processes to **write logs into the kernel**, and retrieve them using the virtual file `/dev/logger`.
## Features
- Log messages from user space into the kernel
- Timestamp, process ID, CPU core, and process name added to each log
- Uses **reader-writer locking** (`rw_semaphore`) to ensure thread-safe access
- Circular buffer to manage memory efficiently (logs overwrite oldest entries)
- Simple character device interface: `/dev/logger`
## Project Structure
```bash
.
├── logging_driver.c     # Main kernel module source code
├── Makefile             # For building the module
├── README.md            # You're reading it!
## for compile and run
1.BUILD THE MODULE
make
2.INSERT THE KERNEL MODULE
sudo insmod logging_driver.ko
3.CREATE DEVICE FILE
sudo chmod 666 /dev/logger
4.WRITE A LOG
echo "hello from a user space" > /dev/logger
5.READ A LOG
cat /dev/logger
