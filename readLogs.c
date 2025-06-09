#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define DEVICE_FILE "/dev/logger"  // The device file created by the kernel module
#define LOG_FILE "log.txt"         // The file where logs will be stored

int main() {
    int dev_fd, log_fd;
    char buffer[512];
    ssize_t bytes_read;

    // Open the /dev/logger device
    dev_fd = open(DEVICE_FILE, O_RDONLY);
    if (dev_fd == -1) {
        perror("Failed to open device file");
        return 1;
    }

    // Open or create the log file to store logs (append mode)
    log_fd = open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (log_fd == -1) {
        perror("Failed to open log file");
        close(dev_fd);
        return 1;
    }

    // Continuously read from /dev/logger and write to the log file
    while (1) {
        bytes_read = read(dev_fd, buffer, sizeof(buffer));
        if (bytes_read < 0) {
            perror("Failed to read from device");
            break;
        }
        
        if (bytes_read == 0) {
            // No more logs available, wait before trying again
            sleep(1);  // Sleep for a second before trying again
            continue;
        }

        // Write the logs to the log file
        if (write(log_fd, buffer, bytes_read) == -1) {
            perror("Failed to write to log file");
            break;
        }
    }

    // Close the files when done
    close(dev_fd);
    close(log_fd);
    return 0;
}

