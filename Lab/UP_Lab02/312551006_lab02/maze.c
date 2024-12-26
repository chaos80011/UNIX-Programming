/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <linux/module.h>	// included for all kernel modules
#include <linux/kernel.h>	// included for KERN_INFO
#include <linux/init.h>		// included for __init and __exit macros
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/sched.h>	// task_struct requried for current_uid()
#include <linux/cred.h>		// for current_uid();
#include <linux/slab.h>		// for kmalloc/kfree
#include <linux/uaccess.h>	// copy_to_user
#include <linux/string.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/mutex.h>

#include "maze.h"
static DEFINE_MUTEX(mutex);

static dev_t dev_num;
static struct cdev maze_cdev;
static struct class *clazz;


typedef struct {
    coord_t pos;
    bool created;
    maze_t attr;
    pid_t pid;
} Maze;

Maze mazes[3];

// static bool maze_created = false;
coord_t temp_c = {0};
// coord_t pos = {0};

static int mazemod_dev_open(struct inode *i, struct file *f) {
    // if(device_is_open) {
    //     pr_alert("Device has already been opened.");
    //     return -EBUSY;
    // }
	printk(KERN_INFO "maze: device opened.\n");
	return 0;
}

static int mazemod_dev_close(struct inode *i, struct file *f) {
    // if(!device_is_open) {
    //     pr_alert("Device has not been opened.");
    //     return -EBUSY;
    // }
	printk(KERN_INFO "maze: device closed.\n");
    int num = -1;
    for(int i = 0; i < 3; i++) {
        if(mazes[i].pid == current->pid) {
            num = i;
            break;
        }
    }
    if(num != -1) {
        memset(&mazes[num], 0, sizeof(Maze));
    }
	return 0;
}

static ssize_t mazemod_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
	// printk(KERN_INFO "maze: read %zu bytes @ %llu.\n", len, *off);
    // if(!maze_created) {
    //     return -ENOENT;
    // }

    Maze *maze;
    pid_t pid = current->pid;
    int i, num;
    for(i = 0; i < 3; i++) {
        if(pid == mazes[i].pid) {
            num = i;
            break;
        }
    }
    if(i == 3) {
        printk(KERN_INFO "no pid\n");
        return -1;
    } else {
        maze = &mazes[num];
    }
    printk(KERN_INFO "pid: %d\n", pid);
    char *temp = kzalloc(10000, GFP_KERNEL);
    int offset = 0;
    for(int i = 0; i < maze->attr.h; i++) {
        for(int j = 0; j < maze->attr.w; j++) {
            temp[offset] = maze->attr.blk[i][j] == '#';
            offset++;
        }
    }
    if(copy_to_user(buf, temp, maze->attr.w * maze->attr.h)) {
        return -EFAULT;
    }
    kfree(temp);
    temp = NULL;
	return maze->attr.w * maze->attr.h;
}

static ssize_t mazemod_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
    coord_t temp_pos;
    coord_t c64[64];
    if(copy_from_user(&c64, buf, len)) {
        return -EFAULT;
    }
    pid_t pid = current->pid;
    int i, num;
    for(i = 0; i < 3; i++) {
        if(pid == mazes[i].pid) {
            num = i;
            break;
        }
    }
    if(i == 3) {
        printk(KERN_INFO "no pid\n");
        return -1;
    }
    for(int i = 0; i < 64; i++) {
        if((c64[i].x == -1 && c64[i].y == 0) || (c64[i].x == 1 && c64[i].y == 0) 
            || (c64[i].x == 0 && c64[i].y == -1) || (c64[i].x == 0 && c64[i].y == 1)) {
                temp_pos.x = mazes[num].pos.x + c64[i].x;
                temp_pos.y = mazes[num].pos.y + c64[i].y;
                if(mazes[num].attr.blk[temp_pos.y][temp_pos.x] != '#') {
                    mazes[num].pos.x = temp_pos.x;
                    mazes[num].pos.y = temp_pos.y;
                }
        }
    } 

    // coord_t seq[64];
    // if(copy_from_user(seq, buf, len)) {
    //     return -EBUSY;
    // }
    // int cx = pos.x;
    // int cy = pos.y;
    // for(int i = 0; i < sizeof(seq)/sizeof(coord_t); i++) {
	// 	int nx, ny;
	// 	nx = cx + seq[i].x;
	// 	ny = cy + seq[i].y;
	// 	if(nx < 0 || ny < 0 || nx >= maze->w || ny >= maze->h) continue;
	// 	if(maze->blk[ny][nx] != '.') continue;
	// 	cx = nx;
	// 	cy = ny;
	// }
    // pos.x = cx;
    // pos.y = cy;

	return 0;
}

static long mazemod_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
	// printk(KERN_INFO "maze: ioctl cmd=%u arg=%lu.\n", cmd, arg);
    // Maze *maze;
    // pid_t pid = current->pid;
    // int i, num;
    // for(i = 0; i < 3; i++) {
    //     if(pid == mazes[i].pid) {
    //         num = i;
    //         break;
    //     }
    // }
    // if(i == 3) {
    //     printk(KERN_INFO "New process\n");
    // } else {
    //     maze = &mazes[num];
    // }
    mutex_lock(&mutex);
    int num = -1;
    coord_t temp_pos;
    if(cmd != MAZE_CREATE) {
        for(int i = 0; i < 3; i++) {
            if(mazes[i].pid == current->pid) {
                num = i;
                break;
            }
        }
    }

    switch (cmd) {
        case MAZE_CREATE:

            if(copy_from_user(&temp_c, (void *)arg, sizeof(coord_t))) {
                mutex_unlock(&mutex);
                return -EFAULT;
            }
            if(temp_c.x < 3 || temp_c.y < 3 || temp_c.x >= _MAZE_MAXX || temp_c.y >= _MAZE_MAXY) {
                mutex_unlock(&mutex);
                return -EINVAL;
            }
            for(int i = 0; i < 3; i++) {
                if(mazes[i].pid == current->pid) {
                    mutex_unlock(&mutex);
                    return -EEXIST;
                }
            }
            for(num = 0; num < 3; num++) {
                if(mazes[num].created == false) {
                    break;
                }
            }
            if(num == 3) {
                // printk(KERN_INFO "child: Cannot allocate memory");
                mutex_unlock(&mutex);
                return -ENOMEM;
            }

            // maze = &mazes[num];
            mazes[num].pid = current->pid;
            printk(KERN_INFO "pid: %d\n", mazes[num].pid);
            mazes[num].created = true;
            mazes[num].attr.w = temp_c.x;
            mazes[num].attr.h = temp_c.y;
            mazes[num].attr.sx = 1;
            mazes[num].attr.sy = 1;
            mazes[num].attr.ex = mazes[num].attr.w - 2;
            mazes[num].attr.ey = 1;
            mazes[num].pos.x = mazes[num].attr.sx;
            mazes[num].pos.y = mazes[num].attr.sy;
            // #############
            // # # # # # # #
            // # # # # # # #
            // # # # # # # #
            // # # # # # # #
            // # # # # # # #
            // #           #
            // #############

            // The first and last row
            for(int column = 0; column < mazes[num].attr.w; column++) {
                mazes[num].attr.blk[0][column] = '#';
                mazes[num].attr.blk[mazes[num].attr.h - 1][column] = '#';
            }
            for(int row = 1; row < mazes[num].attr.h - 1; row++) {
                for(int column = 0; column < mazes[num].attr.w - 2; column += 2) {
                    mazes[num].attr.blk[row][column] = '#';
                    mazes[num].attr.blk[row][column+1] = '.';
                }
                mazes[num].attr.blk[row][mazes[num].attr.w - 1] = '#';
            }
            int rr = get_random_u32() % (mazes[num].attr.h-2) + 1;
            mazes[num].attr.blk[rr][0] = '#';
            mazes[num].attr.blk[rr][mazes[num].attr.w-1] = '#';
            for(int column = 1; column < mazes[num].attr.w-1; column++) {
                mazes[num].attr.blk[rr][column] = '.';
            }
            mazes[num].attr.blk[mazes[num].attr.sy][mazes[num].attr.sx] = 'S';
            mazes[num].attr.blk[mazes[num].attr.ey][mazes[num].attr.ex] = 'E';
            break;
        case MAZE_RESET:
            if(num == -1) {
                mutex_unlock(&mutex);
                return -ENOENT;
            }
            mazes[num].pos.x = mazes[num].attr.sx;
            mazes[num].pos.y = mazes[num].attr.sy;
            break;
        case MAZE_DESTROY:
            if(num == -1) {
                mutex_unlock(&mutex);
                return -ENOENT;
            }
            memset(&mazes[num], 0, sizeof(Maze));
            break;
        case MAZE_GETSIZE :
            if(num == -1) {
                mutex_unlock(&mutex);
                return -ENOENT;
            }
            temp_c.x = mazes[num].attr.w;
            temp_c.y = mazes[num].attr.h;
            if(copy_to_user((void *)arg, &temp_c, sizeof(coord_t))) {
                mutex_unlock(&mutex);
                return -EBUSY;
            }
            break;
        case MAZE_MOVE:
            if(num == -1) {
                mutex_unlock(&mutex);
                return -ENOENT;
            }
            if(copy_from_user(&temp_c, (void *)arg, sizeof(coord_t))) {
                mutex_unlock(&mutex);
                return -EFAULT;
            }
            if((temp_c.x == -1 && temp_c.y == 0) || (temp_c.x == 1 && temp_c.y == 0) 
                || (temp_c.x == 0 && temp_c.y == -1) || (temp_c.x == 0 && temp_c.y == 1)) {
                    temp_pos.x = mazes[num].pos.x + temp_c.x;
                    temp_pos.y = mazes[num].pos.y + temp_c.y;
                    if(mazes[num].attr.blk[temp_pos.y][temp_pos.x] == '.') {
                        mazes[num].pos.x = temp_pos.x;
                        mazes[num].pos.y = temp_pos.y;
                    }
            }
            break;
        case MAZE_GETPOS:
            if(num == -1) {
                mutex_unlock(&mutex);
                return -ENOENT;
            }
            temp_c.x = mazes[num].pos.x;
            temp_c.y = mazes[num].pos.x;
            if(copy_to_user((void *)arg, &temp_c, sizeof(coord_t))) {
                mutex_unlock(&mutex);
                return -EBUSY;
            }
            break;
        case MAZE_GETSTART:
            if(num == -1) {
                mutex_unlock(&mutex);
                return -ENOENT;
            }
            temp_c.x = mazes[num].attr.sx;
            temp_c.y = mazes[num].attr.sy;
            if(copy_to_user((void *)arg, &temp_c, sizeof(coord_t))) {
                mutex_unlock(&mutex);
                return -EBUSY;
            }
            break;
        case MAZE_GETEND :
            if(num == -1) {
                mutex_unlock(&mutex);
                return -ENOENT;
            }
            temp_c.x = mazes[num].attr.ex;
            temp_c.y = mazes[num].attr.ey;
            if(copy_to_user((void *)arg, &temp_c, sizeof(coord_t))) {
                mutex_unlock(&mutex);
                return -EBUSY;
            }
            break;
    }
    mutex_unlock(&mutex);
	return 0;
}

static const struct file_operations mazemod_dev_fops = {
	.owner = THIS_MODULE,
	.open = mazemod_dev_open,
    .release = mazemod_dev_close,
	.read = mazemod_dev_read,
	.write = mazemod_dev_write,
	.unlocked_ioctl = mazemod_dev_ioctl
};

static int mazemod_proc_read(struct seq_file *m, void *v) {
    for(int num = 0; num < 3; num++) {
        if((mazes[num].created)) {
            seq_printf(m, "##%02d: pid %d - [%d x %d]: (%d, %d) -> (%d, %d) @ (%d, %d)\n", num, mazes[num].pid, mazes[num].attr.w, mazes[num].attr.h, 
                        mazes[num].attr.sx, mazes[num].attr.sy, mazes[num].attr.ex, mazes[num].attr.ey, mazes[num].pos.x, mazes[num].pos.y);
            for(int i = 0; i < mazes[num].attr.h; i++) {
                seq_printf(m, " - %03d: %s\n", i, mazes[num].attr.blk[i]);
            }
        } else {
            seq_printf(m, "##%02d: vacancy\n", num);
        }
        seq_printf(m, "\n");
    }
    return 0;
}

static int mazemod_proc_open(struct inode *inode, struct file *file) {
	return single_open(file, mazemod_proc_read, NULL);
}

static const struct proc_ops mazemod_proc_fops = {
	.proc_open = mazemod_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static char *mazemod_devnode(const struct device *dev, umode_t *mode) {
	if(mode == NULL) return NULL;
	*mode = 0666;
	return NULL;
}

static int __init mazemod_init(void)
{
	// create char dev
	if(alloc_chrdev_region(&dev_num, 0, 1, "maze") < 0)
		return -1;
	if((clazz = class_create("upclass")) == NULL)
		goto release_region;
	clazz->devnode = mazemod_devnode;
	if(device_create(clazz, NULL, dev_num, NULL, "maze") == NULL)
		goto release_class;
	cdev_init(&maze_cdev, &mazemod_dev_fops);
	if(cdev_add(&maze_cdev, dev_num, 1) == -1)
		goto release_device;

	// create proc
	proc_create("maze", 0, NULL, &mazemod_proc_fops);
    
    for(int i = 0; i < 3; i++) {
        mazes[i].created = false;
    }

	printk(KERN_INFO "maze: initialized.\n");
	return 0;    // Non-zero return means that the module couldn't be loaded.

release_device:
	device_destroy(clazz, dev_num);
release_class:
	class_destroy(clazz);
release_region:
	unregister_chrdev_region(dev_num, 1);
	return -1;
}

static void __exit mazemod_cleanup(void)
{
	remove_proc_entry("maze", NULL);

	cdev_del(&maze_cdev);
	device_destroy(clazz, dev_num);
	class_destroy(clazz);
	unregister_chrdev_region(dev_num, 1);

	printk(KERN_INFO "maze: cleaned up.\n");
}

module_init(mazemod_init);
module_exit(mazemod_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Corange");
MODULE_DESCRIPTION("The unix programming course demo kernel module.");
