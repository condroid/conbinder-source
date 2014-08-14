#ifndef _LINUX_CONTAINER_H
#define _LINUX_CONTAINER_H

#include <linux/ioctl.h>

#define CONTAINER_REGISTER      _IOW('c', 1, int)
#define CONTAINER_GET_FRONT_ID  _IOR('c', 2, int)
#define CONTAINER_SET_FRONT_ID  _IOW('c', 3, int)
#define CONTAINER_GET_STACK_POS _IOWR('c', 4, int)
#define CONTAINER_WAIT_FOR_NEW_POS _IOWR('c', 5, int)
#define CONTAINER_GET_AVAILABLE _IOR('c', 6, long)

#define MAX_CONTAINER 9

#endif
