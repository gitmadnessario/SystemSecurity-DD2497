/* Prototypes and definitions for MYSERVER interface. */

#ifndef _MINIX_MYSERVER_H
#define _MINIX_MYSERVER_H

#include <sys/types.h>
#include <minix/endpoint.h>

/* myserver.c */

/* U32 */
int myserver_sys1(int32_t);
int32_t myserver_sys2(int32_t);
int myserver_sys3(void);

#endif /* _MINIX_MYSERVER_H */

