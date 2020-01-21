#ifndef _MYSERVER_MYSERVER_H_
#define _MYSERVER_MYSERVER_H_

/* Type definitions for the Data Store Server. */
#include <sys/types.h>
#include <minix/config.h>
#include <minix/ds.h>
#include <minix/bitmap.h>
#include <minix/param.h>
#include <regex.h>

#include <lib.h>
#include <pwd.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 16
#define IV_SIZE 16
#define CMAC_SIZE 16

#endif /* _DS_STORE_H_ */
