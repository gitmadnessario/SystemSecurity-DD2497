#include <minix/ds.h>
#include <minix/myserver.h>
#include <string.h>

#include "syslib.h"

static int do_invoke_myserver(message *m, int type)
{
	int r;

	r = _taskcall(MYSERVER_PROC_NR, type, m);

	return r;
}

int myserver_sys1(int32_t input)
{
	message m;

	memset(&m, 0, sizeof(m));

	m.m_lc_vfs_getvfsstat.flags = input;

	return do_invoke_myserver(&m, MYSERVER_SYS1);
}

int32_t myserver_sys2(int32_t input){
	message m;

	memset(&m, 0, sizeof(m));

	m.m_lc_vfs_getvfsstat.flags = input;

	return do_invoke_myserver(&m, MYSERVER_SYS2);
}

int myserver_sys3(void){
	message m;

	memset(&m, 0, sizeof(m));

	return do_invoke_myserver(&m, MYSERVER_SYS3);
}


