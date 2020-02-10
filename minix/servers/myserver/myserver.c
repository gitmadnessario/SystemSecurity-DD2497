#include "inc.h"
#include "myserver.h"

#include <minix/timers.h>
#include <minix/sysinfo.h>
#include "../pm/mproc.h"



static int32_t mydriver_readGrant = 0;
static int32_t mydriver_writeGrant = 0;

/*===========================================================================*
 *			    sef_cb_init_fresh				     *
 *===========================================================================*/
int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *info)
{
  return(OK);
}

int32_t getProcess(){
  //struct proc proc[NR_TASKS + NR_PROCS];
  struct mproc mproc[NR_PROCS];
  int r;
  /* Retrieve and check the PM process table. */
  r = getsysinfo(PM_PROC_NR, SI_PROC_TAB, mproc, sizeof(mproc));
  if (r != OK) {
    printf("MYDRIVER: warning: couldn't get copy of PM process table: %d\n", r);
    return -1;
  }
  endpoint_t end_p = 0;
  for (int mslot = 0; mslot < NR_PROCS; mslot++) {
    if (mproc[mslot].mp_flags & IN_USE) {
      if(strcmp(mproc[mslot].mp_name, "mydriver") == 0)
        return mproc[mslot].mp_endpoint;
    }
  }
  return -1;
}


/*===========================================================================*
 *				do_*				     *
 *===========================================================================*/
int do_sys1(message *m_ptr)
{

  //getProcess();

  unsigned char* tmp = "1234";
  int access = CPF_WRITE;
  int returnVal;
  if(mydriver_readGrant == 0){
    mydriver_readGrant = m_ptr->m_lc_vfs_getvfsstat.flags;

  }else{
    mydriver_writeGrant = m_ptr->m_lc_vfs_getvfsstat.flags;
  }
  
  return(OK);
}

int32_t do_sys2(message *m_ptr){
  if(m_ptr->m_lc_vfs_getvfsstat.flags){
    return mydriver_writeGrant;
  }else{
    return mydriver_readGrant;

  }
  return OK;
}

int do_sys3(message *m_ptr){
    return getProcess();
}

