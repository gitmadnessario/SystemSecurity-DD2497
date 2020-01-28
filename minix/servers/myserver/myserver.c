#include "inc.h"
#include "myserver.h"

#include <minix/timers.h>
#include <minix/sysinfo.h>
#include "../pm/mproc.h"



static int32_t mydriver_grant = 0;
static int consumer = 0;

/*===========================================================================*
 *			    sef_cb_init_fresh				     *
 *===========================================================================*/
int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *info)
{
  return(OK);
}

void getProcess(){
  //struct proc proc[NR_TASKS + NR_PROCS];
  struct mproc mproc[NR_PROCS];
  int r;
  /* Retrieve and check the PM process table. */
  r = getsysinfo(PM_PROC_NR, SI_PROC_TAB, mproc, sizeof(mproc));
  if (r != OK) {
    printf("MYDRIVER: warning: couldn't get copy of PM process table: %d\n", r);
    return;
  }
  endpoint_t end_p = 0;
  for (int mslot = 0; mslot < NR_PROCS; mslot++) {
    if (mproc[mslot].mp_flags & IN_USE) {
      if(mproc[mslot].mp_endpoint == 11 || mproc[mslot].mp_endpoint == 65562 ||
       mproc[mslot].mp_endpoint ==  98341 || mproc[mslot].mp_endpoint == 1)
        printf("%d %d %s\n", mproc[mslot].mp_pid, mproc[mslot].mp_endpoint, mproc[mslot].mp_name);
      // if (mproc[mslot].mp_pid == pid)
      //   end_p = mproc[mslot].mp_endpoint;
    }
  }
}


/*===========================================================================*
 *				do_*				     *
 *===========================================================================*/
int do_sys1(message *m_ptr)
{
  //printf("%u\n",getuid());
  printf("invoked the syscall 01\n");


  printf("received message: %d\n", m_ptr->m_lc_vfs_getvfsstat.flags);
  //getProcess();

  unsigned char* tmp = "1234";
  int access = CPF_WRITE;
  int returnVal;
  printf("first time??\n");
  if(mydriver_grant == 0){
    printf("execute for 11\n");
    mydriver_grant = m_ptr->m_lc_vfs_getvfsstat.flags;
    returnVal = sys_safecopyto(98341,mydriver_grant, 0, (vir_bytes)tmp, 5);//(endpnt, grant, offset, ptr, size)
    if(returnVal != OK){
      printf("returnVal = %d\n", returnVal);
    }
    printf("ipc_sendrec\n");
    // int returnVal;
    // m_ptr->m_type = CDEV_READ;
    // returnVal = ipc_send(98341, m_ptr);
    // if(returnVal != OK)
    //   printf("communication error: myserver -> mydriver\n");
    // printf("message sent\n");
  }else{
    mydriver_grant = m_ptr->m_lc_vfs_getvfsstat.flags;
  }
  
  return(OK);
}

int32_t do_sys2(message *m_ptr){
  printf("invoked the syscall 02\n");

  if(!m_ptr->m_lc_vfs_getvfsstat.flags){
    printf("returning value %d\n", mydriver_grant);
    return mydriver_grant;
  }else{
    int returnVal;
    returnVal = ipc_send(98341, m_ptr);
    if(returnVal != OK)
      printf("communication error: myserver -> mydriver\n");
    return 0;
  }
  consumer = 1;
  return OK;
}

int do_sys3(message *m_ptr){
  printf("invoked the syscall 03\n");
  while(consumer == 0){

  }
  return OK;
}

