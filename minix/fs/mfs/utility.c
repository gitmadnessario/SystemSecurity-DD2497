#include "fs.h"
#include "buf.h"
#include "inode.h"
#include "super.h"

#include <minix/bdev.h>
#include "../../lib/libbdev/type.h"
#include "../../lib/libbdev/proto.h"

#include <minix/timers.h>
//#include <include/arch/i386/include/archtypes.h>
//#include "../../kernel/proc.h"
#include <minix/sysinfo.h>
#include "../../servers/pm/mproc.h"

/*
  mydriver  98341
  vfs       1
  mfs       65562
  myserver  11
*/
void encrypt_entry(unsigned char* tmp, unsigned char* data, size_t chunk, cp_grant_id_t extragrant){
    //int device_num = bdev_driver_get(18);
    //printf("Endpoint for device 18: %d\n", device_num);
    int access = CPF_WRITE;
    int returnVal;
    cp_grant_id_t grant = cpf_grant_direct(98341,(vir_bytes)tmp,5,access);

    printf("try given grant\n");
    returnVal = sys_safecopyto(98341,extragrant  ,0,(vir_bytes)tmp,5);//(endpnt, grant, offset, ptr, size)
    if(returnVal != OK){
      printf("returnVal = %d\n", returnVal);
    }
    myserver_sys2(1);
    printf("Hello world\n");
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
      printf("%d %d %s\n", mproc[mslot].mp_pid, mproc[mslot].mp_endpoint, mproc[mslot].mp_name);
      // if (mproc[mslot].mp_pid == pid)
      //   end_p = mproc[mslot].mp_endpoint;
    }
  }
}

/*===========================================================================*
 *				conv2					     *
 *===========================================================================*/
unsigned conv2(norm, w)
int norm;			/* TRUE if no swap, FALSE for byte swap */
int w;				/* promotion of 16-bit word to be swapped */
{
/* Possibly swap a 16-bit word between 8086 and 68000 byte order. */
  if (norm) return( (unsigned) w & 0xFFFF);
  return( ((w&BYTE) << 8) | ( (w>>8) & BYTE));
}


/*===========================================================================*
 *				conv4					     *
 *===========================================================================*/
long conv4(norm, x)
int norm;			/* TRUE if no swap, FALSE for byte swap */
long x;				/* 32-bit long to be byte swapped */
{
/* Possibly swap a 32-bit long between 8086 and 68000 byte order. */
  unsigned lo, hi;
  long l;
  
  if (norm) return(x);			/* byte order was already ok */
  lo = conv2(FALSE, (int) x & 0xFFFF);	/* low-order half, byte swapped */
  hi = conv2(FALSE, (int) (x>>16) & 0xFFFF);	/* high-order half, swapped */
  l = ( (long) lo <<16) | hi;
  return(l);
}
