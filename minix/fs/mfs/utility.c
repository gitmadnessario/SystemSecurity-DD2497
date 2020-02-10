#include "fs.h"
#include "buf.h"
#include "inode.h"
#include "super.h"

#include <minix/bdev.h>
#include "../../lib/libbdev/type.h"
#include "../../lib/libbdev/proto.h"

#include <minix/timers.h>
#include <minix/sysinfo.h>
#include "../../servers/pm/mproc.h"
#include <stdlib.h>
#include <string.h>

/** Copies the data to the driver, passes the inode and the user id and
 *  retrieves the encrypted content along with the cmac
 */
unsigned char* encrypt_entry(struct inode* rip, unsigned char* data, 
  size_t chunk, uid_t uid){
    int returnVal;
    endpoint_t endpoint = myserver_sys3(); //get endpoint of mydriver
    cp_grant_id_t extragrant = myserver_sys2(1); //get write grant
    returnVal = sys_safecopyto(endpoint,extragrant, 0,(vir_bytes)data,chunk);
    if(returnVal != OK){
      printf("returnVal = %d\n", returnVal);
    }
    notify_driver(endpoint,rip,chunk, uid, CDEV_WRITE);
    extragrant = myserver_sys2(0); //get read grant
    //cipher + cmac => +16
    returnVal = sys_safecopyfrom(endpoint,extragrant, 0,(vir_bytes)data,chunk+16);
    if(returnVal != OK){
      printf("returnVal = %d\n", returnVal);
    }
    return data;
}

/** 
 *  Copies the data to the driver, passes the inode and the user id and
 *  retrieves the decrypted content.
 */
unsigned char* decrypt_entry(struct inode* rip, unsigned char* data, 
  size_t chunk, uid_t uid){
    int returnVal;
    endpoint_t endpoint = myserver_sys3(); //get endpoint of mydriver
    cp_grant_id_t extragrant = myserver_sys2(1); //get write grant
    returnVal = sys_safecopyto(endpoint,extragrant, 0,(vir_bytes)data,chunk);
    if(returnVal != OK){
      printf("returnVal = %d\n", returnVal);
    }
    notify_driver(endpoint, rip, chunk, uid, CDEV_READ);
    extragrant = myserver_sys2(0); //get read grant
    //cmac removed => will use chunk - 16 
    returnVal = sys_safecopyfrom(endpoint,extragrant, 0,(vir_bytes)data,chunk - 16);
    if(returnVal != OK){
      printf("returnVal = %d\n", returnVal);
    }
    return data;
}

/**
 * Calls the driver and passes the user id.
 */
void notify_driver(endpoint_t endpoint, struct inode* rip, size_t chunk, 
  uid_t uid, int access){
  message m_ptr;
  int returnVal; 

  //no need to create new message type, use this
  m_ptr.m_type = access;
  m_ptr.m_vm_vfs_mmap.clearend = uid;
  m_ptr.m_vm_vfs_mmap.dev = chunk;
  m_ptr.m_vm_vfs_mmap.ino = rip->i_num;

  returnVal = ipc_send(endpoint, &m_ptr);
  if(returnVal != OK)
    printf("communication error: mfs -> mydriver\n");
  else{
    //all good
  }
}

/**
 * A simple XOR operation as a prototype. 
 * uid is used as a key in a cyclic fashion without any
 * further expansion.
 */ 
unsigned char* simpleXOR(unsigned char* uid, unsigned char* blob, size_t size){
  int i;
  int key_length = strlen(uid);
  unsigned char* tmp = (unsigned char*)malloc(sizeof(char)*size);
  for(i = 0; i < size; i++ ){
    tmp[i] = blob[i] ^ uid[i % key_length];
  }
  memcpy(blob, tmp, size);
  return tmp;
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
