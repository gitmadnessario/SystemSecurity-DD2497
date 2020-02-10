#include <stdio.h>
#include <stdlib.h>
#include <minix/syslib.h>
#include <minix/chardriver.h>
#include <minix/myserver.h>
#include "mydriver.h"

/* SEF functions and variables. */
static void sef_local_startup(void);
static int sef_cb_init(int type, sef_init_info_t *info);
static int sef_cb_lu_state_save(int, int);
static int lu_state_restore(void);
static int sef_cb_init_response(void);

 
/** State variable to count the number of times the device has been opened.
 * Note that this is not the regular type of open counter: it never decreases.
 */
static int open_counter;

/*
 * Function prototypes for the hello driver.
 */
static int mydriver_open(devminor_t minor, int access, endpoint_t user_endpt);
static int mydriver_close(devminor_t minor);
static ssize_t mydriver_read(devminor_t minor, u64_t position, endpoint_t endpt,
    cp_grant_id_t grant, size_t size, int flags, cdev_id_t id);
static ssize_t mydriver_write(devminor_t UNUSED(minor), u64_t position,
                           endpoint_t endpt, cp_grant_id_t grant, size_t size, int UNUSED(flags),
                           cdev_id_t UNUSED(id));
static void mydriver_other(message *m_ptr, int ipc_status);

static void startCycle();
static void generateGrants();
static void handleSendReceive();

/* Buffer used to pass messages in and out of the driver */
unsigned char* internal_buffer = NULL;
 
static int sef_cb_lu_state_save(int UNUSED(state), int UNUSED(flags)) {
  printf("sef_cb_lu_state_save\n");
  return OK;
}
 
static int lu_state_restore() {
  printf("lu_state_restore\n");
  return OK;
}

static void handleSendReceive(){
  message m;
	int ipc_status, reply_status;
  int r;
  while (TRUE) {

		/* Receive Message */
		r = sef_receive_status(ANY, &m, &ipc_status);
		if (r != OK) {
			printf("sef_receive_status() failed\n");
			continue;
		}
    printf("got message\n");
    switch (m.m_type)
    {
    case CDEV_READ:
      decrypt_entry(getUserPassword(m.m_vm_vfs_mmap.clearend), internal_buffer,
       m.m_vm_vfs_mmap.dev);
      break;
    case CDEV_WRITE:
      encrypt_entry(getUserPassword(m.m_vm_vfs_mmap.clearend), internal_buffer,
       m.m_vm_vfs_mmap.dev);
      break;
    default:
      printf("got message2\n");
      break;
    }
  }
}

static void startCycle(){
  generateGrants();
  //handleSendReceive();
}

static void generateGrants(){
  int access = CPF_READ;
  cp_grant_id_t mygrant = cpf_grant_direct(65562, (vir_bytes)internal_buffer, 
      1024, access);
  if(mygrant == -1)
    printf("failed to create grant, mydriver.c\n");
  //printf("mydriver created grant = %d\n", mygrant);
  myserver_sys1(mygrant); //store test grant in middleware

  access = CPF_WRITE;
  mygrant = cpf_grant_direct(65562, (vir_bytes)internal_buffer, 1024, access);
  if(mygrant == -1)
    printf("failed to create grant, mydriver.c\n");
  //printf("mydriver created grant = %d\n", mygrant);
  myserver_sys1(mygrant); //store the grant to use in middleware
}

static int sef_cb_init(int type, sef_init_info_t *UNUSED(info))
{
  /* Initialize the hello driver. */
  int do_announce_driver = TRUE;
  internal_buffer = (unsigned char*)malloc(1024 * sizeof(char));
  open_counter = 0;
  switch(type) {
  case SEF_INIT_FRESH:
    startCycle();
    //printf("%s", HELLO_MESSAGE);
    
    break;
 
  case SEF_INIT_LU:
    /* Restore the state. */
    lu_state_restore();
    do_announce_driver = FALSE;
 
    printf("%sHey, I'm a new version!\n", HELLO_MESSAGE);
    break;
 
  case SEF_INIT_RESTART:
    printf("%sHey, I've just been restarted!\n", HELLO_MESSAGE);
    break;

  default:
    printf("default case, type = %d\n", type);
    break;
  }
  printf("unkown type\n");
  /* Announce we are up when necessary. */
  if (do_announce_driver) {
    chardriver_announce();
  }
 
  /* Initialization completed successfully. */
  return OK;
}

static void sef_local_startup()
{
  /*
   * Register init callbacks. Use the same function for all event types
   */
  sef_setcb_init_fresh(sef_cb_init);
  sef_setcb_init_lu(sef_cb_init);
  sef_setcb_init_restart(sef_cb_init);

  /* Handle responses */
  sef_setcb_lu_response(sef_cb_lu_response_rs_reply);
  /* agree to update immediately when LU request is received */
  sef_setcb_lu_prepare(sef_cb_lu_prepare_always_ready); 
  /* support live update starting from any standard state */
  sef_setcb_lu_state_isvalid(sef_cb_lu_state_isvalid_standard); 

  /*
   * Register live update callbacks.
   */
  sef_setcb_lu_state_save(sef_cb_lu_state_save);
 
  /* Let SEF perform startup. */
  sef_startup();
}


/* Entry points to the hello driver. */
static struct chardriver mydriver_tab =
{
 .cdr_open	= mydriver_open,
 .cdr_close	= mydriver_close,
 .cdr_read	= mydriver_read,
 .cdr_write	= mydriver_write,
 .cdr_other = mydriver_other,
};

static int mydriver_open(devminor_t UNUSED(minor), int UNUSED(access),
                      endpoint_t UNUSED(user_endpt))
{
  printf("mydriver_open(). Called %d time(s).\n", ++open_counter);
  return OK;
}
 
static int mydriver_close(devminor_t UNUSED(minor))
{
  printf("mydriver_close()\n");
  return OK;
}
 
static ssize_t mydriver_read(devminor_t UNUSED(minor), u64_t position,
                          endpoint_t endpt, cp_grant_id_t grant, size_t size, 
                          int UNUSED(flags), cdev_id_t UNUSED(id))
{
  u64_t dev_size;
  char *ptr;
  int ret;
  char *buf = HELLO_MESSAGE;
 
  printf("mydriver_read()\n");
 
  /* This is the total size of our device. */
  dev_size = (u64_t) strlen(buf);
 
  /* Check for EOF, and possibly limit the read size. */
  if (position >= dev_size) return 0;		/* EOF */
  if (position + size > dev_size)
    size = (size_t)(dev_size - position);	/* limit size */
 
  /* Copy the requested part to the caller. */
  ptr = buf + (size_t)position;
  if ((ret = sys_safecopyto(endpt, grant, 0, (vir_bytes) ptr, size)) != OK)
    return ret;
 
  /* Return the number of bytes read. */
  return size;
}

static ssize_t mydriver_write(devminor_t UNUSED(minor), u64_t position,
                           endpoint_t endpt, cp_grant_id_t grant, size_t size,
                            int UNUSED(flags), cdev_id_t UNUSED(id))
{
  int ret;
  char buf[1025];
 
  printf("hello_write(position=%llu, size=%zu)\n", position, size);
 
  if (size > 1024)
    size = (size_t)(1024);	/* limit size */
 
  ret = sys_safecopyfrom(endpt, grant, 0, (vir_bytes) buf, size);
  printf("ret=%d\n", ret);

  buf[1024] = 0;
  printf("received=%s\n", buf);

  // unsigned char* tmp = "9999";
  // int access = CPF_WRITE;
  // cp_grant_id_t mygrant = cpf_grant_direct(65562,(vir_bytes)tmp,5,access);
  // if(mygrant == -1)
  //   printf("failed to create grant, mydriver.c\n");
  // printf("mydriver created grant = %d\n", mygrant);

  // myserver_sys1(mygrant);
  
  return size;
}

static void mydriver_other(message *m_ptr, int ipc_status){
  printf("mydriver_other called succesfully\n");
}


int main(int argc, char **argv)
{

  env_setargs(argc, argv);
  /*
   * Perform initialization.
   */
  sef_local_startup();
  
  printf("reached this, driver main\n");

  /*
   * Run the main loop.
   */
  //chardriver_task(&mydriver_tab);

  handleSendReceive();
  
  return OK;
}