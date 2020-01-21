/*  getlogin(3)
 *
 *  Author: Terrence W. Holm          Aug. 1988
 */

#include <sys/cdefs.h>
#include "namespace.h"
#include <lib.h>

#include <pwd.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "extern.h"

/*
 * indluce/pwd.h
 */
// struct passwd {
// 	__aconst char *pw_name;		/* user name */
// 	__aconst char *pw_passwd;	/* encrypted password */
// 	uid_t	       pw_uid;		/* user uid */
// 	gid_t	       pw_gid;		/* user gid */
// 	time_t	       pw_change;	/* password change time */
// 	__aconst char *pw_class;	/* user login class */
// 	__aconst char *pw_gecos;	/* general information */
// 	__aconst char *pw_dir;		/* home directory */
// 	__aconst char *pw_shell;	/* default shell */
// 	time_t 	       pw_expire;	/* account expiration */
// };

//This is called for "passwd [username]"
int __getlogin(char *logname, size_t sz)
{
  struct passwd *pw_entry;
  int i;
  printf("__getlogin\n");
  for(i = 0; i < sz; i++){
    printf("%c", logname[i]);
  }
  pw_entry = getpwuid(getuid());
  printf("\n__getlogin:after getpwuid()\n");
  for(i = 0; i < sz; i++){
    printf("%c ", pw_entry->pw_name[i]);
  }
  printf("uid_t:%u\n", pw_entry->pw_uid);
  printf("hashed password:%s\n", pw_entry->pw_passwd);

  if (pw_entry == (struct passwd *)NULL)
    return 0; 
    
  strncpy(logname, pw_entry->pw_name, sz);
  return sz;
}
