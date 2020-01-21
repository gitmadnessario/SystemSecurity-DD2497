#ifndef _MYSERVER_PROTO_H
#define _MYSERVER_PROTO_H

/* Function prototypes. */

/* main.c */
int main(int argc, char **argv);

/* myserver.c */
int do_sys1(message *m_ptr);
int do_check_code(message *m_ptr);
int sef_cb_init_fresh(int type, sef_init_info_t *info);

/* function prototypes */
uid_t getuid(void);

void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t);
void keygen(unsigned char *, unsigned char **, unsigned char *);
int myencrypt(unsigned char *, int, unsigned char *, unsigned char *,
    unsigned char **);
int decrypt(unsigned char *, int, unsigned char *, unsigned char *,
    unsigned char **);
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char **);
int verify_cmac(unsigned char *, unsigned char *);
unsigned char* generate_iv(unsigned char*, int);
void encrypt_entry(unsigned char*, unsigned char*, int);
void decrypt_entry(unsigned char*, unsigned char*, int);

#endif
