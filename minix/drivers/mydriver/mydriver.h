#ifndef __MYDRIVER_H
#define __MYDRIVER_H
 
/** The Hello, World! message. */
#define HELLO_MESSAGE "Hello, World!\n"

/* Buffer used when copy in/out of the driver */
extern unsigned char* internal_buffer;

/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t);
unsigned char* getUserPassword(uid_t);
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
 
#endif /* __MYDRIVER_H */
