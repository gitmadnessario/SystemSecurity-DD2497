#include "mycrypto.h"

#include <minix/syslib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// #include "../../../crypto/external/bsd/openssl/dist/crypto/evp/evp.h"
// #include "../../../crypto/external/bsd/openssl/dist/crypto/cmac/cmac.h"
// #include "../../../crypto/external/bsd/openssl/dist/crypto/"
// #include "../../../crypto/external/bsd/openssl/dist/crypto/evp/"

// #include <openssl/evp.h>
// #include <openssl/err.h>
// #include <openssl/conf.h>
// #include <openssl/cmac.h>

//typedef long unsigned size_t;


void test_print(void){
    char* test = NULL;
    sys_safecopyto(18,0,0,(vir_bytes)test,0);//(endpnt, grant, offset, ptr, size)
    //OpenSSL_add_all_algorithms();
    printf("test_print called succesfully\n");
}

/*
 * Prints the hex value of the input
 * 16 values per line
 */
// void
// print_hex(unsigned char *data, size_t len)
// {
// 	size_t i;

// 	if (!data)
// 		printf("NULL data\n");
// 	else {
// 		for (i = 0; i < len; i++) {
// 			if (!(i % 16) && (i != 0))
// 				printf("\n");
// 			printf("%02X ", data[i]);
// 		}
// 		printf("\n");
// 	}
// }

/*
 * Generates a key using the given password
 */
// void
// keygen(unsigned char *password, unsigned char **key, unsigned char *iv){

// 	//PKCS5_PBKDF2_HMAC for safer use
// 	int i;
// 	unsigned char* salt = NULL;
// 	int nrounds = 15;
// 	const EVP_MD *dgst = NULL;

// 	OpenSSL_add_all_algorithms();

// 	dgst=EVP_get_digestbyname("sha1");
//   if(!dgst) { fprintf(stderr, "no such digest: sha1\n"); }

// 	*key = malloc(64);
// 	i = EVP_BytesToKey(EVP_aes_256_xts(), EVP_sha1(), salt, 
// 	(const unsigned char*)password, strlen((const char*)password), nrounds, *key, iv);
// 	if (i != 64) {
// 			printf("Key size is wrong\n");
// 			exit(1);
// 	}
// }