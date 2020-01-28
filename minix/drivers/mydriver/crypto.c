/*
 * AES XTS 256
 * 
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 16
#define IV_SIZE 16
#define CMAC_SIZE 16

/* function prototypes */
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

/*
 * Prints the hex value of the input
 * 16 values per line
 */
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 */
void
print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}

/*
 * Generates a key using the given password
 */
void
keygen(unsigned char *password, unsigned char **key, unsigned char *iv){

	//PKCS5_PBKDF2_HMAC for safer use
	int i;
	unsigned char* salt = NULL;
	int nrounds = 15;
	const EVP_MD *dgst = NULL;

	OpenSSL_add_all_algorithms();

	dgst=EVP_get_digestbyname("sha1");
    if(!dgst) { fprintf(stderr, "no such digest: sha1\n"); }

	*key = malloc(64);
	i = EVP_BytesToKey(EVP_aes_256_xts(), EVP_sha1(), salt, 
	(const unsigned char*)password, strlen((const char*)password), nrounds, *key, iv);
	if (i != 64) {
			printf("Key size is wrong\n");
			exit(1);
	}
}

/*
 * Generate a random string of length size
 */
unsigned char* generate_iv(unsigned char* iv, int size){
	//This should be the block/unit number when storing(16 bytes)
	const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJK0123456789";
    if (size) {
        for (int n = 0; n < size; n++) {
            //int key = rand() % (int) (sizeof charset - 1);
            //iv[n] = charset[key];
		    iv[n] = charset[n];
        }
        //iv[size] = '\0'; //not neaded, iv is 16 bytes
    }
    return iv;
}

/*
 * Encrypts the data
 */
int
myencrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
    unsigned char *iv, unsigned char **ciphertext){
    int ciphertext_len;// = plaintext_len+BLOCK_SIZE;
    EVP_CIPHER_CTX e;

    EVP_CIPHER_CTX_init(&e);

    if(EVP_EncryptInit_ex(&e,EVP_aes_256_xts(),NULL,key,iv)!=1){
        printf("Fail on encrypt init\n");
        return -1;
    }

    unsigned char* mycipher = malloc(plaintext_len + BLOCK_SIZE);
    unsigned char* mycipher2 = malloc(plaintext_len + BLOCK_SIZE);
    int myclen;
    int myclen2;
    /* Add padding if plaintext less than one block */
    if(plaintext_len < 16){
        for(int i = plaintext_len; i < 16 - plaintext_len; i++){
            plaintext[i] = 0x00;
        }
        plaintext_len = 16;
    }
    if(EVP_EncryptUpdate(&e,mycipher, &myclen,plaintext, plaintext_len) != 1){
        printf("failed to encrypt update\n");
        return -1;
    }
    if(EVP_EncryptFinal_ex(&e,mycipher2, &myclen2) != 1){
        printf("failed to encrypt final\n");
        return -1;
    }
    *ciphertext = malloc(myclen + myclen2);
    memcpy(*ciphertext,mycipher,myclen);
    memcpy(*(ciphertext) + myclen,mycipher2,myclen2);
    ciphertext_len = myclen + myclen2;

    printf("\nEncrypted:\n");
    print_hex(mycipher, myclen);
    print_hex(mycipher2, myclen2);
    free(mycipher);
    free(mycipher2);
    return ciphertext_len;
}


/*
 * Decrypts the data and returns the plaintext size
 */
int
decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
    unsigned char *iv, unsigned char **plaintext){
	int plaintext_len;
	EVP_CIPHER_CTX e;

	EVP_CIPHER_CTX_init(&e);

	if(EVP_DecryptInit_ex(&e,EVP_aes_256_xts(),NULL,key,iv) != 1){
		printf("Fail on encrypt init\n");
		return -1;
	}

	unsigned char* myplain = malloc(ciphertext_len + BLOCK_SIZE);
	int myplen;
	int myplen2;
	if(EVP_DecryptUpdate(&e,myplain, &myplen,ciphertext, ciphertext_len) != 1){
		printf("Failed to decrypt update\n");
		return -1;
	}

	if(EVP_DecryptFinal_ex(&e, myplain + myplen, &myplen2) != 1){
		printf("Failed to decrypt final\n");
		return -1;
	}

	*plaintext = malloc(myplen + myplen2);
	memcpy(*plaintext,myplain,myplen+myplen2);
	plaintext_len = myplen + myplen2;
	printf("\nDecrypted:\n");
	print_string(*plaintext,plaintext_len);
	free(myplain);

	return plaintext_len;
}


/*
 * Generates a CMAC
 */
void
gen_cmac(unsigned char *data, size_t data_len, unsigned char *key,
    unsigned char **cmac)
{
	CMAC_CTX *mycmac = CMAC_CTX_new();
	size_t mac_size = 16;
	*cmac = malloc(CMAC_SIZE);
	CMAC_Init(mycmac,key,32,EVP_aes_256_ecb(),NULL);
	CMAC_Update(mycmac,data,data_len);
	CMAC_Final(mycmac,*cmac,&mac_size);

	printf("CMAC computed:\n");
	print_hex(*cmac,CMAC_SIZE);
}


/*
 * Verifies a CMAC
 */
int
verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{
	int i;
	for(i=0;i<CMAC_SIZE;i++){
		if(cmac1[i] != cmac2[i])
			return 0;
	}
	return 1;
}

/* Entry point for encrypting the given blob */
void encrypt_entry(unsigned char* password, unsigned char* plaintext, int plaintext_len){
	//unsigned char *password;	/* the user defined password */
	unsigned char* key; 		/* the generated key */
	unsigned char* iv = (unsigned char*)malloc(sizeof(unsigned char) * IV_SIZE);
	unsigned char* cipher;
	int cipher_len;
	unsigned char* macblob;

	/* Init arguments */
	key = NULL;
	cipher = NULL;
	macblob = NULL;

	/* Keygen from password */
	printf("Generated key:\n");
	keygen(password, &key, iv);
	print_hex(key,64);

    printf("Generate IV:\n");
	iv = generate_iv(iv,IV_SIZE);
    print_hex(iv, 16);

  	/* encrypt */
	cipher_len = myencrypt(plaintext,plaintext_len,key,iv,&cipher);
	if(cipher_len == -1)
		exit(1);
	
	/* Sign */
	gen_cmac(cipher,cipher_len,key,&macblob);

}

/* Entry point for decrypting the given blob */
void decrypt_entry(unsigned char* password, unsigned char* cipher, int cipher_len){
    unsigned char* macblob;
    unsigned char* verify_mac = malloc(CMAC_SIZE);
    unsigned char* key; 		/* the generated key */
    unsigned char* iv = (unsigned char*)malloc(sizeof(unsigned char) * IV_SIZE);
    unsigned char* plaintext;
    int plaintext_len;

    /* Keygen from password */
	printf("Generated key:\n");
	keygen(password, &key, iv);
	print_hex(key,64);

    printf("Generate IV:\n");
	iv = generate_iv(iv,IV_SIZE);
    print_hex(iv, 16);

    /* Split mac from cipher */
    memcpy(verify_mac, &cipher[cipher_len - 16], 16);
    cipher_len -= 16;

    /* Sign */
	gen_cmac(cipher,cipher_len,key,&macblob);

	/* Verify */
	if(!verify_cmac(macblob,verify_mac)){
		printf("verification failed\n");
		exit(1);
	}
	else
		printf("Verified\n");

	/* Decrypt */
	plaintext_len = decrypt(cipher, cipher_len, key, iv, &plaintext);
	if (plaintext_len == -1)
		exit(1);
}

