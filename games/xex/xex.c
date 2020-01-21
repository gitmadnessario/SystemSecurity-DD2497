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
void usage(void);
void check_args(char *, char *, unsigned char *);
void keygen(unsigned char *, unsigned char **, unsigned char *);
int myencrypt(unsigned char *, int, unsigned char *, unsigned char *,
    unsigned char **);
int decrypt(unsigned char *, int, unsigned char *, unsigned char *,
    unsigned char **);
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char **);
int verify_cmac(unsigned char *, unsigned char *);
int readFromFile(char *, unsigned char**, unsigned char**, int);
int writeToFile(char *, unsigned char *, int sizeOfStr, unsigned char*);
unsigned char* generate_iv(unsigned char*, int);


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
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
_Noreturn void usage(void){
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits"
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -h            This help message\n"
	);
	exit(-1);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void
check_args(char *input_file, char *output_file, unsigned char *password)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
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

/* 
 * Read from a file.
 * In the MINIX version take only the memcpy at the end
 * in order to extract the mac before decrypting the data.
 */
int readFromFile(char * inF, unsigned char** input, unsigned char** macblob, int mode){
	FILE * temPinF = fopen(inF,"r");
	if(!temPinF){
		printf("Could not open file for reading\n");
		exit(1);
	}
	if(mode)
		*macblob = malloc(CMAC_SIZE);
	char c;
	int counter=0;
	int BUFF_SIZE = 1024;
	unsigned char * str = malloc(BUFF_SIZE);
	while((c=fgetc(temPinF))!=EOF){
		if(counter == BUFF_SIZE){
			BUFF_SIZE+=1024;
			if(!(str=realloc(str,BUFF_SIZE))){
				exit(1);// null pointer on realloc exit with error
			}
		}
		str[counter]=c;
		counter++;
	}
	fclose(temPinF);
	if(mode){
		memcpy(*macblob, &str[counter - 16], 16);
	}
	*input = str;
	return counter;
}

int writeToFile(char * outF,unsigned char * str,int sizeOfStr, unsigned char* cmac){
	FILE * tempOutF = fopen(outF,"wb");
	if(!tempOutF){
		printf("Could not open file for writing\n");
		exit(1);
	}
	fwrite(str,sizeof(unsigned char),sizeOfStr, tempOutF);
	fwrite(cmac,sizeof(unsigned char),CMAC_SIZE, tempOutF);
	fclose(tempOutF);
	return 1;
}

int
main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */
	unsigned char* key; 		/* the generated key */
	unsigned char* iv = (unsigned char*)malloc(sizeof(unsigned char) * IV_SIZE);
	unsigned char* plaintext;
	int plaintext_len;
	unsigned char* cipher;
	int cipher_len;
	unsigned char* macblob;
	unsigned char* macblob2;

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	key = NULL;
	plaintext = NULL;
	cipher = NULL;
	macblob = NULL;
	macblob2 = NULL;

	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "i:m:o:p:")) != -1) {
		switch (opt) {
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'h':
		default:
			usage();
		}
	}

	/* check arguments */
	check_args(input_file, output_file, password);

	/* Keygen from password */
	printf("Generated key:\n");
	keygen(password, &key, iv);
	print_hex(key,64);

	unsigned char* test;
	readFromFile(input_file, &test, &macblob2, 0);

	printf("\nRead from input:\n");
	print_string(test,strlen((const char*)test));

	/* Operate on the data according to the mode */

	/* encrypt */
	iv = generate_iv(iv,IV_SIZE);

	cipher_len = myencrypt(test,strlen((const char*)test),key,iv,&cipher);
	if(cipher_len == -1)
		exit(1);
	
	/* Sign */
	gen_cmac(cipher,cipher_len,key,&macblob);

	/* Save CIPHER | CMAC to file */
	writeToFile(output_file, cipher, cipher_len, macblob);

	free(cipher);

	cipher_len = readFromFile(output_file, &cipher, &macblob2, 1) - 16;

	/* Verify */
	if(!verify_cmac(macblob,macblob2)){
		printf("verification failed\n");
		exit(1);
	}
	else
		printf("Verified\n");

	/* Decrypt */
	plaintext_len = decrypt(cipher, cipher_len, key, iv, &plaintext);
	if (plaintext_len == -1)
		exit(1);

	/* Clean up */
	free(input_file);
	free(output_file);
	free(password);
	free(iv);
	free(cipher);

	/* END */
	return 0;
}
