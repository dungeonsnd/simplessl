#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/aes.h>


int main(int argc, char** argv) {

   AES_KEY aes;
    unsigned char key[AES_BLOCK_SIZE];        // AES_BLOCK_SIZE = 16
    unsigned char iv[AES_BLOCK_SIZE];        // init vector
    unsigned char* input_string;
    unsigned char* encrypt_string;
    unsigned char* decrypt_string;
    unsigned int len;        // encrypt length (in multiple of AES_BLOCK_SIZE)
    unsigned int i;
    int remainder;
    

    // check usage
    if (argc != 2) {
        fprintf(stderr, "%s <plain text>\n", argv[0]);
        exit(-1);
    }
    // check input
    if (strlen(argv[1])<=0) {
        fprintf(stderr, "input length is zero!\n");
        exit(-1);
    }

    // set the encryption length
    len = strlen(argv[1]) + AES_BLOCK_SIZE;
    remainder =strlen(argv[1])%AES_BLOCK_SIZE;
    if ( 0!=remainder)
        len -= remainder;

    // set the input string
    input_string = (unsigned char*)calloc(len, sizeof(unsigned char));
    if (input_string == NULL) {
        fprintf(stderr, "Unable to allocate memory for input_string\n");
        exit(-1);
    }
    //padding! Important!    
    memset( input_string,len-strlen(argv[1]),len );
    strncpy((char*)input_string, argv[1], strlen(argv[1]));
    
    // Generate AES 128-bit key
    memset(key, 0x01, AES_BLOCK_SIZE);

    // Set encryption key
    memset(iv, 0x01, AES_BLOCK_SIZE);
    if (AES_set_encrypt_key(key, 128, &aes) < 0) {
        fprintf(stderr, "Unable to set encryption key in AES\n");
        exit(-1);
    }

    // alloc encrypt_string
    encrypt_string = (unsigned char*)calloc(len, sizeof(unsigned char));    
    if (encrypt_string == NULL) {
        fprintf(stderr, "Unable to allocate memory for encrypt_string\n");
        exit(-1);
    }

    // encrypt (iv will change)
    AES_cbc_encrypt(input_string, encrypt_string, len, &aes, iv, AES_ENCRYPT);

    /////////////////////////////////////
    
    // alloc decrypt_string
    decrypt_string = (unsigned char*)calloc(len, sizeof(unsigned char));
    if (decrypt_string == NULL) {
        fprintf(stderr, "Unable to allocate memory for decrypt_string\n");
        exit(-1);
    }
    
    // Set decryption key
    memset(iv, 0x01, AES_BLOCK_SIZE);
    if (AES_set_decrypt_key(key, 128, &aes) < 0) {
        fprintf(stderr, "Unable to set decryption key in AES\n");
        exit(-1);
    }

    // decrypt
    AES_cbc_encrypt(encrypt_string, decrypt_string, len, &aes, iv, 
            AES_DECRYPT);

    // print
    printf("input_string =%s\n", input_string);
    printf("encrypted string =");
    for (i=0; i<len; ++i) {
        printf("%u ", encrypt_string[i]);    
    }
    printf("\n");
    printf("decrypted string =%s\n", decrypt_string);



    return 0;
}
