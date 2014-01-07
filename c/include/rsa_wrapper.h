
#include <stdio.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>


void init_openssl(void)
{
    OpenSSL_add_all_algorithms();
    RAND_load_file("/dev/urandom", 1024);
}

void cleanup_openssl(void)
{
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    ERR_remove_thread_state(0);
    EVP_cleanup();
    
    ERR_remove_state(0);
}

int rsa_generate_key(RSA * rsa, int bits)
{
    int ret =0;
    unsigned long e=RSA_3;
    BIGNUM * bignum=BN_new();  
    do{
        if(NULL ==bignum)
            break;
        int rt=BN_set_word(bignum,e);
        if(rt!=1)
        {
            printf("BN_set_word err!\n");
            ret =-1;
            break;
        }
        
        rt=RSA_generate_key_ex(rsa,bits,bignum,NULL);
        if(rt!=1)
        {
            printf("RSA_generate_key_ex err!\n");
            ret =-1;
            break;
        }
    }while(0);
    
    if(bignum)
        BN_clear_free(bignum);
    return ret;
}



int passwd_callback(char *pcszBuff,int size,int rwflag, void *pPass)
{
    size_t unPass = strlen((char*)pPass);
    if(unPass > (size_t)size)
        unPass = (size_t)size;
    memcpy(pcszBuff, pPass, unPass);
    return (int)unPass;
}
int rsa_read_private_key(RSA * rsa,const char * fileName,int useCipherPrivateKey,unsigned char * passphrase)
{
    int ret =0;  
    FILE * pFile = NULL;
    pFile = fopen(fileName,"rt");
    
    do{
        if(NULL ==pFile)
        {
            printf("fopen err!\n");
            break;
        }
        if(useCipherPrivateKey)
        {
            rsa =PEM_read_RSAPrivateKey(pFile, NULL,passwd_callback, passphrase);                                        
            if(NULL==rsa)
            {
                printf("PEM_read_RSAPrivateKey err!\n");
                ERR_print_errors_fp(stderr);
                break;
            }
        }
        else
        {  
            rsa =PEM_read_RSAPrivateKey(pFile, NULL,NULL, NULL);                                        
            if(NULL==rsa)
            {
                printf("PEM_read_RSAPrivateKey err!\n");
                break;
            }
        }
    }while(0);
    
    if(pFile)
    {
        fclose(pFile);
        pFile = NULL;
    }
    return ret;
}

int rsa_write_private_key(RSA * rsa,const char * fileName,int useCipherPrivateKey,unsigned char * passphrase,int passphraseLength)
{
    int ret =0;  
    FILE * pFile = NULL;
    pFile = fopen(fileName,"wt");
    
    do{
        if(NULL ==pFile)
        {
            printf("fopen err!\n");
            break;
        }
        if(useCipherPrivateKey)
        {            
            if( !PEM_write_RSAPrivateKey(pFile, rsa, EVP_aes_256_cbc(), passphrase, passphraseLength,NULL,NULL) )
            {
                printf("PEM_write_RSAPrivateKey err!\n");
                break;
            }
        }
        else
        {
            if( !PEM_write_RSAPrivateKey(pFile, rsa, NULL, NULL, 0, NULL, NULL) )
            {
                printf("PEM_write_RSAPrivateKey err!\n");
                break;
            }
        }
    }while(0);
    
    if(pFile)
    {
        fclose(pFile);
        pFile = NULL;
    }
    return ret;
}


int rsa_read_public_key(RSA * rsa,const char * fileName)
{
    int ret =0;  
    FILE * pFile = NULL;
    pFile = fopen(fileName,"rt");
    
    do{
        if(NULL ==pFile)
        {
            printf("fopen err!\n");
            break;
        }
        rsa =PEM_read_RSAPublicKey(pFile, NULL,NULL, NULL);                                        
        if(NULL==rsa)
        {
            printf("PEM_read_RSAPublicKey err!\n");
            ERR_print_errors_fp(stderr);
            break;
        }
    }while(0);
    
    if(pFile)
    {
        fclose(pFile);
        pFile = NULL;
    }
    return ret;
}

int rsa_write_public_key(RSA * rsa,const char * fileName)
{
    int ret =0;  
    FILE * pFile = NULL;
    pFile = fopen(fileName,"wt");
    
    do{
        if(NULL ==pFile)
        {
            printf("fopen err!\n");
            break;
        }
        if( !PEM_write_RSAPublicKey(pFile, rsa) )
        {
            printf("PEM_write_RSAPublicKey err!\n");
            break;
        }
    }while(0);
    
    if(pFile)
    {
        fclose(pFile);
        pFile = NULL;
    }
    return ret;
}


#define LINE_SUM 30
int rsa_encrypt_private(int fromlen, unsigned char *from,unsigned char *to, RSA *rsa, int padding,int & resultSignatureLen)
{    
    printf("\nrsa_encrypt_private from----\n");
    for(int i=0;i<fromlen;i++)
    {
        printf("%02x,",from[i]);
        if (i%LINE_SUM==LINE_SUM-1) printf("\n");
    }
    int len=RSA_private_encrypt(fromlen,from,to,rsa,padding);
    if(len<=0)
    {
        printf("RSA_private_encrypt err!\n");
        return -1;
    }
    resultSignatureLen =len;
    printf("\nto----\n");
    for(int i=0;i<resultSignatureLen;i++)
    {
        printf("%02x,",to[i]);
        if (i%LINE_SUM==LINE_SUM-1) printf("\n");
    }
    return 0;
}

int rsa_decrypt_public(int fromlen, unsigned char *from,unsigned char *to, RSA *rsa, int padding,int & resultLen)
{
    printf("\nrsa_decrypt_public from----\n");
    for(int i=0;i<fromlen;i++)
    {
        printf("%02x,",from[i]);
        if (i%LINE_SUM==LINE_SUM-1) printf("\n");
    }
    int len=RSA_public_decrypt(fromlen,from,to,rsa,padding);
    if(len<=0)
    {
        printf("RSA_public_decrypt err!\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    resultLen =len;
    printf("\nrsa_decrypt_public to----\n");
    for(int i=0;i<resultLen;i++)
    {
        printf("%02x,",to[i]);
        if (i%LINE_SUM==LINE_SUM-1) printf("\n");
    }
    return 0;
}

int rsa_encrypt_public(int fromlen, unsigned char *from,unsigned char *to, RSA *rsa, int padding,int & resultLen)
{
    printf("\nrsa_encrypt_public from----\n");
    for(int i=0;i<fromlen;i++)
    {
        printf("%02x,",from[i]);
        if (i%LINE_SUM==LINE_SUM-1) printf("\n");
    }
    int len=RSA_public_encrypt(fromlen,from,to,rsa,padding);
    if(len<=0)
    {
        printf("RSA_public_encrypt err!\n");
        return -1;
    }
    resultLen =len;
    printf("\nrsa_encrypt_public to----\n");
    for(int i=0;i<resultLen;i++)
    {
        printf("%02x,",to[i]);
        if (i%LINE_SUM==LINE_SUM-1) printf("\n");
    }
    return 0;
}
   
int rsa_decrypt_private(int fromlen, unsigned char *from,unsigned char *to, RSA *rsa, int padding,int & resultLen)
{
    printf("\nrsa_decrypt_private from----\n");
    for(int i=0;i<fromlen;i++)
    {
        printf("%02x,",from[i]);
        if (i%LINE_SUM==LINE_SUM-1) printf("\n");
    }
    int len=RSA_private_decrypt(fromlen,from,to,rsa,padding);
    if(len<=0)
    {
        printf("RSA_private_decrypt err!\n");
        return -1;
    }
    resultLen =len;
    printf("\nrsa_decrypt_private to----\n");
    for(int i=0;i<resultLen;i++)
    {
        printf("%02x,",to[i]);
        if (i%LINE_SUM==LINE_SUM-1) printf("\n");
    }
    return 0;
}