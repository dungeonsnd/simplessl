
#include <stdio.h>
#include <string.h>
#include <string>

#include "rsa_wrapper.hpp"

int MAIN( int argc,char * argv[] )
 {
    init_openssl();
    
    RSA * rsa=RSA_new();
    do{
        if(NULL ==rsa)
        {
            printf("RSA_new err!\n");
            break;
        }
        int bits =2048;
        int rt =rsa_generate_key(rsa, bits);
        if(0!=rt)
        {
            printf("rsa_generate_key err!\n");
            break;
        }
        
        const std::string privatekey("privatekey.pem");
        const std::string publickey("publickey.pem");
        const char* pcszPassphrase = "open sezamee";
        int encryptedPrivateKey =0;
        
        rt =rsa_write_private_key(rsa,privatekey.c_str(),encryptedPrivateKey,(unsigned char*)pcszPassphrase,(int)strlen(pcszPassphrase));
        if(0!=rt)
        {
            printf("rsa_write_key err!\n");
            break;
        }
        
        rt =rsa_write_public_key(rsa,publickey.c_str());
        if(0!=rt)
        {
            printf("rsa_write_key err!\n");
            break;
        }
        
        
        
        rt =rsa_read_private_key(rsa,privatekey.c_str(),encryptedPrivateKey,(unsigned char*)pcszPassphrase);
        if(0!=rt)
        {
            printf("rsa_write_key err!\n");
            break;
        }
        
    /*
        
        rt =rsa_read_public_key(rsa,publickey.c_str());
        if(0!=rt)
        {
            printf("rsa_write_key err!\n");
            break;
        }
        
        ///////////////////////////////////////////////////////////
        int flen =RSA_size(rsa);
        int padding =RSA_PKCS1_PADDING;
//        int padding =RSA_NO_PADDING;
//        int padding =RSA_X931_PADDING;
        if(padding==RSA_PKCS1_PADDING)
            flen-=11;
        else if(padding==RSA_X931_PADDING)
            flen-=2;
        else if(padding==RSA_NO_PADDING)
            flen=flen;
        else
        {
            printf("\nrsa not surport !\n");
            return -1;
        }
        
        unsigned char from[300],to[300];
        for(int i=0;i<flen;i++)
            memset(&from[i],i,1);
        printf(" \n**** flen=%d,padding=%d \n",flen,padding);
        int resultSignatureLen =0;
        rt =rsa_encrypt_private(flen, from, to, rsa, padding, resultSignatureLen);
        if(-1==rt)
        {
            printf("\nrsa_encrypt_private err!\n");
            break;
        }
        
        printf(" \n**** resultSignatureLen=%d,padding=%d \n",resultSignatureLen,padding);
        int resultLen =0;
        rt =rsa_decrypt_public(resultSignatureLen, to, from, rsa, padding, resultLen);
        if(0!=rt)
        {
            printf("\nrsa_decrypt_public err!\n");
            break;
        }
        printf(" \n**** rsa_decrypt_public , resultLen=%d \n",resultLen);
    
    
        // 
        flen=RSA_size(rsa);
        padding =RSA_PKCS1_PADDING;
        if(padding==RSA_PKCS1_PADDING)
            flen-=11;
        else if(padding==RSA_SSLV23_PADDING)
            flen-=11;
        else if(padding==RSA_X931_PADDING)
            flen-=2;
        else if(padding==RSA_NO_PADDING)
            flen=flen;
        else if(padding==RSA_PKCS1_OAEP_PADDING)
            flen=flen-2 * SHA_DIGEST_LENGTH-2 ;
        else
        {
            printf("rsa not surport !\n");
            break;
        }
        printf(" \n**** flen=%d,padding=%d \n",flen,padding);
        
        for(int i=0;i<flen;i++)
            memset(&from[i],i,1);
        resultLen =0;
        rt =rsa_encrypt_public(flen, from, to, rsa, padding, resultLen);
        if(0!=rt)
        {
            printf("\rsa_encrypt_public err!\n");
            break;
        }
        printf(" \n**** rsa_encrypt_public , resultLen=%d \n",resultLen);
        
        rt =rsa_decrypt_private(resultLen, to, from, rsa, padding, resultLen);
        if(0!=rt)
        {
            printf("\rsa_decrypt_private err!\n");
            break;
        }
        printf(" \n**** rsa_decrypt_private , resultLen=%d \n",resultLen);
        
        */
    }while(0);
    if(rsa)
    {
        RSA_free(rsa);
    }
    cleanup_openssl();
    return 0;
}

int main( int argc,char * argv[] )
{
    for(int i=0;i<10;i++)
        MAIN(argc,argv);
    return 0;
}

