
#include <openssl/evp.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <string.h>

int base64_a()
{
	EVP_ENCODE_CTX	ectx,dctx;
	unsigned char	in[500],out[800],d[500];
	int		inl,outl,i,total,ret,total2;

	EVP_EncodeInit(&ectx);
	for(i=0;i<500;i++)
		memset(&in[i],i,1);
	inl=500;
	total=0;
	EVP_EncodeUpdate(&ectx,out,&outl,in,inl);
	total+=outl;
	EVP_EncodeFinal(&ectx,out+total,&outl);
	total+=outl;
	printf("%s\n",out);

	EVP_DecodeInit(&dctx);
	outl=500;
	total2=0;
	ret=EVP_DecodeUpdate(&dctx,d,&outl,out,total);
	if(ret<0)
	{
		printf("EVP_DecodeUpdate err!\n");
		return -1;
	}
	total2+=outl;
	ret=EVP_DecodeFinal(&dctx,d,&outl);
	total2+=outl;
	return 0;
}

int base64_b()
{
// 	unsigned char	in[500],out[800],d[500],*p;
// 	int				inl,i,len,pad;
// 
// 	for(i=0;i<500;i++)
// 		memset(&in[i],i,1);

	unsigned char out[800],d[500],*p;
	unsigned char in[] ="ab·Ç";
	printf("%s\n",in);
	int	 i,len,pad;
	int inl =strlen((char*)in);

// 	printf("please input how much(<500) to base64 : \n");
// 	scanf("%d",&inl);
	len=EVP_EncodeBlock(out,in,inl);
	printf("%s\n",out);
	p=out+len-1;
	pad=0;
	for(i=0;i<4;i++)
	{
		if(*p=='=')
			pad++;
		p--;
	}
	len=EVP_DecodeBlock(d,out,len);
	len-=pad;
	if((len!=inl) || (memcmp(in,d,len)))
		printf("err!\n");
	//printf("test ok.\n");
	return 0;
}

/**
* Use EVP to Base64 encode the input byte array to readable text
*/
char* base64(const unsigned char *inputBuffer, int inputLen)
{
	EVP_ENCODE_CTX	ctx;
	int base64Len = (((inputLen+2)/3)*4) + 1; // Base64 text length
	int pemLen = base64Len + base64Len/64; // PEM adds a newline every 64 bytes
	char* base64 = new char[pemLen];
	int result;
	EVP_EncodeInit(&ctx);
	EVP_EncodeUpdate(&ctx, (unsigned char *)base64, &result, (unsigned char *)inputBuffer, inputLen);
	EVP_EncodeFinal(&ctx, (unsigned char *)&base64[result], &result);
	return base64;
}

/**
* Use EVP to Base64 decode the input readable text to original bytes
*/
unsigned char* unbase64(char *input, int length, int* outLen)
{
	EVP_ENCODE_CTX	ctx;
	int orgLen = (((length+2)/4)*3) + 1;
	unsigned char* orgBuf = new unsigned char[orgLen];
	int result, tmpLen;
	EVP_DecodeInit(&ctx);
	EVP_DecodeUpdate(&ctx, (unsigned char *)orgBuf, &result, (unsigned char *)input, length);
	EVP_DecodeFinal(&ctx, (unsigned char *)&orgBuf[result], &tmpLen);
	result += tmpLen;
	*outLen = result;
	return orgBuf;
}

int base64test()
{
	unsigned char inputBuffer[] ="ab·Ç";
	int inputLen =strlen((char*)inputBuffer);
	char* b64 =base64(inputBuffer, inputLen);
	printf("%s",b64);

	int length =strlen(b64);
	int outLen;
	unsigned char* unb64 =unbase64(b64, length, &outLen);
	printf("%s\n",unb64);
	return 0;
}

int	hash_test()
{
    unsigned char	in[]="3dsferyewyrtetegvbzVEgarhaggavxcv";
    unsigned char	out[128] ={0};
    size_t			n;
    int				i;

    n=strlen((const char*)in);

    MD4(in,n,out);
    printf("\n\nMD4 digest result :\n");
    for(i=0;i<16;i++)
        printf("%x ",out[i]);

    MD5(in,n,out);
    printf("\n\nMD5 digest result :\n");
    for(i=0;i<16;i++)
        printf("%x ",out[i]);

    SHA(in,n,out);
    printf("\n\nSHA digest result :\n");
    for(i=0;i<20;i++)
        printf("%x ",out[i]);

    SHA1(in,n,out);
    printf("\n\nSHA1 digest result :\n");
    for(i=0;i<20;i++)
        printf("%x ",out[i]);

    SHA256(in,n,out);
    printf("\n\nSHA256 digest result :\n");
    for(i=0;i<32;i++)
        printf("%x ",out[i]);

    SHA512(in,n,out);
    printf("\n\nSHA512 digest result :\n");
    for(i=0;i<64;i++)
        printf("%x ",out[i]);
    printf("\n");
    return 0;
}


int	main()
{
	//base64_a(); //Note,error,but not a bug.
// 	base64_b();
// 	printf("\n");
// 	base64test();

    hash_test();

    char ch;
    printf("press anykey to exit...\n");
    scanf("%c",&ch);

	return 0;
}
