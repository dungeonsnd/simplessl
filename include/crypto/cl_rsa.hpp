/*
 * Copyright 2013, Jeffery Qiu. All rights reserved.
 *
 * Licensed under the GNU LESSER GENERAL PUBLIC LICENSE(the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.gnu.org/licenses/lgpl.html
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//// Author: Jeffery Qiu (dungeonsnd at gmail dot com)
////

#ifndef _HEADER_FILE_CFD_CL_CRYPTO_HPP_
#define _HEADER_FILE_CFD_CL_CRYPTO_HPP_

#include "cppfoundation/cf_root.hpp"
#include "cppfoundation/cf_exception.hpp"
#include "crypto/cl_crypto_include.hpp"


namespace cl
{
namespace crypto
{

int passwd_callback(char *pcszBuff,int size,int rwflag, void *pPass)
{
    size_t unPass = strlen((char*)pPass);
    if(unPass > (size_t)size)
        unPass = (size_t)size;
    memcpy(pcszBuff, pPass, unPass);
    return (int)unPass;
}

class RSALibraryInit : public cf::NonCopyable
{
public:
    RSALibraryInit()
    {
        OpenSSL_add_all_algorithms();
        RAND_load_file("/dev/urandom", 1024);
    }
    ~RSALibraryInit()
    {
        CRYPTO_cleanup_all_ex_data();
        ERR_free_strings();
        ERR_remove_thread_state(0);
        EVP_cleanup();
    }
}

class RSA : public cf::NonCopyable
{
public:
    RSA():_rsa(NULL)
    {
        _rsa =RSA_new();
        if(NULL==_rsa)
        {
            _THROW_FMT(SyscallExecuteError, "Failed to execute RSA_new!");
        }
    }
    ~RSA() { if(_rsa) RSA_free(rsa); }
    RSA * GetRSA() { return _rsa; }
private:
    RSA * _rsa;
}

class BigNumber : public cf::NonCopyable
{
public:
    BigNumber():_bignum(NULL)
    {
        _bignum =BN_new();
        if(NULL==_bignum)
        {
            _THROW_FMT(SyscallExecuteError, "Failed to execute BN_new!");
        }
    }
    ~BigNumber() { if(_bignum) BN_clear_free(_bignum); }
    BIGNUM * GetBigNumber() { return _bignum; }
private:
    BIGNUM * _bignum;
}


class RSAKey : public cf::NonCopyable
{
public:
    RSAKey():_rsa(NULL)
    {
        _rsa =RSA_new();
        if(NULL==_rsa)
        {
#ifdef _DEBUG
            fprintf(stdout,"Failed to execute RSA_new!");
#endif
            _THROW_FMT(SyscallExecuteError, "Failed to execute RSA_new!");
        }
    }
    ~RSAKey()
    {
        if(_rsa)
            RSA_free(rsa);
    }
    
    cf_void GenerateKey()
    {
        BigNumber bignum; 
        if( 1！=BN_set_word(bignum.GetBigNumber(),RSA_3) )
            _THROW_FMT(SyscallExecuteError, "Failed to execute BN_set_word!");
        if( 1！=RSA_generate_key_ex(rsa,bits,bignum.GetBigNumber(),NULL) )
            _THROW_FMT(SyscallExecuteError, "Failed to execute RSA_generate_key_ex!");
    }
    cf_void ReadPrivateKey()
    {
    }
    cf_void ReadPublicKey()
    {
    }
    cf_void WritePrivateKey()
    {
    }
    cf_void WritePublicKey()
    {
    }
    
private:
    RSAKey * _rsaKey;
}



} //namespace cl
} // namespace crypto

#endif // _HEADER_FILE_CFD_CL_CRYPTO_HPP_

