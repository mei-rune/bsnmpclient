/* crypto/evp/m_md5.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
* All rights reserved.
*
* This package is an SSL implementation written
* by Eric Young (eay@cryptsoft.com).
* The implementation was written so as to conform with Netscapes SSL.
* 
* This library is free for commercial and non-commercial use as long as
* the following conditions are aheared to.  The following conditions
* apply to all code found in this distribution, be it the RC4, RSA,
* lhash, DES, etc., code; not just the SSL code.  The SSL documentation
* included with this distribution is covered by the same copyright terms
* except that the holder is Tim Hudson (tjh@cryptsoft.com).
* 
* Copyright remains Eric Young's, and as such any Copyright notices in
* the code are not to be removed.
* If this package is used in a product, Eric Young should be given attribution
* as the author of the parts of the library used.
* This can be in the form of a textual message at program startup or
* in documentation (online or textual) provided with the package.
* 
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
* 3. All advertising materials mentioning features or use of this software
*    must display the following acknowledgement:
*    "This product includes cryptographic software written by
*     Eric Young (eay@cryptsoft.com)"
*    The word 'cryptographic' can be left out if the rouines from the library
*    being used are not cryptographic related :-).
* 4. If you include any Windows specific code (or a derivative thereof) from 
*    the apps directory (application code) you must include an acknowledgement:
*    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
* 
* THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
* 
* The licence and distribution terms for any publically available version or
* derivative of this code cannot be changed.  i.e. this code cannot simply be
* copied and put under another distribution licence
* [including the GNU Public Licence.]
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "compat/openssl_evp.h"
#include "openssl_evp_local.h"


#define NID_des_ecb		29
#define NID_des_cbc		31
#define NID_des_cfb64		30
#define NID_des_ofb64		45
#define NID_des_cfb1		656
#define NID_des_cfb8		657

static int des_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
    const unsigned char *iv, int enc);
static int des_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr);

/* Because of various casts and different names can't use IMPLEMENT_BLOCK_CIPHER */

static int des_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
    const unsigned char *in, unsigned int inl)
{
    BLOCK_CIPHER_ecb_loop()
        DES_ecb_encrypt((DES_cblock *)(in + i), (DES_cblock *)(out + i), ctx->cipher_data, ctx->encrypt);
    return 1;
}

static int des_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
    const unsigned char *in, unsigned int inl)
{
    DES_ofb64_encrypt(in, out, (long)inl, ctx->cipher_data, (DES_cblock *)ctx->iv, &ctx->num);
    return 1;
}

static int des_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
    const unsigned char *in, unsigned int inl)
{
    DES_ncbc_encrypt(in, out, (long)inl, ctx->cipher_data,
        (DES_cblock *)ctx->iv, ctx->encrypt);
    return 1;
}

static int des_cfb64_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
    const unsigned char *in, unsigned int inl)
{
    DES_cfb64_encrypt(in, out, (long)inl, ctx->cipher_data,
        (DES_cblock *)ctx->iv, &ctx->num, ctx->encrypt);
    return 1;
}

/* Although we have a CFB-r implementation for DES, it doesn't pack the right
way, so wrap it here */
//static int des_cfb1_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
//    const unsigned char *in, unsigned int inl)
//{
//    unsigned int n;
//    unsigned char c[1],d[1];
//
//    for(n=0 ; n < inl ; ++n)
//    {
//        c[0]=(in[n/8]&(1 << (7-n%8))) ? 0x80 : 0;
//        DES_cfb_encrypt(c,d,1,1,ctx->cipher_data,(DES_cblock *)ctx->iv,
//            ctx->encrypt);
//        out[n/8]=(out[n/8]&~(0x80 >> (n%8)))|((d[0]&0x80) >> (n%8));
//    }
//    return 1;
//}
//
//static int des_cfb8_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
//    const unsigned char *in, unsigned int inl)
//{
//    DES_cfb_encrypt(in,out,8,inl,ctx->cipher_data,(DES_cblock *)ctx->iv,
//        ctx->encrypt);
//    return 1;
//}

int EVP_CIPHER_get_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
{
    return -1;
    //int i=0;
    //unsigned int l;

    //if (type != NULL) 
    //	{
    //	l=EVP_CIPHER_CTX_iv_length(c);
    //	assert(l <= sizeof(c->iv));
    //	i=ASN1_TYPE_get_octetstring(type,c->oiv,l);
    //	if (i != (int)l)
    //		return(-1);
    //	else if (i > 0)
    //		memcpy(c->iv,c->oiv,l);
    //	}
    //return(i);
}

int EVP_CIPHER_set_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
{
    return -1;
    //int i=0;
    //unsigned int j;

    //if (type != NULL)
    //	{
    //	j=EVP_CIPHER_CTX_iv_length(c);
    //	assert(j <= sizeof(c->iv));
    //	i=ASN1_TYPE_set_octetstring(type,c->oiv,j);
    //	}
    //return(i);
}

BLOCK_CIPHER_defs(des, DES_key_schedule, NID_des, 8, 8, 8, 64,
    EVP_CIPH_RAND_KEY,
    des_init_key, NULL,
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    des_ctrl);


static int des_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
    const unsigned char *iv, int enc)
{
    DES_cblock *deskey = (DES_cblock *)key;
#ifdef EVP_CHECK_DES_KEY
    if(DES_set_key_checked(deskey,(DES_key_schedule *)ctx->cipher_data) != 0)
        return 0;
#else
    DES_set_key_unchecked(deskey, (DES_key_schedule *)ctx->cipher_data);
#endif
    return 1;
}

static int des_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{

    switch(type)
    {
    case EVP_CTRL_RAND_KEY:
        if (ssleay_rand_bytes((unsigned char*)ptr, 8) <= 0)
            return 0;
        DES_set_odd_parity((DES_cblock *)ptr);
        return 1;

    default:
        return -1;
    }
}
