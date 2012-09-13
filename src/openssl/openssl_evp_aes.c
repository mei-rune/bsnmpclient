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

#define NID_aes_128_ofb128		420
#define NID_aes_128_cfb128		421
#define NID_aes_128_ecb		418
#define NID_aes_128_cbc		419

#define NID_aes_192_ecb		422
#define NID_aes_192_cbc		423
#define NID_aes_192_ofb128		424
#define NID_aes_192_cfb128		425


#define NID_aes_256_ecb		426
#define NID_aes_256_cbc		427
#define NID_aes_256_ofb128		428
#define NID_aes_256_cfb128		429


#define NID_aes_128_cfb1		650
#define NID_aes_192_cfb1		651
#define NID_aes_256_cfb1		652
#define NID_aes_128_cfb8		653
#define NID_aes_192_cfb8		654
#define NID_aes_256_cfb8		655

static int aes_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc);

typedef struct {
    AES_KEY ks;
} EVP_AES_KEY;

#define data(ctx)	EVP_C_DATA(EVP_AES_KEY,ctx)

IMPLEMENT_BLOCK_CIPHER(aes_128, ks, AES, EVP_AES_KEY,
                       NID_aes_128, 16, 16, 16, 128,
                       EVP_CIPH_FLAG_FIPS|EVP_CIPH_FLAG_DEFAULT_ASN1,
                       aes_init_key,
                       NULL, NULL, NULL, NULL)
IMPLEMENT_BLOCK_CIPHER(aes_192, ks, AES, EVP_AES_KEY,
                       NID_aes_192, 16, 24, 16, 128,
                       EVP_CIPH_FLAG_FIPS|EVP_CIPH_FLAG_DEFAULT_ASN1,
                       aes_init_key,
                       NULL, NULL, NULL, NULL)
IMPLEMENT_BLOCK_CIPHER(aes_256, ks, AES, EVP_AES_KEY,
                       NID_aes_256, 16, 32, 16, 128,
                       EVP_CIPH_FLAG_FIPS|EVP_CIPH_FLAG_DEFAULT_ASN1,
                       aes_init_key,
                       NULL, NULL, NULL, NULL)

#define IMPLEMENT_AES_CFBR(ksize,cbits,flags)	IMPLEMENT_CFBR(aes,AES,EVP_AES_KEY,ks,ksize,cbits,16,flags)

IMPLEMENT_AES_CFBR(128,1,EVP_CIPH_FLAG_FIPS)
IMPLEMENT_AES_CFBR(192,1,EVP_CIPH_FLAG_FIPS)
IMPLEMENT_AES_CFBR(256,1,EVP_CIPH_FLAG_FIPS)

IMPLEMENT_AES_CFBR(128,8,EVP_CIPH_FLAG_FIPS)
IMPLEMENT_AES_CFBR(192,8,EVP_CIPH_FLAG_FIPS)
IMPLEMENT_AES_CFBR(256,8,EVP_CIPH_FLAG_FIPS)

static int aes_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc) {
    int ret;

    if ((ctx->cipher->flags & EVP_CIPH_MODE) == EVP_CIPH_CFB_MODE
            || (ctx->cipher->flags & EVP_CIPH_MODE) == EVP_CIPH_OFB_MODE
            || enc)
        ret=AES_set_encrypt_key(key, ctx->key_len * 8, (AES_KEY*)ctx->cipher_data);
    else
        ret=AES_set_decrypt_key(key, ctx->key_len * 8, (AES_KEY*)ctx->cipher_data);

    if(ret < 0) {
        EVPerr(EVP_F_AES_INIT_KEY,EVP_R_AES_KEY_SETUP_FAILED);
        return 0;
    }

    return 1;
}
