#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

//#ifdef _cplusplus
//extern "C" {
//#endif
#include "/mnt/hgfs/linux_study/agent/include/openssl/aes.h"
#include "/mnt/hgfs/linux_study/agent/include/openssl/rand.h"
#include "/mnt/hgfs/linux_study/agent/include/openssl/des.h"
#include "/mnt/hgfs/linux_study/agent/include/openssl/md5.h"
#include "/mnt/hgfs/linux_study/agent/include/openssl/ossl_typ.h"
#include "/mnt/hgfs/linux_study/agent/include/openssl/evp.h"
#include "/mnt/hgfs/linux_study/agent/include/openssl/x509.h"


/*
#include "openssl/aes.h"
#include "openssl/rand.h"
#include "openssl/des.h"
#include "openssl/md5.h"
#include "openssl/ossl_typ.h"
#include "openssl/evp.h"
#include "openssl/x509.h"
*/

//#ifdef _cplusplus
//}
//#endif

typedef enum {
	GENERAL = 0,
	ECB,
	CBC,
	CFB,
	OFB,
	TRIPLE_ECB,
	TRIPLE_CBC
}CRYPTO_MODE;


bool MD5_CryptData(char* pszEncodeDataIn, int nEncodeInLen, char* pszEncodeOut);

bool AES_CryptData(unsigned char* pszInData, int nInLen, unsigned char* pszOutData, unsigned char* pszKey);
bool AES_DecryptData(unsigned char* pszInData, int nInLen, unsigned char* pszOutData, unsigned char* pszKey);

bool AES_CryptDataEVP(unsigned char* pszInEncode, int nEnCodeLen, unsigned char* pszKey, unsigned char* pszOutEncode, int* pnEnCodoedLen);
bool AES_DecryptDataEVP(unsigned char* pszInEncode, int nEnCodeLen, unsigned char* pszKey, unsigned char* pszOutDecode, int* pnDeCodedLen);

#endif
