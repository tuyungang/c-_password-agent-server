#include "cryptdatafunc.h"
#include <string.h>

bool AES_CryptDataEVP(unsigned char* pszEncode, int nEnCodeLen, unsigned char* pszKey, unsigned char* pszOutEncode, int* pnEnCodoedLen)
{
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);

	int nRetCode = EVP_EncryptInit_ex(&ctx, EVP_aes_128_ecb(), NULL, pszKey, NULL);
	if (nRetCode != 1)
		return false;

	unsigned char* pResult = (unsigned char*)malloc(sizeof(unsigned char) * (nEnCodeLen + 64)); // 弄个足够大的空间
	if (pResult == NULL)
		return false;

	int nLenResult = 0;
	nRetCode = EVP_EncryptUpdate(&ctx, pResult, &nLenResult, pszEncode, nEnCodeLen);
	if (nRetCode != 1)
	{
		if (pResult)
		{
			free(pResult);
			pResult = NULL;
		}
		return false;
	}

	int nFinalLen = 0;
	nRetCode = EVP_EncryptFinal_ex(&ctx, pResult + nLenResult, &nFinalLen);
	if (nRetCode != 1)
	{
		if (pResult)
		{
			free(pResult);
			pResult = NULL;
		}
		return false;
	}

	nRetCode = EVP_CIPHER_CTX_cleanup(&ctx);
	if (nRetCode != 1)
	{
		if (pResult)
		{
			free(pResult);
			pResult = NULL;
		}
		return false;
	}
	
	int nEnCodoedLen = nLenResult + nFinalLen;
	memcpy(pszOutEncode, pResult, nEnCodoedLen);
	*pnEnCodoedLen = nEnCodoedLen;	

	if (pResult)
	{
		free(pResult);
		pResult = NULL;
	}
	return true;
}

bool AES_DecryptDataEVP(unsigned char* pszInEncode, int nEnCodeLen, unsigned char* pszKey, unsigned char* pszOutDecode, int* pnDeCodedLen)
{
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	int nRetCode = EVP_DecryptInit_ex(&ctx, EVP_aes_128_ecb(), NULL, pszKey, NULL);
	if (nRetCode != 1)
		return false;

	unsigned char* pResult = (unsigned char*)malloc(sizeof(unsigned char) * (nEnCodeLen + 64)); // 弄个足够大的空间
	if (pResult == NULL)
		return false;

	int nLenUpdate = 0;
	nRetCode = EVP_DecryptUpdate(&ctx, pResult, &nLenUpdate, pszInEncode, nEnCodeLen);
	if (nRetCode != 1)
	{
		free(pResult);
		pResult = NULL;
		return false;
	}

	int nFinalLen = 0;
	nRetCode = EVP_DecryptFinal_ex(&ctx, pResult + nLenUpdate, &nFinalLen);
	if (nRetCode != 1)
	{
		free(pResult);
		pResult = NULL;
		return false;
	}

	nRetCode = EVP_CIPHER_CTX_cleanup(&ctx);
	if (nRetCode != 1)
	{
		free(pResult);
		pResult = NULL;
		return false;
	}

	int nDeCodedLen = nLenUpdate + nFinalLen;
	memcpy(pszOutDecode, pResult, nDeCodedLen);
	*pnDeCodedLen = nDeCodedLen;

	free(pResult);
	pResult = NULL;
	return true;
}

bool AES_CryptData(unsigned char* pszInData, int nInLen, unsigned char* pszOutData, unsigned char* pszKey)
{
	//try
	{
		unsigned char iv_enc[16] = { 0x01, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 };
		unsigned char enc_out[32] = { 0 };
		AES_KEY enc_key;
		AES_set_encrypt_key(pszKey, 128, &enc_key);
		AES_cbc_encrypt(pszInData, enc_out, 32, &enc_key, iv_enc, AES_ENCRYPT);
		memcpy(pszOutData, enc_out, 32);
	}
	/*catch (...)
	{
		return false;
	}*/
	return true;
}

bool AES_DecryptData(unsigned char* pszInData, int nInLen, unsigned char* pszOutData, unsigned char* pszKey)
{
	//try
	{
		unsigned char iv_dec[16] = { 0x01, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 };
		unsigned char dec_out[32] = { 0 };
		AES_KEY dec_key;
		AES_set_decrypt_key(pszKey, 128, &dec_key);
		AES_cbc_encrypt(pszInData, dec_out, 32, &dec_key, iv_dec, AES_DECRYPT);
		memcpy(pszOutData, dec_out, 32);
	}
	/*catch (...)
	{
		return false;
	}*/
	return true;
}


bool MD5_CryptData(char* pszEncodeDataIn, int nEncodeInLen, char* pszEncodeOut)
{
	unsigned char md[16]; 
	MD5_CTX ctx;
	MD5_Init(&ctx); 
	MD5_Update(&ctx, pszEncodeDataIn, nEncodeInLen); 
	MD5_Final(md, &ctx);
	char szTemp[3] = {0}, szEncodeData[33] = {0};
	int i = 0;
	for (i = 0; i < 16; i++)
	{
		sprintf(szTemp, "%02X", md[i]);
		memcpy(szEncodeData + i * 2, szTemp, 2);
	}
	memcpy(pszEncodeOut, szEncodeData, 32);
	return true;
}
