// Copyright 2025 - Roberto De Ioris

#include "UncryptoolFunctionLibrary.h"

#define UI UI_ST
THIRD_PARTY_INCLUDES_START
#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "openssl/kdf.h"
THIRD_PARTY_INCLUDES_END
#undef UI

namespace Uncryptool
{
	bool HKDF(const EUncryptoolHash Hash, const FUncryptoolBytes& Salt, const FUncryptoolBytes& IKM, const FUncryptoolBytes& Info, TArray<uint8>& OutputBytes, FString& ErrorMessage)
	{
		const EVP_MD* HashAlgo = nullptr;
		switch (Hash)
		{
		case EUncryptoolHash::SHA256:
			HashAlgo = EVP_sha256();
			break;
		case EUncryptoolHash::SHA384:
			HashAlgo = EVP_sha384();
			break;
		case EUncryptoolHash::SHA512:
			HashAlgo = EVP_sha512();
			break;
		case EUncryptoolHash::SHA1:
			HashAlgo = EVP_sha1();
			break;
		case EUncryptoolHash::SHA224:
			HashAlgo = EVP_sha224();
			break;
		case EUncryptoolHash::RIPEMD160:
			HashAlgo = EVP_ripemd160();
			break;
		case EUncryptoolHash::BLAKE2b512:
			HashAlgo = EVP_blake2b512();
			break;
		case EUncryptoolHash::BLAKE2s256:
			HashAlgo = EVP_blake2s256();
			break;
		default:
			ErrorMessage = "Unsupported Hash Algorithm";
			return false;
		}

		EVP_PKEY_CTX* Context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
		if (!Context)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		if (EVP_PKEY_derive_init(Context) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_CTX_free(Context);
			return false;
		}

		if (EVP_PKEY_CTX_set_hkdf_md(Context, HashAlgo) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_CTX_free(Context);
			return false;
		}

		if (EVP_PKEY_CTX_set1_hkdf_salt(Context, Salt.GetData(), Salt.Num()) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_CTX_free(Context);
			return false;
		}

		if (EVP_PKEY_CTX_set1_hkdf_key(Context, IKM.GetData(), IKM.Num()) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_CTX_free(Context);
			return false;
		}

		if (EVP_PKEY_CTX_add1_hkdf_info(Context, Info.GetData(), Info.Num()) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_CTX_free(Context);
			return false;
		}

		SIZE_T KeyLen = EVP_MD_size(HashAlgo);
		OutputBytes.SetNum(KeyLen, EAllowShrinking::No);

		if (EVP_PKEY_derive(Context, OutputBytes.GetData(), &KeyLen) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_CTX_free(Context);
			return false;
		}

		EVP_PKEY_CTX_free(Context);
		return true;
	}

	bool PBEScrypt(const FUncryptoolBytes& Password, const FUncryptoolBytes& Salt, const uint64 N, const uint64 R, const uint64 P, const int32 KeyLen, TArray<uint8>& OutputBytes, FString& ErrorMessage)
	{
		if (KeyLen < 1)
		{
			ErrorMessage = "KeyLen must be > 0";
			return false;
		}

		OutputBytes.SetNum(KeyLen, EAllowShrinking::No);
		if (EVP_PBE_scrypt(Password.GetData<char>(), Password.Num(), Salt.GetData(), Salt.Num(), N, R, P, 0, OutputBytes.GetData(), KeyLen) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		return true;
	}

}