// Copyright 2025 - Roberto De Ioris

#include "UncryptoolFunctionLibrary.h"

#define UI UI_ST
THIRD_PARTY_INCLUDES_START
#include "openssl/evp.h"
#include "openssl/hmac.h"
THIRD_PARTY_INCLUDES_END
#undef UI

namespace Uncryptool
{
	bool PBKDF2HMAC(const FUncryptoolBytes& Password, const FUncryptoolBytes& Salt, const int32 Iterations, const EUncryptoolHash Hash, const int32 KeyLen, TArray<uint8>& OutputBytes, FString& ErrorMessage)
	{
		if (KeyLen < 1)
		{
			ErrorMessage = "KeyLen must be > 0";
			return false;
		}

		if (Iterations < 1)
		{
			ErrorMessage = "Iterations must be > 0";
			return false;
		}

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

		OutputBytes.SetNum(KeyLen, EAllowShrinking::No);

		if (PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(Password.GetData()), Password.Num(), Salt.GetData(), Salt.Num(), Iterations, HashAlgo, KeyLen, OutputBytes.GetData()) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		return true;
	}
}