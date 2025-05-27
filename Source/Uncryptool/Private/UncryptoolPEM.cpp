// Copyright 2025 - Roberto De Ioris

#include "UncryptoolFunctionLibrary.h"

#define UI UI_ST
THIRD_PARTY_INCLUDES_START
#include "openssl/bio.h"
#include "openssl/pem.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "openssl/ripemd.h"
THIRD_PARTY_INCLUDES_END
#undef UI

namespace Uncryptool
{
	bool PEMToPrivateKey(const FUncryptoolBytes& PEMBytes, FUncryptoolPrivateKey& PrivateKey, FString& ErrorMessage)
	{
		BIO* OpenSSLBio = BIO_new_mem_buf(PEMBytes.GetData(), PEMBytes.Num());
		if (!OpenSSLBio)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		EVP_PKEY* EVPPrivateKey = PEM_read_bio_PrivateKey(OpenSSLBio, nullptr, nullptr, nullptr);
		if (!EVPPrivateKey)
		{
			BIO_free(OpenSSLBio);
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		const int32 EVPPrivateKeyType = EVP_PKEY_id(EVPPrivateKey);
		switch (EVPPrivateKeyType)
		{
		case EVP_PKEY_RSA:
			PrivateKey.Type = EUncryptoolKey::RSA;
			break;
		case EVP_PKEY_DSA:
			PrivateKey.Type = EUncryptoolKey::DSA;
			break;
		case EVP_PKEY_EC:
			PrivateKey.Type = EUncryptoolKey::EC;
			break;
		default:
			ErrorMessage = "Unsupported Key type";
			EVP_PKEY_free(EVPPrivateKey);
			BIO_free(OpenSSLBio);
			return false;
		}

		PrivateKey.Bits = EVP_PKEY_bits(EVPPrivateKey);

		int32 DerLen = i2d_PrivateKey(EVPPrivateKey, nullptr);
		if (DerLen <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPrivateKey);
			BIO_free(OpenSSLBio);
			return false;
		}

		PrivateKey.DER.SetNum(DerLen, EAllowShrinking::No);

		uint8* DERPtr = PrivateKey.DER.GetData();
		DerLen = i2d_PrivateKey(EVPPrivateKey, &DERPtr);
		if (DerLen <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPrivateKey);
			BIO_free(OpenSSLBio);
			return false;
		}

		EVP_PKEY_free(EVPPrivateKey);
		BIO_free(OpenSSLBio);

		return true;
	}

	bool PEMToPrivateKey(const FString& PEMString, FUncryptoolPrivateKey& PrivateKey, FString& ErrorMessage)
	{
		TArray<uint8> PEMBytes = UTF8StringToBytes(PEMString);
		return PEMToPrivateKey(PEMBytes, PrivateKey, ErrorMessage);
	}
}