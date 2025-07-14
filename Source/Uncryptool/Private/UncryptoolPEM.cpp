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
		case EVP_PKEY_ED448:
			PrivateKey.Type = EUncryptoolKey::ED448;
			break;
		case EVP_PKEY_ED25519:
			PrivateKey.Type = EUncryptoolKey::ED25519;
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

	bool PEMToPublicKey(const FUncryptoolBytes& PEMBytes, FUncryptoolPublicKey& PublicKey, FString& ErrorMessage)
	{
		BIO* OpenSSLBio = BIO_new_mem_buf(PEMBytes.GetData(), PEMBytes.Num());
		if (!OpenSSLBio)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		EVP_PKEY* EVPPublicKey = PEM_read_bio_PUBKEY(OpenSSLBio, nullptr, nullptr, nullptr);
		if (!EVPPublicKey)
		{
			BIO_free(OpenSSLBio);
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		const int32 EVPPublicKeyType = EVP_PKEY_id(EVPPublicKey);
		switch (EVPPublicKeyType)
		{
		case EVP_PKEY_RSA:
			PublicKey.Type = EUncryptoolKey::RSA;
			break;
		case EVP_PKEY_DSA:
			PublicKey.Type = EUncryptoolKey::DSA;
			break;
		case EVP_PKEY_EC:
			PublicKey.Type = EUncryptoolKey::EC;
			break;
		case EVP_PKEY_ED448:
			PublicKey.Type = EUncryptoolKey::ED448;
			break;
		case EVP_PKEY_ED25519:
			PublicKey.Type = EUncryptoolKey::ED25519;
			break;
		default:
			ErrorMessage = "Unsupported Key type";
			EVP_PKEY_free(EVPPublicKey);
			BIO_free(OpenSSLBio);
			return false;
		}

		PublicKey.Bits = EVP_PKEY_bits(EVPPublicKey);

		int32 DerLen = i2d_PUBKEY(EVPPublicKey, nullptr);
		if (DerLen <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPublicKey);
			BIO_free(OpenSSLBio);
			return false;
		}

		PublicKey.DER.SetNum(DerLen, EAllowShrinking::No);

		uint8* PublicKeyDERPtr = PublicKey.DER.GetData();
		DerLen = i2d_PUBKEY(EVPPublicKey, &PublicKeyDERPtr);
		if (DerLen <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPublicKey);
			BIO_free(OpenSSLBio);
			return false;
		}

		EVP_PKEY_free(EVPPublicKey);
		BIO_free(OpenSSLBio);

		return true;
	}

	bool PEMToPrivateKey(const FString& PEMString, FUncryptoolPrivateKey& PrivateKey, FString& ErrorMessage)
	{
		TArray<uint8> PEMBytes = UTF8StringToBytes(PEMString);
		return PEMToPrivateKey(PEMBytes, PrivateKey, ErrorMessage);
	}

	bool PublicKeyMatchesPrivateKey(const FUncryptoolPublicKey& PublicKey, const FUncryptoolPrivateKey& PrivateKey, FString& ErrorMessage)
	{
		if (PublicKey.Type != PrivateKey.Type)
		{
			ErrorMessage = "Keys type does not match";
			return false;
		}

		if (PublicKey.Bits != PrivateKey.Bits)
		{
			ErrorMessage = "Keys bit size does not match";
			return false;
		}

		const uint8* PublicKeyDERPtr = PublicKey.DER.GetData();
		EVP_PKEY* EVPPublicKey = d2i_PUBKEY(nullptr, &PublicKeyDERPtr, PublicKey.DER.Num());
		if (!EVPPublicKey)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		const uint8* PrivateKeyDERPtr = PrivateKey.DER.GetData();
		EVP_PKEY* EVPPrivateKey = d2i_AutoPrivateKey(nullptr, &PrivateKeyDERPtr, PrivateKey.DER.Num());
		if (!EVPPrivateKey)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPublicKey);
			return false;
		}

		if (EVP_PKEY_cmp(EVPPublicKey, EVPPrivateKey) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPrivateKey);
			EVP_PKEY_free(EVPPublicKey);
			return false;
		}

		EVP_PKEY_free(EVPPrivateKey);
		EVP_PKEY_free(EVPPublicKey);

		return true;
	}

	bool PublicKeyFromPrivateKey(const FUncryptoolPrivateKey& PrivateKey, FUncryptoolPublicKey& PublicKey, FString& ErrorMessage)
	{
		const uint8* PrivateKeyDERPtr = PrivateKey.DER.GetData();
		EVP_PKEY* EVPPrivateKey = d2i_AutoPrivateKey(nullptr, &PrivateKeyDERPtr, PrivateKey.DER.Num());
		if (!EVPPrivateKey)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		int32 DerLen = i2d_PUBKEY(EVPPrivateKey, nullptr);
		if (DerLen <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPrivateKey);
			return false;
		}

		PublicKey.Type = PrivateKey.Type;
		PublicKey.Bits = PrivateKey.Bits;
		PublicKey.DER.SetNum(DerLen, EAllowShrinking::No);

		uint8* PublicKeyDERPtr = PublicKey.DER.GetData();
		DerLen = i2d_PUBKEY(EVPPrivateKey, &PublicKeyDERPtr);
		if (DerLen <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPrivateKey);
			return false;
		}

		EVP_PKEY_free(EVPPrivateKey);
		return true;
	}

	bool PublicKeyToPEM(const FUncryptoolPublicKey& PublicKey, TArray<uint8>& PEMBytes, FString& ErrorMessage)
	{
		const uint8* PublicKeyDERPtr = PublicKey.DER.GetData();
		EVP_PKEY* EVPPublicKey = d2i_PUBKEY(nullptr, &PublicKeyDERPtr, PublicKey.DER.Num());
		if (!EVPPublicKey)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		BIO* OpenSSLBio = BIO_new(BIO_s_mem());
		if (!OpenSSLBio)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPublicKey);
			return false;
		}

		if (PEM_write_bio_PUBKEY(OpenSSLBio, EVPPublicKey) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPublicKey);
			BIO_free(OpenSSLBio);
			return false;
		}

		char* PEMChars = nullptr;
		int64 PEMLen = BIO_get_mem_data(OpenSSLBio, &PEMChars);
		if (PEMLen <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPublicKey);
			BIO_free(OpenSSLBio);
			return false;
		}

		PEMBytes.Empty();
		PEMBytes.Append(reinterpret_cast<const uint8*>(PEMChars), PEMLen);

		EVP_PKEY_free(EVPPublicKey);
		BIO_free(OpenSSLBio);
		return true;
	}

	bool PublicKeyToPEM(const FUncryptoolPublicKey& PublicKey, FString& PEMString, FString& ErrorMessage)
	{
		TArray<uint8> PEMBytes;
		if (!PublicKeyToPEM(PublicKey, PEMBytes, ErrorMessage))
		{
			return false;
		}

		PEMString = BytesToUTF8String(PEMBytes);
		return true;
	}

	bool PublicKeyToRaw(const FUncryptoolPublicKey& PublicKey, TArray<uint8>& OutputBytes, FString& ErrorMessage)
	{
		const uint8* PublicKeyDERPtr = PublicKey.DER.GetData();
		EVP_PKEY* EVPPublicKey = d2i_PUBKEY(nullptr, &PublicKeyDERPtr, PublicKey.DER.Num());
		if (!EVPPublicKey)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		SIZE_T KeyLen = 0;
		if (EVP_PKEY_get_raw_public_key(EVPPublicKey, nullptr, &KeyLen) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPublicKey);
			return false;
		}

		OutputBytes.SetNum(KeyLen, EAllowShrinking::No);

		if (EVP_PKEY_get_raw_public_key(EVPPublicKey, OutputBytes.GetData(), &KeyLen) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPublicKey);
			return false;
		}

		EVP_PKEY_free(EVPPublicKey);

		return true;
	}
}