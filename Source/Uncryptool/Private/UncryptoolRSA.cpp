// Copyright 2025 - Roberto De Ioris

#include "UncryptoolFunctionLibrary.h"

#define UI UI_ST
THIRD_PARTY_INCLUDES_START
#include "openssl/rsa.h"
#include "openssl/evp.h"
#include "openssl/obj_mac.h"
#include "openssl/x509.h"
THIRD_PARTY_INCLUDES_END
#undef UI

namespace Uncryptool
{

	bool GenerateRSAKey(const int32 Bits, FUncryptoolPrivateKey& PrivateKey, FUncryptoolPublicKey& PublicKey, FString& ErrorMessage)
	{
		if (Bits < 512 && (Bits % 8) != 8)
		{
			ErrorMessage = "RSA bits must be at least 512 and dividible by 8";
			return false;
		}

		EVP_PKEY_CTX* Context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
		if (!Context)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		if (EVP_PKEY_keygen_init(Context) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_CTX_free(Context);
			return false;
		}

		if (EVP_PKEY_CTX_set_rsa_keygen_bits(Context, Bits) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_CTX_free(Context);
			return false;
		}

		EVP_PKEY* EVPPrivateKey = nullptr;

		// 4. Generate the RSA key
		if (EVP_PKEY_keygen(Context, &EVPPrivateKey) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_CTX_free(Context);
			return false;
		}

		int32 DerLen = i2d_PrivateKey(EVPPrivateKey, nullptr);
		if (DerLen <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPrivateKey);
			EVP_PKEY_CTX_free(Context);
			return false;
		}

		PrivateKey.Type = EUncryptoolKey::RSA;
		PrivateKey.Bits = Bits;
		PrivateKey.DER.SetNum(DerLen, EAllowShrinking::No);

		uint8* DERPtr = PrivateKey.DER.GetData();
		DerLen = i2d_PrivateKey(EVPPrivateKey, &DERPtr);
		if (DerLen <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPrivateKey);
			EVP_PKEY_CTX_free(Context);
			return false;
		}

		DerLen = i2d_PUBKEY(EVPPrivateKey, nullptr);
		if (DerLen <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPrivateKey);
			EVP_PKEY_CTX_free(Context);
			return false;
		}

		PublicKey.Type = EUncryptoolKey::RSA;
		PublicKey.Bits = Bits;
		PublicKey.DER.SetNum(DerLen, EAllowShrinking::No);

		DERPtr = PublicKey.DER.GetData();
		DerLen = i2d_PUBKEY(EVPPrivateKey, &DERPtr);
		if (DerLen <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPrivateKey);
			EVP_PKEY_CTX_free(Context);
			return false;
		}

		EVP_PKEY_free(EVPPrivateKey);
		EVP_PKEY_CTX_free(Context);

		return true;
	}

	bool RSADigestSign(const FUncryptoolPrivateKey& PrivateKey, const FUncryptoolBytes& InputBytes, const EUncryptoolHash Hash, TArray<uint8>& OutputSignature, FString& ErrorMessage)
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
		default:
			ErrorMessage = "Unsupported Hash Algorithm";
			return false;
		}

		const uint8* DERPtr = PrivateKey.DER.GetData();

		EVP_PKEY* EVPPrivateKey = d2i_AutoPrivateKey(nullptr, &DERPtr, PrivateKey.DER.Num());
		if (!EVPPrivateKey)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		EVP_MD_CTX* Context = EVP_MD_CTX_new();
		if (!Context)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPrivateKey);
			return false;
		}

		if (EVP_DigestSignInit(Context, nullptr, HashAlgo, nullptr, EVPPrivateKey) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_MD_CTX_free(Context);
			EVP_PKEY_free(EVPPrivateKey);
			return false;
		}

		if (EVP_DigestSignUpdate(Context, InputBytes.GetData(), InputBytes.Num()) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_MD_CTX_free(Context);
			EVP_PKEY_free(EVPPrivateKey);
			return false;
		}

		SIZE_T SignatureLen = 0;
		if (EVP_DigestSignFinal(Context, nullptr, &SignatureLen) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_MD_CTX_free(Context);
			EVP_PKEY_free(EVPPrivateKey);
			return false;
		}

		OutputSignature.SetNum(SignatureLen, EAllowShrinking::No);

		if (EVP_DigestSignFinal(Context, OutputSignature.GetData(), &SignatureLen) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_MD_CTX_free(Context);
			EVP_PKEY_free(EVPPrivateKey);
			return false;
		}

		// the first call to EVP_DigestSignFinal returned the max size of a signature (not the actual size)
		OutputSignature.SetNum(SignatureLen, EAllowShrinking::No);

		EVP_MD_CTX_free(Context);
		EVP_PKEY_free(EVPPrivateKey);

		return true;
	}

	bool RSADigestVerify(const FUncryptoolPublicKey& PublicKey, const FUncryptoolBytes& InputBytes, const EUncryptoolHash Hash, const FUncryptoolBytes& SignatureBytes, FString& ErrorMessage)
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
		default:
			ErrorMessage = "Unsupported Hash Algorithm";
			return false;
		}

		const uint8* DERPtr = PublicKey.DER.GetData();

		EVP_PKEY* EVPPublicKey = d2i_PUBKEY(nullptr, &DERPtr, PublicKey.DER.Num());
		if (!EVPPublicKey)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		EVP_MD_CTX* Context = EVP_MD_CTX_new();
		if (!Context)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPublicKey);
			return false;
		}

		EVP_PKEY_CTX* PKeyContext = nullptr;

		if (EVP_DigestVerifyInit(Context, nullptr, HashAlgo, nullptr, EVPPublicKey) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_MD_CTX_free(Context);
			EVP_PKEY_free(EVPPublicKey);
			return false;
		}

		if (EVP_DigestVerifyUpdate(Context, InputBytes.GetData(), InputBytes.Num()) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_MD_CTX_free(Context);
			EVP_PKEY_free(EVPPublicKey);
			return false;
		}

		if (EVP_DigestVerifyFinal(Context, SignatureBytes.GetData(), SignatureBytes.Num()) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_MD_CTX_free(Context);
			EVP_PKEY_free(EVPPublicKey);
			return false;
		}

		EVP_MD_CTX_free(Context);
		EVP_PKEY_free(EVPPublicKey);

		return true;
	}

	bool RSAEncrypt(const FUncryptoolPublicKey& PublicKey, const FUncryptoolBytes& InputBytes, TArray<uint8>& OutputBytes, FString& ErrorMessage)
	{
		const uint8* DERPtr = PublicKey.DER.GetData();

		EVP_PKEY* EVPPublicKey = d2i_PUBKEY(nullptr, &DERPtr, PublicKey.DER.Num());
		if (!EVPPublicKey)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		EVP_PKEY_CTX* Context = EVP_PKEY_CTX_new(EVPPublicKey, nullptr);
		if (!Context)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPublicKey);
			return false;
		}

		if (EVP_PKEY_encrypt_init(Context) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_CTX_free(Context);
			EVP_PKEY_free(EVPPublicKey);
			return false;
		}

		SIZE_T EncryptedLen = 0;
		if (EVP_PKEY_encrypt(Context, nullptr, &EncryptedLen, InputBytes.GetData(), InputBytes.Num()) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_CTX_free(Context);
			EVP_PKEY_free(EVPPublicKey);
			return false;
		}

		OutputBytes.SetNum(EncryptedLen, EAllowShrinking::No);

		if (EVP_PKEY_encrypt(Context, OutputBytes.GetData(), &EncryptedLen, InputBytes.GetData(), InputBytes.Num()) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_CTX_free(Context);
			EVP_PKEY_free(EVPPublicKey);
			return false;
		}

		OutputBytes.SetNum(EncryptedLen, EAllowShrinking::No);

		EVP_PKEY_CTX_free(Context);
		EVP_PKEY_free(EVPPublicKey);

		return true;
	}

	bool RSADecrypt(const FUncryptoolPrivateKey& PrivateKey, const FUncryptoolBytes& InputBytes, TArray<uint8>& OutputBytes, FString& ErrorMessage)
	{
		const uint8* DERPtr = PrivateKey.DER.GetData();

		EVP_PKEY* EVPPrivateKey = d2i_AutoPrivateKey(nullptr, &DERPtr, PrivateKey.DER.Num());
		if (!EVPPrivateKey)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		EVP_PKEY_CTX* Context = EVP_PKEY_CTX_new(EVPPrivateKey, nullptr);
		if (!Context)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPrivateKey);
			return false;
		}

		if (EVP_PKEY_decrypt_init(Context) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_CTX_free(Context);
			EVP_PKEY_free(EVPPrivateKey);
			return false;
		}

		SIZE_T DecryptedLen = 0;
		if (EVP_PKEY_decrypt(Context, nullptr, &DecryptedLen, InputBytes.GetData(), InputBytes.Num()) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_CTX_free(Context);
			EVP_PKEY_free(EVPPrivateKey);
			return false;
		}

		OutputBytes.SetNum(DecryptedLen, EAllowShrinking::No);

		if (EVP_PKEY_decrypt(Context, OutputBytes.GetData(), &DecryptedLen, InputBytes.GetData(), InputBytes.Num()) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_CTX_free(Context);
			EVP_PKEY_free(EVPPrivateKey);
			return false;
		}

		OutputBytes.SetNum(DecryptedLen, EAllowShrinking::No);

		EVP_PKEY_CTX_free(Context);
		EVP_PKEY_free(EVPPrivateKey);

		return true;
	}

	bool RSAPublicKeyFromModulusAndExponent(const FUncryptoolBigNum& Modulus, const FUncryptoolBigNum& Exponent, FUncryptoolPublicKey& PublicKey, FString& ErrorMessage)
	{
		RSA* RSAPtr = RSA_new();
		if (!RSAPtr)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		if (!RSA_set0_key(RSAPtr, reinterpret_cast<BIGNUM*>(Modulus.GetNativeBigNum()), reinterpret_cast<BIGNUM*>(Exponent.GetNativeBigNum()), nullptr))
		{
			ErrorMessage = GetOpenSSLError();
			RSA_free(RSAPtr);
			return false;
		}

		EVP_PKEY* EVPPrivateKey = EVP_PKEY_new();
		if (!EVPPrivateKey)
		{
			ErrorMessage = GetOpenSSLError();
			RSA_free(RSAPtr);
			return false;
		}

		// this transfers ownership of RSAPtr!
		if (EVP_PKEY_assign_RSA(EVPPrivateKey, RSAPtr) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			RSA_free(RSAPtr);
			EVP_PKEY_free(EVPPrivateKey);
			return false;
		}

		int32 DerLen = i2d_PUBKEY(EVPPrivateKey, nullptr);
		if (DerLen <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPrivateKey);
			return false;
		}

		PublicKey.DER.SetNum(DerLen, EAllowShrinking::No);

		uint8* DERPtr = PublicKey.DER.GetData();
		DerLen = i2d_PUBKEY(EVPPrivateKey, &DERPtr);
		if (DerLen <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPrivateKey);
			return false;
		}

		EVP_PKEY_free(EVPPrivateKey);
		return true;
	}
}