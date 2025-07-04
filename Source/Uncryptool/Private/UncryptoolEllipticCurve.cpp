// Copyright 2025 - Roberto De Ioris

#include "UncryptoolFunctionLibrary.h"

#define UI UI_ST
THIRD_PARTY_INCLUDES_START
#include "openssl/ec.h"
#include "openssl/evp.h"
#include "openssl/obj_mac.h"
#include "openssl/x509.h"
THIRD_PARTY_INCLUDES_END
#undef UI

namespace Uncryptool
{

	bool GenerateECKey(const EUncryptoolEllipticCurve EllipticCurve, FUncryptoolPrivateKey& PrivateKey, FUncryptoolPublicKey& PublicKey, FString& ErrorMessage)
	{
		int32 Nid = -1;
		switch (EllipticCurve)
		{
		case EUncryptoolEllipticCurve::PRIME256V1:
			Nid = NID_X9_62_prime256v1;
			break;
		case EUncryptoolEllipticCurve::SECP256K1:
			Nid = NID_secp256k1;
			break;
		case EUncryptoolEllipticCurve::SECP384R1:
			Nid = NID_secp384r1;
			break;
		case EUncryptoolEllipticCurve::SECP521R1:
			Nid = NID_secp521r1;
			break;
		default:
			ErrorMessage = "Unknown Elliptic Curve";
			return false;
		}

		EC_KEY* ECKey = EC_KEY_new_by_curve_name(Nid);
		if (!ECKey)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		if (EC_KEY_generate_key(ECKey) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EC_KEY_free(ECKey);
			return false;
		}

		PrivateKey.Type = EUncryptoolKey::EC;
		PublicKey.Type = EUncryptoolKey::EC;

		const EC_GROUP* ECGroup = EC_KEY_get0_group(ECKey);
		if (!ECGroup)
		{
			ErrorMessage = GetOpenSSLError();
			EC_KEY_free(ECKey);
			return false;
		}

		BIGNUM* CurveOrderBigNum = BN_new();
		if (!CurveOrderBigNum)
		{
			ErrorMessage = GetOpenSSLError();
			EC_KEY_free(ECKey);
			return false;
		}

		if (!EC_GROUP_get_order(ECGroup, CurveOrderBigNum, nullptr))
		{
			ErrorMessage = GetOpenSSLError();
			BN_free(CurveOrderBigNum);
			EC_KEY_free(ECKey);
			return 0;
		}

		PrivateKey.Bits = BN_num_bits(CurveOrderBigNum);
		PublicKey.Bits = PrivateKey.Bits;

		BN_free(CurveOrderBigNum);

		int32 DerLen = i2d_ECPrivateKey(ECKey, nullptr);
		if (DerLen <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EC_KEY_free(ECKey);
			return false;
		}

		PrivateKey.DER.SetNum(DerLen, EAllowShrinking::No);

		uint8* DERPtr = PrivateKey.DER.GetData();

		DerLen = i2d_ECPrivateKey(ECKey, &DERPtr);
		if (DerLen <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EC_KEY_free(ECKey);
			return false;
		}

		EVP_PKEY* EVPPrivateKey = EVP_PKEY_new();
		if (!EVPPrivateKey)
		{
			ErrorMessage = GetOpenSSLError();
			EC_KEY_free(ECKey);
			return false;
		}

		// this transfers ownership of ECKey!
		if (EVP_PKEY_assign_EC_KEY(EVPPrivateKey, ECKey) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EC_KEY_free(ECKey);
			return false;
		}

		DerLen = i2d_PUBKEY(EVPPrivateKey, nullptr);
		if (DerLen <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPrivateKey);
			return false;
		}

		PublicKey.DER.SetNum(DerLen, EAllowShrinking::No);

		DERPtr = PublicKey.DER.GetData();
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

	bool ECDSADigestSign(const FUncryptoolPrivateKey& PrivateKey, const FUncryptoolBytes& InputBytes, const EUncryptoolHash Hash, TArray<uint8>& OutputSignature, FString& ErrorMessage)
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
		default:
			ErrorMessage = "Unsupported Hash Algorithm";
			return false;
		}

		const uint8* DERPtr = PrivateKey.DER.GetData();

		EC_KEY* ECKey = d2i_ECPrivateKey(nullptr, &DERPtr, PrivateKey.DER.Num());
		if (!ECKey)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		EVP_PKEY* EVPPrivateKey = EVP_PKEY_new();
		if (!EVPPrivateKey)
		{
			ErrorMessage = GetOpenSSLError();
			EC_KEY_free(ECKey);
			return false;
		}

		// this transfers ownership of ECKey!
		if (EVP_PKEY_assign_EC_KEY(EVPPrivateKey, ECKey) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPrivateKey);
			EC_KEY_free(ECKey);
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

	bool ECDSADigestVerify(const FUncryptoolPublicKey& PublicKey, const FUncryptoolBytes& InputBytes, const EUncryptoolHash Hash, const FUncryptoolBytes& SignatureBytes, FString& ErrorMessage)
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
}