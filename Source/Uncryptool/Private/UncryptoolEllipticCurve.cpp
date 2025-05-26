// Copyright 2025 - Roberto De Ioris

#include "Uncryptool.h"
#include "UncryptoolFunctionLibrary.h"

#define UI UI_ST
THIRD_PARTY_INCLUDES_START
#include "openssl/ec.h"
#include "openssl/evp.h"
#include "openssl/obj_mac.h"
THIRD_PARTY_INCLUDES_END
#undef UI

namespace Uncryptool
{

	bool GenerateECKey(const EUncryptoolEllipticCurve EllipticCurve, TArray<uint8>& PrivateKey, TArray<uint8>& PublicKey, FString& ErrorMessage)
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

		const BIGNUM* PrivateKeyBigNum = EC_KEY_get0_private_key(ECKey);
		if (!PrivateKeyBigNum)
		{
			ErrorMessage = GetOpenSSLError();
			EC_KEY_free(ECKey);
			return false;
		}

		const int32 NumBytes = BN_num_bytes(PrivateKeyBigNum);
		PrivateKey.SetNum(NumBytes, EAllowShrinking::No);

		BN_bn2bin(PrivateKeyBigNum, PrivateKey.GetData());

		const EC_POINT* PublicKeyPoint = EC_KEY_get0_public_key(ECKey);
		if (!PublicKeyPoint)
		{
			PrivateKey.Empty();
			ErrorMessage = GetOpenSSLError();
			EC_KEY_free(ECKey);
			return false;
		}

		const EC_GROUP* PublicKeyGroup = EC_KEY_get0_group(ECKey);
		if (!PublicKeyGroup)
		{
			PrivateKey.Empty();
			ErrorMessage = GetOpenSSLError();
			EC_KEY_free(ECKey);
			return false;
		}

		const int32 Bits = EC_GROUP_get_degree(PublicKeyGroup);
		const int32 PrivateKeyExpectedLen = (Bits + 7) / 8;

		const int32 Delta = PrivateKeyExpectedLen - PrivateKey.Num();
		if (Delta > 0)
		{
			PrivateKey.InsertZeroed(0, Delta);
		}

		const SIZE_T PublicKeyNumBytes = EC_POINT_point2oct(PublicKeyGroup, PublicKeyPoint, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
		PublicKey.SetNum(PublicKeyNumBytes, EAllowShrinking::No);

		EC_POINT_point2oct(PublicKeyGroup, PublicKeyPoint, POINT_CONVERSION_UNCOMPRESSED, PublicKey.GetData(), PublicKeyNumBytes, nullptr);

		EC_KEY_free(ECKey);
		return true;
	}

	bool ECDSADigestSign(const EUncryptoolEllipticCurve EllipticCurve, const FUncryptoolBytes& PrivateKey, const FUncryptoolBytes& InputBytes, const EUncryptoolHash Hash, TArray<uint8>& OutputSignature, FString& ErrorMessage)
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

		const EVP_MD* HashAlgo = nullptr;
		switch (Hash)
		{
		case EUncryptoolHash::SHA256:
			HashAlgo = EVP_sha256();
			break;
		case EUncryptoolHash::SHA512:
			HashAlgo = EVP_sha512();
			break;
		case EUncryptoolHash::RIPEMD160:
			HashAlgo = EVP_ripemd160();
			break;
		default:
			ErrorMessage = "Unknown Hash Algorithm";
			return false;
		}

		EC_KEY* ECKey = EC_KEY_new_by_curve_name(Nid);
		if (!ECKey)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		BIGNUM* PrivateKeyBigNum = BN_bin2bn(PrivateKey.GetData(), PrivateKey.Num(), nullptr);
		if (!PrivateKeyBigNum)
		{
			ErrorMessage = GetOpenSSLError();
			EC_KEY_free(ECKey);
			return false;
		}

		if (EC_KEY_set_private_key(ECKey, PrivateKeyBigNum) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EC_KEY_free(ECKey);
			BN_free(PrivateKeyBigNum);
			return false;
		}

		EVP_PKEY* EVPPrivateKey = EVP_PKEY_new();
		if (!EVPPrivateKey)
		{
			ErrorMessage = GetOpenSSLError();
			EC_KEY_free(ECKey);
			BN_free(PrivateKeyBigNum);
			return false;
		}

		if (EVP_PKEY_assign_EC_KEY(EVPPrivateKey, ECKey) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EC_KEY_free(ECKey);
			BN_free(PrivateKeyBigNum);
			return false;
		}

		EVP_MD_CTX* Context = EVP_MD_CTX_new();
		if (!Context)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPrivateKey);
			EC_KEY_free(ECKey);
			BN_free(PrivateKeyBigNum);
			EVP_PKEY_free(EVPPrivateKey);
			return false;
		}


		if (EVP_DigestSignInit(Context, nullptr, HashAlgo, nullptr, EVPPrivateKey) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_MD_CTX_free(Context);
			EVP_PKEY_free(EVPPrivateKey);
			EC_KEY_free(ECKey);
			BN_free(PrivateKeyBigNum);
			return false;
		}

		if (EVP_DigestSignUpdate(Context, InputBytes.GetData(), InputBytes.Num()) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_MD_CTX_free(Context);
			EVP_PKEY_free(EVPPrivateKey);
			EC_KEY_free(ECKey);
			BN_free(PrivateKeyBigNum);
			return false;
		}

		SIZE_T SignatureLen = 0;
		if (EVP_DigestSignFinal(Context, nullptr, &SignatureLen) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_MD_CTX_free(Context);
			EVP_PKEY_free(EVPPrivateKey);
			EC_KEY_free(ECKey);
			BN_free(PrivateKeyBigNum);
			return false;
		}

		OutputSignature.SetNum(SignatureLen, EAllowShrinking::No);

		if (EVP_DigestSignFinal(Context, OutputSignature.GetData(), &SignatureLen) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_MD_CTX_free(Context);
			EVP_PKEY_free(EVPPrivateKey);
			EC_KEY_free(ECKey);
			BN_free(PrivateKeyBigNum);
			return false;
		}

		EVP_MD_CTX_free(Context);
		EVP_PKEY_free(EVPPrivateKey);
		EC_KEY_free(ECKey);
		BN_free(PrivateKeyBigNum);

		return true;
	}
}