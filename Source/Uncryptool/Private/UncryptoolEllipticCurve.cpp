// Copyright 2025 - Roberto De Ioris

#include "Uncryptool.h"
#include "UncryptoolFunctionLibrary.h"

#define UI UI_ST
THIRD_PARTY_INCLUDES_START
#include "openssl/ec.h"
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

}