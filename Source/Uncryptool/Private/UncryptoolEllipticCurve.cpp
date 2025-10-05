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
	bool GenerateKeyFromCustomEllipticCurve(const FUncryptoolEllipticCurve& EllipticCurve, FUncryptoolPrivateKey& PrivateKey, FUncryptoolPublicKey& PublicKey, FString& ErrorMessage)
	{
		return false;
	}

	bool ECPrivateKeyToCustomEllipticCurve(const FUncryptoolPrivateKey& PrivateKey, FUncryptoolEllipticCurve& EllipticCurve, FString& ErrorMessage)
	{
		const uint8* DERPtr = PrivateKey.DER.GetData();

		EC_KEY* ECKey = d2i_ECPrivateKey(nullptr, &DERPtr, PrivateKey.DER.Num());
		if (!ECKey)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		const EC_GROUP* Group = EC_KEY_get0_group(ECKey);
		if (!Group)
		{
			ErrorMessage = GetOpenSSLError();
			EC_KEY_free(ECKey);
			return false;
		}

		BN_CTX* Context = BN_CTX_new();
		if (!Group)
		{
			ErrorMessage = GetOpenSSLError();
			EC_KEY_free(ECKey);
			return false;
		}

		BN_CTX_start(Context);

		if (!EC_GROUP_get_curve_GFp(Group, EllipticCurve.P.GetNativeBigNum<BIGNUM>(), EllipticCurve.A.GetNativeBigNum<BIGNUM>(), EllipticCurve.B.GetNativeBigNum<BIGNUM>(), Context))
		{
			ErrorMessage = GetOpenSSLError();
			EC_KEY_free(ECKey);
			return false;
		}

		const EC_POINT* G = EC_GROUP_get0_generator(Group);
		if (!G)
		{
			ErrorMessage = GetOpenSSLError();
			BN_CTX_end(Context);
			BN_CTX_free(Context);
			EC_KEY_free(ECKey);
			return false;
		}

		if (!EC_POINT_get_affine_coordinates_GFp(Group, G, EllipticCurve.Gx.GetNativeBigNum<BIGNUM>(), EllipticCurve.Gy.GetNativeBigNum<BIGNUM>(), Context))
		{
			ErrorMessage = GetOpenSSLError();
			BN_CTX_end(Context);
			BN_CTX_free(Context);
			EC_KEY_free(ECKey);
			return false;
		}

		if (!EC_GROUP_get_order(Group, EllipticCurve.Order.GetNativeBigNum<BIGNUM>(), Context))
		{
			ErrorMessage = GetOpenSSLError();
			BN_CTX_end(Context);
			BN_CTX_free(Context);
			EC_KEY_free(ECKey);
			return false;
		}

		if (!EC_GROUP_get_cofactor(Group, EllipticCurve.Cofactor.GetNativeBigNum<BIGNUM>(), Context))
		{
			ErrorMessage = GetOpenSSLError();
			BN_CTX_end(Context);
			BN_CTX_free(Context);
			EC_KEY_free(ECKey);
			return false;
		}

		BN_CTX_end(Context);
		BN_CTX_free(Context);
		EC_KEY_free(ECKey);
		return true;
	}

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
		case EUncryptoolEllipticCurve::X25519:
			Nid = NID_X25519;
			break;
		default:
			ErrorMessage = "Unknown Elliptic Curve";
			return false;
		}

		EVP_PKEY_CTX* Context = EVP_PKEY_CTX_new_id(Nid == NID_X25519 ? EVP_PKEY_X25519 : EVP_PKEY_EC, nullptr);
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

		if (Nid != NID_X25519)
		{
			if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(Context, Nid) <= 0)
			{
				ErrorMessage = GetOpenSSLError();
				EVP_PKEY_CTX_free(Context);
				return false;
			}
		}

		EVP_PKEY* EVPKey = nullptr;
		if (EVP_PKEY_keygen(Context, &EVPKey) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_CTX_free(Context);
			return false;
		}

		EVP_PKEY_CTX_free(Context);

		PrivateKey.Type = EUncryptoolKey::EC;
		PublicKey.Type = EUncryptoolKey::EC;

		PrivateKey.Bits = EVP_PKEY_bits(EVPKey);
		PublicKey.Bits = PrivateKey.Bits;

		int32 DerLen = i2d_PrivateKey(EVPKey, nullptr);
		if (DerLen <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPKey);
			return false;
		}

		PrivateKey.DER.SetNum(DerLen, EAllowShrinking::No);

		uint8* DERPtr = PrivateKey.DER.GetData();

		DerLen = i2d_PrivateKey(EVPKey, &DERPtr);
		if (DerLen <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPKey);
			return false;
		}

		DerLen = i2d_PUBKEY(EVPKey, nullptr);
		if (DerLen <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPKey);
			return false;
		}

		PublicKey.DER.SetNum(DerLen, EAllowShrinking::No);

		DERPtr = PublicKey.DER.GetData();
		DerLen = i2d_PUBKEY(EVPKey, &DERPtr);
		if (DerLen <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPKey);
			return false;
		}

		EVP_PKEY_free(EVPKey);

		return true;
	}

	bool ECPrivateKeyFromRaw(const EUncryptoolEllipticCurve EllipticCurve, const FUncryptoolBytes& InputBytes, FUncryptoolPrivateKey& PrivateKey, FString& ErrorMessage)
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
		case EUncryptoolEllipticCurve::X25519:
			Nid = NID_X25519;
			break;
		default:
			ErrorMessage = "Unknown Elliptic Curve";
			return false;
		}

		EVP_PKEY* EVPKey = EVP_PKEY_new_raw_private_key(Nid == NID_X25519 ? EVP_PKEY_X25519 : EVP_PKEY_EC, nullptr, InputBytes.GetData(), InputBytes.Num());
		if (!EVPKey)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		PrivateKey.Type = EUncryptoolKey::EC;
		PrivateKey.Bits = EVP_PKEY_bits(EVPKey);

		int32 DerLen = i2d_PrivateKey(EVPKey, nullptr);
		if (DerLen <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPKey);
			return false;
		}

		PrivateKey.DER.SetNum(DerLen, EAllowShrinking::No);

		uint8* DERPtr = PrivateKey.DER.GetData();

		DerLen = i2d_PrivateKey(EVPKey, &DERPtr);
		if (DerLen <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPKey);
			return false;
		}

		EVP_PKEY_free(EVPKey);
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

	bool ECDH(const FUncryptoolPrivateKey& PrivateKey, const FUncryptoolPublicKey& PublicKey, TArray<uint8>& OutputSharedSecret, FString& ErrorMessage)
	{
		const uint8* DERPtr = PublicKey.DER.GetData();

		EVP_PKEY* EVPPublicKey = d2i_PUBKEY(nullptr, &DERPtr, PublicKey.DER.Num());
		if (!EVPPublicKey)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		const int32 CurveType = EVP_PKEY_base_id(EVPPublicKey);

		DERPtr = PrivateKey.DER.GetData();

		EVP_PKEY* EVPPrivateKey = d2i_PrivateKey(CurveType, nullptr, &DERPtr, PrivateKey.DER.Num());
		if (!EVPPrivateKey)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPublicKey);
			return false;
		}

		EVP_PKEY_CTX* Context = EVP_PKEY_CTX_new(EVPPrivateKey, nullptr);
		if (!Context)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPublicKey);
			EVP_PKEY_free(EVPPrivateKey);
			return false;
		}

		if (EVP_PKEY_derive_init(Context) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_CTX_free(Context);
			EVP_PKEY_free(EVPPublicKey);
			EVP_PKEY_free(EVPPrivateKey);
			return false;
		}

		if (EVP_PKEY_derive_set_peer(Context, EVPPublicKey) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_CTX_free(Context);
			EVP_PKEY_free(EVPPublicKey);
			EVP_PKEY_free(EVPPrivateKey);
			return false;
		}

		SIZE_T KeyLen = 0;
		if (EVP_PKEY_derive(Context, nullptr, &KeyLen) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_CTX_free(Context);
			EVP_PKEY_free(EVPPublicKey);
			EVP_PKEY_free(EVPPrivateKey);
			return false;
		}

		OutputSharedSecret.SetNum(KeyLen, EAllowShrinking::No);

		if (EVP_PKEY_derive(Context, OutputSharedSecret.GetData(), &KeyLen) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_CTX_free(Context);
			EVP_PKEY_free(EVPPublicKey);
			EVP_PKEY_free(EVPPrivateKey);
			return false;
		}

		EVP_PKEY_CTX_free(Context);
		EVP_PKEY_free(EVPPublicKey);
		EVP_PKEY_free(EVPPrivateKey);
		return true;
	}
}