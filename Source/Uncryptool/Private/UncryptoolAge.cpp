// Copyright 2025 - Roberto De Ioris

#include "UncryptoolFunctionLibrary.h"

#define UI UI_ST
THIRD_PARTY_INCLUDES_START
#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "openssl/sha.h"
#include "openssl/ripemd.h"
THIRD_PARTY_INCLUDES_END
#undef UI

namespace Uncryptool
{
	bool LoadAgeIdentity(const FUncryptoolBytes& InputBytes, FUncryptoolPrivateKey& PrivateKey, FUncryptoolPublicKey& PublicKey, FString& ErrorMessage)
	{
		TArray<uint8> Accumulator;
		bool bComment = false;
		bool bResetNext = false;
		for (int32 Index = 0; Index < InputBytes.Num(); Index++)
		{
			const uint8 Byte = InputBytes.GetData()[Index];
			if (bComment)
			{
				if (Byte == '\n')
				{
					bComment = false;
					bResetNext = true;
				}
				continue;
			}
			else
			{
				if (Byte == '#')
				{
					bComment = true;
					continue;
				}
				else if (Byte == '\n')
				{
					bResetNext = true;
				}
				else
				{
					if (bResetNext)
					{
						Accumulator.Empty();
						bResetNext = false;
					}
					Accumulator.Add(Byte);
				}
			}
		}

		TArray<uint8> PrivateKeyRaw;
		if (!Bech32Decode("AGE-SECRET-KEY-", Accumulator, PrivateKeyRaw, ErrorMessage))
		{
			return false;
		}

		if (PrivateKeyRaw.Num() != 32)
		{
			ErrorMessage = "Invalid X25519 key size, expected 32 bytes";
			return false;
		}

		EVP_PKEY* EVPPrivateKey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, PrivateKeyRaw.GetData(), 32);
		if (!EVPPrivateKey)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		PrivateKey.Type = EUncryptoolKey::EC;
		PrivateKey.Bits = EVP_PKEY_bits(EVPPrivateKey);

		int32 DerLen = i2d_PrivateKey(EVPPrivateKey, nullptr);
		if (DerLen <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPrivateKey);
			return false;
		}

		PrivateKey.DER.SetNum(DerLen, EAllowShrinking::No);

		uint8* DERPtr = PrivateKey.DER.GetData();

		DerLen = i2d_PrivateKey(EVPPrivateKey, &DERPtr);
		if (DerLen <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_PKEY_free(EVPPrivateKey);
			return false;
		}

		EVP_PKEY_free(EVPPrivateKey);

		return PublicKeyFromPrivateKey(PrivateKey, PublicKey, ErrorMessage);
	}
}