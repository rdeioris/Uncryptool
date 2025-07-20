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

	bool DecryptAgeX25519(const FUncryptoolBytes& InputBytes, FUncryptoolPrivateKey& PrivateKey, FString& ErrorMessage)
	{
		// step0: extract the version
		const char* AgeVersion = "age-encryption.org/v1\n";
		const int32 AgeVersionLen = FCStringAnsi::Strlen(AgeVersion);

		if (InputBytes.Num() < AgeVersionLen)
		{
			ErrorMessage = "Invalid age version";
			return false;
		}

		if (FMemory::Memcmp(InputBytes.GetData(), AgeVersion, AgeVersionLen))
		{
			ErrorMessage = "Unsupported age version";
			return false;
		}

		// step1: extract recipients
		for (int32 ByteIndex = AgeVersionLen; ByteIndex < InputBytes.Num(); ByteIndex++)
		{

		}
		return false;
	}

	bool EncryptAgeX25519(const FUncryptoolBytes& InputBytes, const TArray<FUncryptoolPublicKey>& PublicKeys, TArray<uint8>& EncryptedBytes, FString& ErrorMessage)
	{
		TArray<uint8> FileKey;
		if (!Uncryptool::RandomBytes(16, FileKey))
		{
			ErrorMessage = "Unable to generate File key";
			return false;
		}

		TArray<uint8> NonceZero;
		NonceZero.AddZeroed(12);

		TArray<uint8> NoncePayload;
		if (!Uncryptool::RandomBytes(16, NoncePayload))
		{
			ErrorMessage = "Unable to generate Payload nonce";
			return false;
		}

		TArray<uint8> PayloadKey;
		if (!Uncryptool::HKDF(EUncryptoolHash::SHA256, NoncePayload, FileKey, "payload", PayloadKey, ErrorMessage))
		{
			return false;
		}

		EncryptedBytes.Empty();
		EncryptedBytes.Append("age-encryption.org/v1\n");
		for (const FUncryptoolPublicKey& PublicKey : PublicKeys)
		{
			TArray<uint8> PublicKeyRaw;
			if (!Uncryptool::PublicKeyToRaw(PublicKey, PublicKeyRaw, ErrorMessage))
			{
				return false;
			}

			TArray<uint8> Identity;
			if (!Uncryptool::Bech32Encode("age1", PublicKeyRaw, Identity, ErrorMessage))
			{
				return false;
			}

			TArray<uint8> EphemeralSecret;
			if (!Uncryptool::RandomBytes(32, EphemeralSecret))
			{
				ErrorMessage = FString::Printf(TEXT("Unable to generate X25519 recipient stanza for %s"), *Uncryptool::BytesToUTF8String(Identity));
				return false;
			}

			FUncryptoolPrivateKey EphemeralPrivateKey;
			if (!Uncryptool::ECPrivateKeyFromRaw(EUncryptoolEllipticCurve::X25519, EphemeralSecret, EphemeralPrivateKey, ErrorMessage))
			{
				return false;
			}

			FUncryptoolPublicKey EphemeralShare;
			if (!Uncryptool::PublicKeyFromPrivateKey(EphemeralPrivateKey, EphemeralShare, ErrorMessage))
			{
				return false;
			}

			TArray<uint8> SharedSecret;
			if (!Uncryptool::ECDH(EphemeralPrivateKey, PublicKey, SharedSecret, ErrorMessage))
			{
				return false;
			}

			TArray<uint8> Salt;
			if (!Uncryptool::PublicKeyToRaw(EphemeralShare, Salt, ErrorMessage))
			{
				return false;
			}
			Salt.Append(PublicKeyRaw);

			TArray<uint8> WrappingKey;
			if (!Uncryptool::HKDF(EUncryptoolHash::SHA256, Salt, SharedSecret, "age-encryption.org/v1/X25519", WrappingKey, ErrorMessage))
			{
				return false;
			}

			TArray<uint8> StanzaBody;
			if (!Uncryptool::EncryptChaCha20Poly1305(FileKey, WrappingKey, NonceZero, "", StanzaBody, ErrorMessage))
			{
				return false;
			}

			// append stanza line
		}

		// compute HMAC key
		TArray<uint8> HMACKey;
		if (!Uncryptool::HKDF(EUncryptoolHash::SHA256, "", FileKey, "header", HMACKey, ErrorMessage))
		{
			return false;
		}


		// compute HMAC
		TArray<uint8> HMAC;
		if (!Uncryptool::HMAC(EUncryptoolHash::SHA256, "", HMACKey, HMAC, ErrorMessage))
		{
			return false;
		}

		// append HMAC

		// append payload...

		// first nonce

		// then chunks...
		TArray<uint8> NonceChunk;

		TArray<uint8> Chunk;
		if (!Uncryptool::EncryptChaCha20Poly1305(InputBytes, PayloadKey, NonceChunk, "", Chunk, ErrorMessage))
		{
			return false;
		}


		return true;
	}
}