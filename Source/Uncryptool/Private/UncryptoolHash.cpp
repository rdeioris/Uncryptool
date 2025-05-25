// Copyright 2025 - Roberto De Ioris

#include "Uncryptool.h"

#define UI UI_ST
THIRD_PARTY_INCLUDES_START
#include "openssl/sha.h"
#include "openssl/ripemd.h"
THIRD_PARTY_INCLUDES_END
#undef UI

namespace Uncryptool
{

	TArray<uint8> SHA256Digest(const FUncryptoolBytes& Bytes)
	{
		SHA256_CTX Context;
		SHA256_Init(&Context);

		SHA256_Update(&Context, Bytes.GetData(), Bytes.Num());

		TArray<uint8> Digest;
		Digest.AddUninitialized(SHA256_DIGEST_LENGTH);

		SHA256_Final(Digest.GetData(), &Context);

		return Digest;
	}

	TArray<uint8> SHA512Digest(const FUncryptoolBytes& Bytes)
	{
		SHA512_CTX Context;
		SHA512_Init(&Context);

		SHA512_Update(&Context, Bytes.GetData(), Bytes.Num());

		TArray<uint8> Digest;
		Digest.AddUninitialized(SHA512_DIGEST_LENGTH);

		SHA512_Final(Digest.GetData(), &Context);

		return Digest;
	}

	TArray<uint8> RIPEMD160Digest(const FUncryptoolBytes& Bytes)
	{
		RIPEMD160_CTX Context;
		RIPEMD160_Init(&Context);

		RIPEMD160_Update(&Context, Bytes.GetData(), Bytes.Num());

		TArray<uint8> Digest;
		Digest.AddUninitialized(RIPEMD160_DIGEST_LENGTH);

		RIPEMD160_Final(Digest.GetData(), &Context);

		return Digest;
	}

	FString SHA256HexDigest(const FUncryptoolBytes& Bytes)
	{
		return BytesToHexString(SHA256Digest(Bytes));
	}

	FString SHA512HexDigest(const FUncryptoolBytes& Bytes)
	{
		return BytesToHexString(SHA512Digest(Bytes));
	}

	FString RIPEMD160HexDigest(const FUncryptoolBytes& Bytes)
	{
		return BytesToHexString(RIPEMD160Digest(Bytes));
	}

}