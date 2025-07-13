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


	bool Hash(const EUncryptoolHash Hash, const FUncryptoolBytes& Bytes, TArray<uint8>& OutputBytes, FString& ErrorMessage)
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
		case EUncryptoolHash::BLAKE2b512:
			HashAlgo = EVP_blake2b512();
			break;
		case EUncryptoolHash::BLAKE2s256:
			HashAlgo = EVP_blake2s256();
			break;
		default:
			ErrorMessage = "Unsupported Hash Algorithm";
			return false;
		}

		EVP_MD_CTX* Context = EVP_MD_CTX_new();
		if (!Context)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		if (EVP_DigestInit(Context, HashAlgo) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_MD_CTX_free(Context);
			return false;
		}

		if (EVP_DigestUpdate(Context, Bytes.GetData(), Bytes.Num()) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_MD_CTX_free(Context);
			return false;
		}

		uint32 DigestLen = EVP_MD_size(HashAlgo);

		OutputBytes.SetNum(DigestLen, EAllowShrinking::No);

		if (EVP_DigestFinal(Context, OutputBytes.GetData(), &DigestLen) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_MD_CTX_free(Context);
			return false;
		}

		EVP_MD_CTX_free(Context);
		return true;
	}

	bool HMAC(const FUncryptoolBytes& Bytes, const FUncryptoolBytes& Secret, const EUncryptoolHash Hash, TArray<uint8>& OutputBytes, FString& ErrorMessage)
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
		case EUncryptoolHash::BLAKE2b512:
			HashAlgo = EVP_blake2b512();
			break;
		case EUncryptoolHash::BLAKE2s256:
			HashAlgo = EVP_blake2s256();
			break;
		default:
			ErrorMessage = "Unsupported Hash Algorithm";
			return false;
		}

		uint32 DigestLen = EVP_MD_size(HashAlgo);

		OutputBytes.SetNum(DigestLen, EAllowShrinking::No);

		if (::HMAC(HashAlgo, Secret.GetData(), Secret.Num(), Bytes.GetData(), Bytes.Num(), OutputBytes.GetData(), &DigestLen) == nullptr)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		return true;
	}

	bool PBEScrypt(const FUncryptoolBytes& Password, const FUncryptoolBytes& Salt, const uint64 N, const uint64 R, const uint64 P, const int32 KeyLen, TArray<uint8>& OutputBytes, FString& ErrorMessage)
	{
		if (KeyLen < 1)
		{
			ErrorMessage = "KeyLen must be > 0";
			return false;
		}

		OutputBytes.SetNum(KeyLen, EAllowShrinking::No);
		if (EVP_PBE_scrypt(Password.GetData<char>(), Password.Num(), Salt.GetData(), Salt.Num(), N, R, P, 0, OutputBytes.GetData(), KeyLen) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		return true;
	}


}