// Copyright 2025 - Roberto De Ioris

#pragma once

#include "Modules/ModuleManager.h"

class FUncryptoolModule : public IModuleInterface
{
public:

	/** IModuleInterface implementation */
	virtual void StartupModule() override;
	virtual void ShutdownModule() override;
};

struct FUncryptoolBytes
{
	FUncryptoolBytes(const std::initializer_list<uint8>& Bytes) : Ptr(Bytes.begin()), Size(Bytes.size())
	{
	}

	template<typename T>
	FUncryptoolBytes(const T& Container) : Ptr(Container.GetData()), Size(Container.Num())
	{
	}

	const uint8* GetData() const
	{
		return Ptr;
	}

	int32 Num() const
	{
		return Size;
	}

	const uint8* Ptr;
	const int32 Size;
};

enum class EUncryptoolEllipticCurve : uint8;
enum class EUncryptoolHash : uint8;

namespace Uncryptool
{
	/*
	* Utils functions
	*/

	UNCRYPTOOL_API TArray<uint8> UTF8StringToBytes(const FStringView& String);
	UNCRYPTOOL_API FString BytesToUTF8String(const FUncryptoolBytes& Bytes);
	UNCRYPTOOL_API FString BytesToHexString(const FUncryptoolBytes& Bytes);

	UNCRYPTOOL_API FString GetOpenSSLError();

	UNCRYPTOOL_API bool RandomBytes(const int32 NumBytes, TArray<uint8>& OutputBytes);
	UNCRYPTOOL_API bool RandomBytesFill(TArray<uint8>& Bytes);

	/*
	* Hashing functions
	*/

	UNCRYPTOOL_API TArray<uint8> SHA256Digest(const FUncryptoolBytes& Bytes);
	UNCRYPTOOL_API TArray<uint8> SHA512Digest(const FUncryptoolBytes& Bytes);
	UNCRYPTOOL_API TArray<uint8> RIPEMD160Digest(const FUncryptoolBytes& Bytes);
	UNCRYPTOOL_API FString SHA256HexDigest(const FUncryptoolBytes& Bytes);
	UNCRYPTOOL_API FString SHA512HexDigest(const FUncryptoolBytes& Bytes);
	UNCRYPTOOL_API FString RIPEMD160HexDigest(const FUncryptoolBytes& Bytes);


	/*
	* Symmetric Encryption functions
	*/

	UNCRYPTOOL_API bool DecryptAES256CBC(const FUncryptoolBytes& EncryptedBytes, const FUncryptoolBytes& Key, const FUncryptoolBytes& Iv, TArray<uint8>& OutputBytes, FString& ErrorMessage);
	UNCRYPTOOL_API bool EncryptAES256CBC(const FUncryptoolBytes& InputBytes, const FUncryptoolBytes& Key, const FUncryptoolBytes& Iv, TArray<uint8>& EncryptedBytes, FString& ErrorMessage);
	UNCRYPTOOL_API bool DecryptChaCha20(const FUncryptoolBytes& EncryptedBytes, const FUncryptoolBytes& Key, const FUncryptoolBytes& Nonce, TArray<uint8>& OutputBytes, FString& ErrorMessage);
	UNCRYPTOOL_API bool EncryptChaCha20(const FUncryptoolBytes& InputBytes, const FUncryptoolBytes& Key, const FUncryptoolBytes& Nonce, TArray<uint8>& EncryptedBytes, FString& ErrorMessage);

	/*
	* Elliptic Curve Cryptography (ECC)
	*/

	UNCRYPTOOL_API bool GenerateECKey(const EUncryptoolEllipticCurve EllipticCurve, TArray<uint8>& PrivateKey, TArray<uint8>& PublicKey, FString& ErrorMessage);
	UNCRYPTOOL_API bool ECDSADigestSign(const EUncryptoolEllipticCurve EllipticCurve, const FUncryptoolBytes& PrivateKey, const FUncryptoolBytes& InputBytes, const EUncryptoolHash Hash, TArray<uint8>& OutputSignature, FString& ErrorMessage);
}
