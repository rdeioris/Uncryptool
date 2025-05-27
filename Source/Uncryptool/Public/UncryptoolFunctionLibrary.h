// Fill out your copyright notice in the Description page of Project Settings.

#pragma once

#include "CoreMinimal.h"
#include "Kismet/BlueprintFunctionLibrary.h"
#include "UncryptoolFunctionLibrary.generated.h"

UENUM()
enum class EUncryptoolHash : uint8
{
	SHA256,
	SHA512,
	RIPEMD160,
	Unknown = 0xff
};

UENUM()
enum class EUncryptoolEllipticCurve : uint8
{
	PRIME256V1,
	SECP256K1,
	SECP384R1,
	SECP521R1,
	Unknown = 0xff
};

UENUM()
enum class EUncryptoolKey : uint8
{
	RSA,
	DSA,
	EC,
	Unknown = 0xff
};

USTRUCT(BlueprintType)
struct FUncryptoolPrivateKey
{
	GENERATED_BODY()

	UPROPERTY(BlueprintReadOnly, VisibleAnywhere, Category = "Uncryptool")
	EUncryptoolKey Type = EUncryptoolKey::Unknown;

	UPROPERTY(BlueprintReadOnly, VisibleAnywhere, Category = "Uncryptool")
	int32 Bits = 0;

	TArray<uint8> DER;
};

USTRUCT(BlueprintType)
struct FUncryptoolPublicKey
{
	GENERATED_BODY()

	UPROPERTY(BlueprintReadOnly, VisibleAnywhere, Category = "Uncryptool")
	EUncryptoolKey Type = EUncryptoolKey::Unknown;

	UPROPERTY(BlueprintReadOnly, VisibleAnywhere, Category = "Uncryptool")
	int32 Bits = 0;

	TArray<uint8> DER;
};

USTRUCT(BlueprintType)
struct FUncryptoolBigNum
{
	GENERATED_BODY()

	FUncryptoolBigNum();
	~FUncryptoolBigNum();
	FUncryptoolBigNum(const FUncryptoolBigNum& Other);
	FUncryptoolBigNum& operator=(const FUncryptoolBigNum& Other);
	FUncryptoolBigNum(FUncryptoolBigNum&& Other);

protected:
	void* BigNumPtr = nullptr;
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

	UNCRYPTOOL_API bool GenerateECKey(const EUncryptoolEllipticCurve EllipticCurve, FUncryptoolPrivateKey& PrivateKey, FUncryptoolPublicKey& PublicKey, FString& ErrorMessage);
	UNCRYPTOOL_API bool ECDSADigestSign(const FUncryptoolPrivateKey& PrivateKey, const FUncryptoolBytes& InputBytes, const EUncryptoolHash Hash, TArray<uint8>& OutputSignature, FString& ErrorMessage);

	/*
	* Asymmetric keys
	*/

	UNCRYPTOOL_API bool PEMToPrivateKey(const FUncryptoolBytes& PEMBytes, FUncryptoolPrivateKey& PrivateKey, FString& ErrorMessage);
}


/**
 *
 */
UCLASS()
class UNCRYPTOOL_API UUncryptoolFunctionLibrary : public UBlueprintFunctionLibrary
{
	GENERATED_BODY()

public:

	UFUNCTION(BlueprintCallable, BlueprintPure, Category = "Uncryptool")
	static TArray<uint8> UTF8StringToBytes(const FString& String);

	UFUNCTION(BlueprintCallable, BlueprintPure, Category = "Uncryptool")
	static FString BytesToUTF8String(const TArray<uint8>& Bytes);

	UFUNCTION(BlueprintCallable, BlueprintPure, Category = "Uncryptool")
	static FString BytesToHexString(const TArray<uint8>& Bytes);

	UFUNCTION(BlueprintCallable, Category = "Uncryptool")
	static FString SHA256HexDigest(const TArray<uint8>& Bytes);

	UFUNCTION(BlueprintCallable, Category = "Uncryptool")
	static FString SHA512HexDigest(const TArray<uint8>& Bytes);

	UFUNCTION(BlueprintCallable, Category = "Uncryptool")
	static FString RIPEMD160HexDigest(const TArray<uint8>& Bytes);

	UFUNCTION(BlueprintCallable, Category = "Uncryptool")
	static TArray<uint8> DecryptAES256CBC(const TArray<uint8>& Bytes, const TArray<uint8>& Key, const TArray<uint8>& Iv, bool& bSuccess, FString& ErrorMessage);

	UFUNCTION(BlueprintCallable, Category = "Uncryptool")
	static TArray<uint8> EncryptAES256CBC(const TArray<uint8>& Bytes, const TArray<uint8>& Key, const TArray<uint8>& Iv, bool& bSuccess, FString& ErrorMessage);

	UFUNCTION(BlueprintCallable, Category = "Uncryptool")
	static TArray<uint8> DecryptChaCha20(const TArray<uint8>& Bytes, const TArray<uint8>& Key, const TArray<uint8>& Nonce, bool& bSuccess, FString& ErrorMessage);

	UFUNCTION(BlueprintCallable, Category = "Uncryptool")
	static TArray<uint8> EncryptChaCha20(const TArray<uint8>& Bytes, const TArray<uint8>& Key, const TArray<uint8>& Nonce, bool& bSuccess, FString& ErrorMessage);

	UFUNCTION(BlueprintCallable, Category = "Uncryptool")
	static TArray<uint8> RandomBytes(const int32 NumBytes);
};
