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
	RIPEMD160
};

UENUM()
enum class EUncryptoolEllipticCurve : uint8
{
	PRIME256V1,
	SECP256K1,
	SECP384R1,
	SECP521R1
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
