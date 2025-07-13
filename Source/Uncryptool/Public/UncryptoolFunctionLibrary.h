// Copyright 2025 - Roberto De Ioris

#pragma once

#include "CoreMinimal.h"
#include "Kismet/BlueprintFunctionLibrary.h"
#include "UncryptoolFunctionLibrary.generated.h"

UENUM()
enum class EUncryptoolHash : uint8
{
	SHA256,
	SHA384,
	SHA512,
	RIPEMD160,
	SHA1,
	SHA224,
	BLAKE2b512,
	BLAKE2s256,
	Unknown = 0xff
};

UENUM()
enum class EUncryptoolEllipticCurve : uint8
{
	PRIME256V1,
	SECP256K1,
	SECP384R1,
	SECP521R1,
	X25519,
	Unknown = 0xff
};

UENUM()
enum class EUncryptoolKey : uint8
{
	RSA,
	DSA,
	EC,
	ED25519,
	ED448,
	DH,
	Unknown = 0xff
};

UENUM()
enum class EUncryptoolKeyDerivation : uint8
{
	PBKDF2,
	Scrypt,
	HKDF,
	Legacy,
	Unknown = 0xff
};

UENUM()
enum class EUncryptoolCipher : uint8
{
	AES256CBC,
	Camelia256CBC,
	ChaCha20,
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

	void* GetNativeBigNum() const;

protected:
	void* NativeBigNum = nullptr;
};

struct FUncryptoolBytes
{
	FUncryptoolBytes(const char* Chars) : Ptr(reinterpret_cast<const uint8*>(Chars)), Size(FCStringAnsi::Strlen(Chars))
	{
	}

	FUncryptoolBytes(const std::initializer_list<uint8>& Bytes) : Ptr(Bytes.begin()), Size(Bytes.size())
	{
	}

	FUncryptoolBytes(const uint8* InPtr, const int32 InSize) : Ptr(InPtr), Size(InSize)
	{
	}

	template<typename T>
	FUncryptoolBytes(const T& Container) : Ptr(Container.GetData()), Size(Container.Num())
	{
	}

	template<typename T>
	const T* GetData() const
	{
		return reinterpret_cast<const T*>(Ptr);
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
	template<typename T>
	T StructNumericCast(const FUncryptoolStructArgument& StructArgument);
}

USTRUCT(BlueprintType)
struct FUncryptoolStructArgument
{
	GENERATED_BODY()

	enum class Type { Raw, Int64, UInt64, Int32, UInt32, Int16, UInt16, Int8, UInt8, Float, Double, Bool, Invalid = 0xff };

	FUncryptoolStructArgument() : InternalType(Type::Invalid), Number(0LLU) {};

	FUncryptoolStructArgument(const int32 InValue) : InternalType(Type::Int32), Number(InValue) {};
	FUncryptoolStructArgument(const uint32 InValue) : InternalType(Type::UInt32), Number(InValue) {};
	FUncryptoolStructArgument(const int16 InValue) : InternalType(Type::Int16), Number(InValue) {};
	FUncryptoolStructArgument(const uint16 InValue) : InternalType(Type::UInt16), Number(InValue) {};

	~FUncryptoolStructArgument() = default;
	FUncryptoolStructArgument(const FUncryptoolStructArgument& Other) = default;
	FUncryptoolStructArgument& operator=(const FUncryptoolStructArgument& Other) = default;
	FUncryptoolStructArgument(FUncryptoolStructArgument&& Other) = default;

	explicit operator int32() const;
	explicit operator int16() const;

	explicit operator uint32() const;
	explicit operator uint16() const;

protected:
	Type InternalType;

	union
	{
		int64 Int64Value;
		uint64 UInt64Value;
		int32 Int32Value;
		uint32 UInt32Value;
		int16 Int16Value;
		uint16 UInt16Value;
		int8 Int8Value;
		uint8 UInt8Value;
		bool BoolValue;
		float FloatValue;
		double DoubleValue;
	} Number;

	TArray<uint8> RawData;

public:
	Type GetType() const { return InternalType; }

	template<typename T>
	friend T Uncryptool::StructNumericCast(const FUncryptoolStructArgument& StructArgument);
};

namespace Uncryptool
{
	/*
	* Utils functions
	*/

	UNCRYPTOOL_API TArray<uint8> UTF8StringToBytes(const FStringView& String);
	UNCRYPTOOL_API FString BytesToUTF8String(const FUncryptoolBytes& Bytes);
	UNCRYPTOOL_API FString BytesToHexString(const FUncryptoolBytes& Bytes);
	UNCRYPTOOL_API bool HexStringToBytes(const FStringView& String, TArray<uint8>& OutputBytes);
	UNCRYPTOOL_API bool HexStringToBytes(const char* UTF8String, TArray<uint8>& OutputBytes);

	UNCRYPTOOL_API FString GetOpenSSLError();

	UNCRYPTOOL_API bool RandomBytes(const int32 NumBytes, TArray<uint8>& OutputBytes);
	UNCRYPTOOL_API bool RandomBytesFill(TArray<uint8>& Bytes);

	UNCRYPTOOL_API bool StructPack(const FStringView& Format, const TArray<FUncryptoolStructArgument>& Arguments, TArray<uint8>& OutputBytes, FString& ErrorMessage);
	UNCRYPTOOL_API bool StructPack(const FString& Format, const TArray<FUncryptoolStructArgument>& Arguments, TArray<uint8>& OutputBytes, FString& ErrorMessage);

	UNCRYPTOOL_API bool BitFromBytes(const FUncryptoolBytes& InputBytes, const int32 Offset, uint8& BitValue);

	/*
	* Hashing functions
	*/

	UNCRYPTOOL_API TArray<uint8> SHA256Digest(const FUncryptoolBytes& Bytes);
	UNCRYPTOOL_API TArray<uint8> SHA512Digest(const FUncryptoolBytes& Bytes);
	UNCRYPTOOL_API TArray<uint8> RIPEMD160Digest(const FUncryptoolBytes& Bytes);
	UNCRYPTOOL_API FString SHA256HexDigest(const FUncryptoolBytes& Bytes);
	UNCRYPTOOL_API FString SHA512HexDigest(const FUncryptoolBytes& Bytes);
	UNCRYPTOOL_API FString RIPEMD160HexDigest(const FUncryptoolBytes& Bytes);

	UNCRYPTOOL_API bool Hash(const EUncryptoolHash Hash, const FUncryptoolBytes& Bytes, TArray<uint8>& OutputBytes, FString& ErrorMessage);


	/*
	* HMAC functions
	*/

	UNCRYPTOOL_API bool HMAC(const FUncryptoolBytes& Bytes, const FUncryptoolBytes& Secret, const EUncryptoolHash Hash, TArray<uint8>& OutputBytes, FString& ErrorMessage);


	/*
	* Key Derivation functions
	*/
	bool PBEScrypt(const FUncryptoolBytes& Password, const FUncryptoolBytes& Salt, const uint64 N, const uint64 R, const uint64 P, const int32 KeyLen, TArray<uint8>& OutputBytes, FString& ErrorMessage);
	

	/*
	* Symmetric Encryption functions
	*/

	UNCRYPTOOL_API bool DecryptAES256CBC(const FUncryptoolBytes& EncryptedBytes, const FUncryptoolBytes& Key, const FUncryptoolBytes& Iv, TArray<uint8>& OutputBytes, FString& ErrorMessage);
	UNCRYPTOOL_API bool EncryptAES256CBC(const FUncryptoolBytes& InputBytes, const FUncryptoolBytes& Key, const FUncryptoolBytes& Iv, TArray<uint8>& EncryptedBytes, FString& ErrorMessage);
	UNCRYPTOOL_API bool DecryptChaCha20(const FUncryptoolBytes& EncryptedBytes, const FUncryptoolBytes& Key, const FUncryptoolBytes& Nonce, TArray<uint8>& OutputBytes, FString& ErrorMessage);
	UNCRYPTOOL_API bool DecryptChaCha20Salted(const FUncryptoolBytes& EncryptedBytes, const FUncryptoolBytes& Password, const EUncryptoolKeyDerivation KeyDerivation, const int32 Iterations, TArray<uint8>& OutputBytes, FString& ErrorMessage);
	UNCRYPTOOL_API bool EncryptChaCha20(const FUncryptoolBytes& InputBytes, const FUncryptoolBytes& Key, const FUncryptoolBytes& Nonce, TArray<uint8>& EncryptedBytes, FString& ErrorMessage);

	UNCRYPTOOL_API bool DecryptAES256CTR(const FUncryptoolBytes& EncryptedBytes, const FUncryptoolBytes& Key, const FUncryptoolBytes& Counter, TArray<uint8>& OutputBytes, FString& ErrorMessage);

	UNCRYPTOOL_API bool DecryptAESZIP(const FUncryptoolBytes& EncryptedBytes, const uint8 EncryptionStrength, const FUncryptoolBytes& Password, TArray<uint8>& OutputBytes, FString& ErrorMessage);

	UNCRYPTOOL_API bool HMAC(const EUncryptoolHash Hash, const FUncryptoolBytes& InputBytes, const FUncryptoolBytes& Key, TArray<uint8>& OutputBytes, FString& ErrorMessage);

	/*
	* Elliptic Curve Cryptography (ECC)
	*/

	UNCRYPTOOL_API bool GenerateECKey(const EUncryptoolEllipticCurve EllipticCurve, FUncryptoolPrivateKey& PrivateKey, FUncryptoolPublicKey& PublicKey, FString& ErrorMessage);
	UNCRYPTOOL_API bool ECDSADigestSign(const FUncryptoolPrivateKey& PrivateKey, const FUncryptoolBytes& InputBytes, const EUncryptoolHash Hash, TArray<uint8>& OutputSignature, FString& ErrorMessage);
	UNCRYPTOOL_API bool ECDSADigestVerify(const FUncryptoolPublicKey& PublicKey, const FUncryptoolBytes& InputBytes, const EUncryptoolHash Hash, const FUncryptoolBytes& SignatureBytes, FString& ErrorMessage);
	UNCRYPTOOL_API bool ECDH(const FUncryptoolPrivateKey& PrivateKey, const FUncryptoolPublicKey& PublicKey, TArray<uint8>& OutputSharedSecret, FString& ErrorMessage);

	/*
	* RSA
	*/

	UNCRYPTOOL_API bool GenerateRSAKey(const int32 Bits, FUncryptoolPrivateKey& PrivateKey, FUncryptoolPublicKey& PublicKey, FString& ErrorMessage);
	UNCRYPTOOL_API bool RSADigestSign(const FUncryptoolPrivateKey& PrivateKey, const FUncryptoolBytes& InputBytes, const EUncryptoolHash Hash, TArray<uint8>& OutputSignature, FString& ErrorMessage);
	UNCRYPTOOL_API bool RSADigestVerify(const FUncryptoolPublicKey& PublicKey, const FUncryptoolBytes& InputBytes, const EUncryptoolHash Hash, const FUncryptoolBytes& SignatureBytes, FString& ErrorMessage);
	UNCRYPTOOL_API bool RSAEncrypt(const FUncryptoolPublicKey& PublicKey, const FUncryptoolBytes& InputBytes, TArray<uint8>& OutputBytes, FString& ErrorMessage);
	UNCRYPTOOL_API bool RSADecrypt(const FUncryptoolPrivateKey& PrivateKey, const FUncryptoolBytes& InputBytes, TArray<uint8>& OutputBytes, FString& ErrorMessage);

	/*
	* Keys management
	*/

	UNCRYPTOOL_API bool PEMToPrivateKey(const FUncryptoolBytes& PEMBytes, FUncryptoolPrivateKey& PrivateKey, FString& ErrorMessage);
	UNCRYPTOOL_API bool PEMToPrivateKey(const FString& PEMString, FUncryptoolPrivateKey& PrivateKey, FString& ErrorMessage);
	UNCRYPTOOL_API bool PEMToPublicKey(const FUncryptoolBytes& PEMBytes, FUncryptoolPublicKey& PublicKey, FString& ErrorMessage);
	UNCRYPTOOL_API bool PEMToPublicKey(const FString& PEMString, FUncryptoolPublicKey& PublicKey, FString& ErrorMessage);
	UNCRYPTOOL_API bool PublicKeyToPEM(const FUncryptoolPublicKey& PublicKey, TArray<uint8>& PEMBytes, FString& ErrorMessage);
	UNCRYPTOOL_API bool PublicKeyToPEM(const FUncryptoolPublicKey& PublicKey, FString& PEMString, FString& ErrorMessage);


	UNCRYPTOOL_API bool PublicKeyMatchesPrivateKey(const FUncryptoolPublicKey& PublicKey, const FUncryptoolPrivateKey& PrivateKey, FString& ErrorMessage);
	UNCRYPTOOL_API bool PublicKeyFromPrivateKey(const FUncryptoolPrivateKey& PrivateKey, FUncryptoolPublicKey& PublicKey, FString& ErrorMessage);

	/*
	* PCSC functions
	*/

	UNCRYPTOOL_API bool PCSCGetReaders(TArray<FString>& Readers, FString& ErrorMessage);
	UNCRYPTOOL_API bool PCSCGetPublicKey(const FString& Reader, const uint8 Slot, const FString& Pin, FUncryptoolPublicKey& PublicKey, FString& ErrorMessage);

	/*
	* PKCS5 functions
	*/

	UNCRYPTOOL_API bool PBKDF2HMAC(const FUncryptoolBytes& Password, const FUncryptoolBytes& Salt, const int32 Iterations, const EUncryptoolHash Hash, const int32 KeyLen, TArray<uint8>& OutputBytes, FString& ErrorMessage);
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
	static TArray<uint8> DecryptChaCha20Salted(const TArray<uint8>& Bytes, const FString& Password, const EUncryptoolKeyDerivation KeyDerivation, const int32 Iterations, bool& bSuccess, FString& ErrorMessage);

	UFUNCTION(BlueprintCallable, Category = "Uncryptool")
	static TArray<uint8> EncryptChaCha20(const TArray<uint8>& Bytes, const TArray<uint8>& Key, const TArray<uint8>& Nonce, bool& bSuccess, FString& ErrorMessage);

	UFUNCTION(BlueprintCallable, Category = "Uncryptool")
	static TArray<uint8> RandomBytes(const int32 NumBytes);

	UFUNCTION(BlueprintCallable, Category = "Uncryptool")
	static TArray<uint8> DecryptAESZIP(const TArray<uint8>& Bytes, const uint8 EncryptionStrength, const TArray<uint8>& Password, bool& bSuccess, FString& ErrorMessage);

	UFUNCTION(BlueprintCallable, Category = "Uncryptool")
	static FUncryptoolPublicKey PCSCGetPublicKey(const FString& Reader, const uint8 Slot, const FString& Pin, bool& bSuccess, FString& ErrorMessage);

	UFUNCTION(BlueprintCallable, Category = "Uncryptool")
	static TArray<FString> PCSCGetReaders(FString& ErrorMessage);
};
