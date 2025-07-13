// Copyright 2025 - Roberto De Ioris

#include "UncryptoolFunctionLibrary.h"

TArray<uint8> UUncryptoolFunctionLibrary::UTF8StringToBytes(const FString& String)
{
	return Uncryptool::UTF8StringToBytes(String);
}

FString UUncryptoolFunctionLibrary::BytesToUTF8String(const TArray<uint8>& Bytes)
{
	return Uncryptool::BytesToUTF8String(Bytes);
}

FString UUncryptoolFunctionLibrary::BytesToHexString(const TArray<uint8>& Bytes)
{
	return Uncryptool::BytesToHexString(Bytes);
}

FString UUncryptoolFunctionLibrary::SHA256HexDigest(const TArray<uint8>& Bytes)
{
	return Uncryptool::SHA256HexDigest(Bytes);
}

FString UUncryptoolFunctionLibrary::SHA512HexDigest(const TArray<uint8>& Bytes)
{
	return Uncryptool::SHA512HexDigest(Bytes);
}

FString UUncryptoolFunctionLibrary::RIPEMD160HexDigest(const TArray<uint8>& Bytes)
{
	return Uncryptool::RIPEMD160HexDigest(Bytes);
}

TArray<uint8> UUncryptoolFunctionLibrary::DecryptAES256CBC(const TArray<uint8>& Bytes, const TArray<uint8>& Key, const TArray<uint8>& Iv, bool& bSuccess, FString& ErrorMessage)
{
	TArray<uint8> OutputBytes;
	bSuccess = Uncryptool::DecryptAES256CBC(Bytes, Key, Iv, OutputBytes, ErrorMessage);
	return OutputBytes;
}

TArray<uint8> UUncryptoolFunctionLibrary::EncryptAES256CBC(const TArray<uint8>& Bytes, const TArray<uint8>& Key, const TArray<uint8>& Iv, bool& bSuccess, FString& ErrorMessage)
{
	TArray<uint8> OutputBytes;
	bSuccess = Uncryptool::EncryptAES256CBC(Bytes, Key, Iv, OutputBytes, ErrorMessage);
	return OutputBytes;
}

TArray<uint8> UUncryptoolFunctionLibrary::DecryptChaCha20(const TArray<uint8>& Bytes, const TArray<uint8>& Key, const TArray<uint8>& Nonce, bool& bSuccess, FString& ErrorMessage)
{
	TArray<uint8> OutputBytes;
	bSuccess = Uncryptool::DecryptChaCha20(Bytes, Key, Nonce, OutputBytes, ErrorMessage);
	return OutputBytes;
}

TArray<uint8> UUncryptoolFunctionLibrary::DecryptChaCha20Salted(const TArray<uint8>& Bytes, const FString& Password, const EUncryptoolKeyDerivation KeyDerivation, const int32 Iterations, bool& bSuccess, FString& ErrorMessage)
{
	TArray<uint8> OutputBytes;
	bSuccess = Uncryptool::DecryptChaCha20Salted(Bytes, UTF8StringToBytes(Password), KeyDerivation, Iterations, OutputBytes, ErrorMessage);
	return OutputBytes;
}

TArray<uint8> UUncryptoolFunctionLibrary::EncryptChaCha20(const TArray<uint8>& Bytes, const TArray<uint8>& Key, const TArray<uint8>& Nonce, bool& bSuccess, FString& ErrorMessage)
{
	TArray<uint8> OutputBytes;
	bSuccess = Uncryptool::EncryptChaCha20(Bytes, Key, Nonce, OutputBytes, ErrorMessage);
	return OutputBytes;
}

TArray<uint8> UUncryptoolFunctionLibrary::RandomBytes(const int32 NumBytes)
{
	TArray<uint8> Output;
	if (!Uncryptool::RandomBytes(NumBytes, Output))
	{
		return {};
	}

	return Output;
}

TArray<uint8> UUncryptoolFunctionLibrary::DecryptAESZIP(const TArray<uint8>& Bytes, const uint8 EncryptionStrength, const TArray<uint8>& Password, bool& bSuccess, FString& ErrorMessage)
{
	TArray<uint8> OutputBytes;
	bSuccess = Uncryptool::DecryptAESZIP(Bytes, EncryptionStrength, Password, OutputBytes, ErrorMessage);
	return OutputBytes;
}