// Copyright 2025 - Roberto De Ioris

#include "UncryptoolFunctionLibrary.h"

#define UI UI_ST
THIRD_PARTY_INCLUDES_START
#include "openssl/err.h"
#include "openssl/rand.h"
THIRD_PARTY_INCLUDES_END
#undef UI

namespace Uncryptool
{

	FString GetOpenSSLError()
	{
		return ERR_error_string(ERR_get_error(), nullptr);
	}

	TArray<uint8> UTF8StringToBytes(const FStringView& String)
	{
		FTCHARToUTF8 UTF8String(String.GetData());
		TArray<uint8> Output;
		Output.Append(reinterpret_cast<const uint8*>(UTF8String.Get()), UTF8String.Length());

		return Output;
	}

	FString BytesToUTF8String(const FUncryptoolBytes& Bytes)
	{
		FUTF8ToTCHAR Converter = FUTF8ToTCHAR(reinterpret_cast<const char*>(Bytes.GetData()), Bytes.Num());
		return FString(Converter.Length(), Converter.Get());
	}

	FString BytesToHexString(const FUncryptoolBytes& Bytes)
	{
		FString HexString;
		for (int32 ByteIndex = 0; ByteIndex < Bytes.Num(); ByteIndex++)
		{
			HexString += FString::Printf(TEXT("%02x"), Bytes.GetData()[ByteIndex]);
		}
		return HexString;
	}

	bool RandomBytes(const int32 NumBytes, TArray<uint8>& OutputBytes)
	{
		OutputBytes.SetNum(NumBytes);
		return RAND_bytes(OutputBytes.GetData(), NumBytes) > 0;
	}

	bool RandomBytesFill(TArray<uint8>& Bytes)
	{
		return RandomBytes(Bytes.Num(), Bytes);
	}

}