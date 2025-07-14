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
	template<typename T>
	T StructNumericCast(const FUncryptoolStructArgument& StructArgument)
	{
		switch (StructArgument.GetType())
		{
		case(FUncryptoolStructArgument::Type::Bool):
			return StructArgument.Number.BoolValue ? 1 : 0;
		case(FUncryptoolStructArgument::Type::Double):
			return static_cast<T>(StructArgument.Number.DoubleValue);
		case(FUncryptoolStructArgument::Type::Float):
			return static_cast<T>(StructArgument.Number.FloatValue);
		case(FUncryptoolStructArgument::Type::Int8):
			return static_cast<T>(StructArgument.Number.Int8Value);
		case(FUncryptoolStructArgument::Type::UInt8):
			return static_cast<T>(StructArgument.Number.UInt8Value);
		case(FUncryptoolStructArgument::Type::Int16):
			return static_cast<T>(StructArgument.Number.Int16Value);
		case(FUncryptoolStructArgument::Type::UInt16):
			return static_cast<T>(StructArgument.Number.UInt16Value);
		case(FUncryptoolStructArgument::Type::Int32):
			return static_cast<T>(StructArgument.Number.Int32Value);
		case(FUncryptoolStructArgument::Type::UInt32):
			return static_cast<T>(StructArgument.Number.UInt32Value);
		case(FUncryptoolStructArgument::Type::Int64):
			return static_cast<T>(StructArgument.Number.Int64Value);
		case(FUncryptoolStructArgument::Type::UInt64):
			return static_cast<T>(StructArgument.Number.UInt64Value);
		default:
			return 0;
		}
	}
}


FUncryptoolStructArgument::operator int32() const
{
	return Uncryptool::StructNumericCast<int32>(*this);
}

FUncryptoolStructArgument::operator int16() const
{
	return Uncryptool::StructNumericCast<int16>(*this);
}

FUncryptoolStructArgument::operator uint32() const
{
	return Uncryptool::StructNumericCast<uint32>(*this);
}

FUncryptoolStructArgument::operator uint16() const
{
	return Uncryptool::StructNumericCast<uint16>(*this);
}

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

	bool HexStringToBytes(const FStringView& String, TArray<uint8>& OutputBytes)
	{
		FString CleanHexString(String);

		CleanHexString = CleanHexString.ToLower().Replace(TEXT("0x"), TEXT(""));

		uint8 CurrentValue = 0;
		bool bFirst = true;
		for (TCHAR Char : CleanHexString)
		{
			if (FChar::IsWhitespace(Char))
			{
				continue;
			}

			if (Char >= '0' && Char <= '9')
			{
				if (bFirst)
				{
					CurrentValue = (Char - '0') << 4;
				}
				else
				{
					CurrentValue |= (Char - '0') & 0x0f;
				}
			}
			else if (Char >= 'a' && Char <= 'f')
			{
				if (bFirst)
				{
					CurrentValue = (10 + (Char - 'a')) << 4;
				}
				else
				{
					CurrentValue |= (10 + (Char - 'a')) & 0x0f;
				}
			}
			else
			{
				return false;
			}

			if (!bFirst)
			{
				OutputBytes.Add(CurrentValue);
			}

			bFirst = !bFirst;
		}

		return true;
	}

	bool HexStringToBytes(const char* UTF8String, TArray<uint8>& OutputBytes)
	{
		return HexStringToBytes(FString(UTF8String), OutputBytes);
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

	template<typename T>
	bool GetStructArgumentNumber(const TArray<FUncryptoolStructArgument>& Arguments, int32& ArgumentIndex, T& Value, FString& ErrorMessage)
	{
		if (!Arguments.IsValidIndex(ArgumentIndex))
		{
			ErrorMessage = FString::Printf(TEXT("Invalid StructPack ArgumentIndex %d (%d Arguments)"), ArgumentIndex, Arguments.Num());
			return false;
		}
		if (Arguments[ArgumentIndex].GetType() == FUncryptoolStructArgument::Type::Invalid || Arguments[ArgumentIndex].GetType() == FUncryptoolStructArgument::Type::Raw)
		{
			ErrorMessage = FString::Printf(TEXT("Invalid StructPack ArgumentIndex %d (expected a Numeric)"), ArgumentIndex);
			return false;
		}
		Value = static_cast<T>(Arguments[ArgumentIndex]);
		ArgumentIndex++;
		return true;
	}

	template<typename T>
	void StructPackAppendValue(TArray<uint8>& OutputBytes, const T& Value, const bool bSwapEndianess)
	{
		const uint8* Ptr = reinterpret_cast<const uint8*>(&Value);
		if (!bSwapEndianess)
		{
			OutputBytes.Append(Ptr, sizeof(T));
		}
		else
		{
			for (int32 Index = sizeof(T) - 1; Index >= 0; Index--)
			{
				OutputBytes.Add(Ptr[Index]);
			}
		}
	}

	template<typename T>
	bool GetAndAppendStructPackNumericValue(const TArray<FUncryptoolStructArgument>& Arguments, int32& ArgumentIndex, TArray<uint8>& OutputBytes, const bool bSwapEndianess, const int32 Repeat, FString& ErrorMessage)
	{
		for (int32 RepeatIndex = 0; RepeatIndex < Repeat; RepeatIndex++)
		{
			T Value = 0;
			if (!GetStructArgumentNumber(Arguments, ArgumentIndex, Value, ErrorMessage))
			{
				return false;
			}
			StructPackAppendValue(OutputBytes, Value, bSwapEndianess);
		}
		return true;
	}

	bool StructPack(const FStringView& Format, const TArray<FUncryptoolStructArgument>& Arguments, TArray<uint8>& OutputBytes, FString& ErrorMessage)
	{
		bool bSwapEndianess = false;
		FString CurrentSymbolCounter;
		int32 CurrentArgumentIndex = 0;
		int32 Repeat = 1;

		for (int32 FormatIndex = 0; FormatIndex < Format.Len(); FormatIndex++)
		{
			const TCHAR Symbol = Format[FormatIndex];

			if (FChar::IsDigit(Symbol))
			{
				CurrentSymbolCounter += Symbol;
				continue;
			}

			if (!CurrentSymbolCounter.IsEmpty())
			{
				Repeat = FCString::Atoi(*CurrentSymbolCounter);
				CurrentSymbolCounter = "";
			}

			switch (Symbol)
			{
			case('@'):
			case('='):
			{
				bSwapEndianess = false;
				break;
			}
			case('>'):
			case('!'):
			{
#if PLATFORM_LITTLE_ENDIAN
				bSwapEndianess = true;
#else
				bSwapEndianess = false;
#endif
				break;
			}
			case('<'):
			{
#if PLATFORM_LITTLE_ENDIAN
				bSwapEndianess = false;
#else
				bSwapEndianess = true;
#endif
				break;
			}
			case('x'): // padding
				OutputBytes.AddZeroed(Repeat);
				break;
			case('i'):
			{
				if (!GetAndAppendStructPackNumericValue<int32>(Arguments, CurrentArgumentIndex, OutputBytes, bSwapEndianess, Repeat, ErrorMessage))
				{
					return false;
				}
				break;
			}
			case('I'):
			{
				if (!GetAndAppendStructPackNumericValue<uint32>(Arguments, CurrentArgumentIndex, OutputBytes, bSwapEndianess, Repeat, ErrorMessage))
				{
					return false;
				}
				break;
			}
			case('h'):
			{
				if (!GetAndAppendStructPackNumericValue<int16>(Arguments, CurrentArgumentIndex, OutputBytes, bSwapEndianess, Repeat, ErrorMessage))
				{
					return false;
				}
				break;
			}
			case('H'):
			{
				if (!GetAndAppendStructPackNumericValue<uint16>(Arguments, CurrentArgumentIndex, OutputBytes, bSwapEndianess, Repeat, ErrorMessage))
				{
					return false;
				}
				break;
			}
			default:
				ErrorMessage = FString::Printf(TEXT("Unknown StructPack Symbol %c at index %d"), Symbol, FormatIndex);
				return false;
			}

			Repeat = 1;
		}

		return true;
	}

	bool StructPack(const FString& Format, const TArray<FUncryptoolStructArgument>& Arguments, TArray<uint8>& OutputBytes, FString& ErrorMessage)
	{
		return StructPack(FStringView(Format), Arguments, OutputBytes, ErrorMessage);
	}

	bool BitFromBytes(const FUncryptoolBytes& InputBytes, const int32 Offset, uint8& BitValue)
	{
		const int32 ByteIndex = Offset / 8;
		const int32 BitIndex = Offset % 8;
		if (ByteIndex >= InputBytes.Num())
		{
			return false;
		}
		BitValue = (InputBytes.GetData()[ByteIndex] >> (7 - BitIndex)) & 0x01;
		return true;
	}

	uint32 Bech32Polymod(const FUncryptoolBytes& InputBytes)
	{
		static const uint32 Generator[] = { 0x3b6a57b2UL, 0x26508e6dUL, 0x1ea119faUL, 0x3d4233ddUL, 0x2a1462b3UL };
		uint32 Checksum = 1;

		for (int32 Index = 0; Index < InputBytes.Num(); Index++)
		{
			const uint8 Top = Checksum >> 25;
			Checksum = ((Checksum & 0x1FFFFFF) << 5) ^ InputBytes.GetData()[Index];
			for (int32 BitIndex = 0; BitIndex < 5; BitIndex++)
			{
				Checksum ^= (Top >> BitIndex) & 1 ? Generator[BitIndex] : 0;
			}
		}

		return Checksum;
	}

	bool Bech32Encode(const FUncryptoolBytes& HRP, const FUncryptoolBytes& InputBytes, TArray<uint8>& OutputBytes, FString& ErrorMessage)
	{
		static const char* Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

		TArray<uint8> Data;

		for (int32 HRPIndex = 0; HRPIndex < HRP.Num(); HRPIndex++)
		{
			Data.Add(HRP.GetData()[HRPIndex] >> 5);
		}

		Data.Add(0);

		for (int32 HRPIndex = 0; HRPIndex < HRP.Num(); HRPIndex++)
		{
			Data.Add(HRP.GetData()[HRPIndex] & 0x1F);
		}

		const int32 NumBits = InputBytes.Num() * 8;
		uint8 Accumulator = 0;
		uint8 BitCounter = 0;
		const int32 DataOffset = Data.Num();
		for (int32 BitIndex = 0; BitIndex < NumBits; BitIndex++)
		{
			uint8 Bit = 0;
			if (!BitFromBytes(InputBytes, BitIndex, Bit))
			{
				ErrorMessage = "Invalid bit stream";
				return false;
			}
			Accumulator |= Bit << (4 - BitCounter);
			BitCounter++;
			if (BitCounter >= 5)
			{
				Data.Add(Accumulator);
				BitCounter = 0;
				Accumulator = 0;
			}
		}

		if (BitCounter > 0)
		{
			Data.Add(Accumulator);
		}

		const int32 ChecksumOffset = Data.Num();
		Data.AddZeroed(6);

		const uint32 Polymod = Bech32Polymod(Data) ^ 1;

		// checksum
		for (int32 ChecksumIndex = 0; ChecksumIndex < 6; ChecksumIndex++)
		{
			Data[ChecksumOffset + ChecksumIndex] = (Polymod >> (5 * (5 - ChecksumIndex))) & 0x1F;
		}

		// encode
		OutputBytes.Empty();
		OutputBytes.Append(HRP.GetData(), HRP.Num());
		OutputBytes.Add('1');

		for (int32 Index = DataOffset; Index < Data.Num(); Index++)
		{
			OutputBytes.Add(Charset[Data[Index]]);
		}

		return true;
	}
}