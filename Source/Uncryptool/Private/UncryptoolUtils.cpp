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
		if (Offset >= InputBytes.Num())
		{
			return false;
		}
		return (InputBytes.GetData()[ByteIndex] >> (7 - BitIndex)) & 0x01;
	}
}