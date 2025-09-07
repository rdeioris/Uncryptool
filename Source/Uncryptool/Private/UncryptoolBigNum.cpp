// Copyright 2025 - Roberto De Ioris

#include "UncryptoolFunctionLibrary.h"

#define UI UI_ST
THIRD_PARTY_INCLUDES_START
#include "openssl/bn.h"
THIRD_PARTY_INCLUDES_END
#undef UI

FUncryptoolBigNum::FUncryptoolBigNum()
{
	NativeBigNum = BN_new();
}

bool FUncryptoolBigNum::FromString(const FString& String)
{
	if (!BN_dec2bn(reinterpret_cast<BIGNUM**>(&NativeBigNum), TCHAR_TO_ANSI(*String)))
	{
		return false;
	}
	return true;
}

bool FUncryptoolBigNum::FromInt64(const int64 Value)
{
	if (Value >= 0)
	{
		if (!BN_set_word(reinterpret_cast<BIGNUM*>(NativeBigNum), static_cast<BN_ULONG>(Value)))
		{
			return false;
		}
	}
	else
	{
		if (!BN_set_word(reinterpret_cast<BIGNUM*>(NativeBigNum), static_cast<BN_ULONG>(-Value)))
		{
			return false;
		}
		BN_set_negative(reinterpret_cast<BIGNUM*>(NativeBigNum), 1);
	}
	return true;
}

FString FUncryptoolBigNum::ToString() const
{
	char* CString = BN_bn2dec(reinterpret_cast<const BIGNUM*>(NativeBigNum));
	if (!CString)
	{
		return "";
	}

	FString Result = ANSI_TO_TCHAR(CString);
	OPENSSL_free(CString);

	return Result;
}

FUncryptoolBigNum::~FUncryptoolBigNum()
{
	if (NativeBigNum)
	{
		BN_clear_free(reinterpret_cast<BIGNUM*>(NativeBigNum));
	}
}

FUncryptoolBigNum::FUncryptoolBigNum(const FUncryptoolBigNum& Other)
{
	if (Other.NativeBigNum)
	{
		NativeBigNum = BN_dup(reinterpret_cast<BIGNUM*>(Other.NativeBigNum));
	}
}

FUncryptoolBigNum& FUncryptoolBigNum::operator=(const FUncryptoolBigNum& Other)
{
	if (Other.NativeBigNum)
	{
		NativeBigNum = BN_dup(reinterpret_cast<BIGNUM*>(Other.NativeBigNum));
	}
	return *this;
}

FUncryptoolBigNum::FUncryptoolBigNum(FUncryptoolBigNum&& Other)
{
	if (Other.NativeBigNum)
	{
		NativeBigNum = Other.NativeBigNum;
		Other.NativeBigNum = nullptr;
	}
}

void* FUncryptoolBigNum::GetNativeBigNum() const
{
	return NativeBigNum;
}
