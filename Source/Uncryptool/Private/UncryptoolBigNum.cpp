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
