// Copyright 2025 - Roberto De Ioris

#include "UncryptoolFunctionLibrary.h"
#include "Uncryptool.h"

#define UI UI_ST
THIRD_PARTY_INCLUDES_START
#include "openssl/bn.h"
THIRD_PARTY_INCLUDES_END
#undef UI

FUncryptoolBigNum::FUncryptoolBigNum()
{
	BigNumPtr = BN_new();
}

FUncryptoolBigNum::~FUncryptoolBigNum()
{
	if (BigNumPtr)
	{
		BN_clear_free(reinterpret_cast<BIGNUM*>(BigNumPtr));
	}
}

FUncryptoolBigNum::FUncryptoolBigNum(const FUncryptoolBigNum& Other)
{
	if (Other.BigNumPtr)
	{
		BigNumPtr = BN_dup(reinterpret_cast<BIGNUM*>(Other.BigNumPtr));
	}
}

FUncryptoolBigNum& FUncryptoolBigNum::operator=(const FUncryptoolBigNum& Other)
{
	if (Other.BigNumPtr)
	{
		BigNumPtr = BN_dup(reinterpret_cast<BIGNUM*>(Other.BigNumPtr));
	}
	return *this;
}

FUncryptoolBigNum::FUncryptoolBigNum(FUncryptoolBigNum&& Other)
{
	if (Other.BigNumPtr)
	{
		BigNumPtr = Other.BigNumPtr;
		Other.BigNumPtr = nullptr;
	}
}