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
	Context = BN_CTX_new();
}

bool FUncryptoolBigNum::SetString(const FString& String)
{
	if (!BN_dec2bn(reinterpret_cast<BIGNUM**>(&NativeBigNum), TCHAR_TO_ANSI(*String)))
	{
		return false;
	}
	return true;
}

bool FUncryptoolBigNum::SetHexString(const FString& HexString)
{
	TArray<uint8> StringBytes;
	if (!Uncryptool::HexStringToBytes(HexString, StringBytes))
	{
		return false;
	}
	return SetString(Uncryptool::BytesToUTF8String(StringBytes));
}

bool FUncryptoolBigNum::SetInt64(const int64 Value)
{
	if (Value >= 0)
	{
		if (!BN_set_word(GetNativeBigNum<BIGNUM>(), static_cast<BN_ULONG>(Value)))
		{
			return false;
		}
	}
	else
	{
		if (!BN_set_word(GetNativeBigNum<BIGNUM>(), static_cast<BN_ULONG>(-Value)))
		{
			return false;
		}
		BN_set_negative(GetNativeBigNum<BIGNUM>(), 1);
	}
	return true;
}

bool FUncryptoolBigNum::SetRand(const int32 Bits)
{
	if (!BN_rand(GetNativeBigNum<BIGNUM>(), Bits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
	{
		return false;
	}
	return true;
}

void* FUncryptoolBigNum::GetContext() const
{
	return Context;
}

FUncryptoolBigNum FUncryptoolBigNum::Add(const FUncryptoolBigNum& Other) const
{
	FUncryptoolBigNum Result;
	BN_add(Result.GetNativeBigNum<BIGNUM>(), GetNativeBigNum<BIGNUM>(), Other.GetNativeBigNum<BIGNUM>());
	return Result;
}

FUncryptoolBigNum FUncryptoolBigNum::ModAdd(const FUncryptoolBigNum& Other, const FUncryptoolBigNum& Modulo) const
{
	FUncryptoolBigNum Result;
	BN_mod_add(Result.GetNativeBigNum<BIGNUM>(), GetNativeBigNum<BIGNUM>(), Other.GetNativeBigNum<BIGNUM>(), Modulo.GetNativeBigNum<BIGNUM>(), GetContext<BN_CTX>());
	return Result;
}

FUncryptoolBigNum FUncryptoolBigNum::Sub(const FUncryptoolBigNum& Other) const
{
	FUncryptoolBigNum Result;
	BN_sub(Result.GetNativeBigNum<BIGNUM>(), GetNativeBigNum<BIGNUM>(), Other.GetNativeBigNum<BIGNUM>());
	return Result;
}

FUncryptoolBigNum FUncryptoolBigNum::ModSub(const FUncryptoolBigNum& Other, const FUncryptoolBigNum& Modulo) const
{
	FUncryptoolBigNum Result;
	BN_mod_sub(Result.GetNativeBigNum<BIGNUM>(), GetNativeBigNum<BIGNUM>(), Other.GetNativeBigNum<BIGNUM>(), Modulo.GetNativeBigNum<BIGNUM>(), GetContext<BN_CTX>());
	return Result;
}

FUncryptoolBigNum FUncryptoolBigNum::Mul(const FUncryptoolBigNum& Other) const
{
	FUncryptoolBigNum Result;
	BN_mul(Result.GetNativeBigNum<BIGNUM>(), GetNativeBigNum<BIGNUM>(), Other.GetNativeBigNum<BIGNUM>(), GetContext<BN_CTX>());
	return Result;
}

FUncryptoolBigNum FUncryptoolBigNum::ModMul(const FUncryptoolBigNum& Other, const FUncryptoolBigNum& Modulo) const
{
	FUncryptoolBigNum Result;
	BN_mod_mul(Result.GetNativeBigNum<BIGNUM>(), GetNativeBigNum<BIGNUM>(), Other.GetNativeBigNum<BIGNUM>(), Modulo.GetNativeBigNum<BIGNUM>(), GetContext<BN_CTX>());
	return Result;
}

FUncryptoolBigNum FUncryptoolBigNum::Exp(const FUncryptoolBigNum& Other) const
{
	FUncryptoolBigNum Result;
	BN_exp(Result.GetNativeBigNum<BIGNUM>(), GetNativeBigNum<BIGNUM>(), Other.GetNativeBigNum<BIGNUM>(), GetContext<BN_CTX>());
	return Result;
}

FUncryptoolBigNum FUncryptoolBigNum::ModExp(const FUncryptoolBigNum& Other, const FUncryptoolBigNum& Modulo) const
{
	FUncryptoolBigNum Result;
	BN_mod_exp(Result.GetNativeBigNum<BIGNUM>(), GetNativeBigNum<BIGNUM>(), Other.GetNativeBigNum<BIGNUM>(), Modulo.GetNativeBigNum<BIGNUM>(), GetContext<BN_CTX>());
	return Result;
}

FUncryptoolBigNum FUncryptoolBigNum::Mod(const FUncryptoolBigNum& Other) const
{
	FUncryptoolBigNum Result;
	BN_mod(Result.GetNativeBigNum<BIGNUM>(), GetNativeBigNum<BIGNUM>(), Other.GetNativeBigNum<BIGNUM>(), GetContext<BN_CTX>());
	return Result;
}

FUncryptoolBigNum FUncryptoolBigNum::Sqr() const
{
	FUncryptoolBigNum Result;
	BN_sqr(Result.GetNativeBigNum<BIGNUM>(), GetNativeBigNum<BIGNUM>(), GetContext<BN_CTX>());
	return Result;
}

bool FUncryptoolBigNum::Cmp(const FUncryptoolBigNum& Other) const
{
	return BN_cmp(GetNativeBigNum<BIGNUM>(), Other.GetNativeBigNum<BIGNUM>()) == 0;
}

int32 FUncryptoolBigNum::NumBits() const
{
	return BN_num_bits(GetNativeBigNum<BIGNUM>());
}

int32 FUncryptoolBigNum::NumBytes() const
{
	return BN_num_bytes(GetNativeBigNum<BIGNUM>());
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
	if (Context)
	{
		BN_CTX_free(GetContext<BN_CTX>());
	}

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
