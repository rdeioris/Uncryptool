// Copyright 2025 - Roberto De Ioris

#if WITH_DEV_AUTOMATION_TESTS
#include "UncryptoolFunctionLibrary.h"
#include "Misc/AutomationTest.h"

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBigNum_ToString, "Uncryptool.UnitTests.BigNum.ToString", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBigNum_ToString::RunTest(const FString& Parameters)
{
	FUncryptoolBigNum BigNum;
	BigNum.SetInt64(17);

	TestEqual("BigNum.ToString() == \"17\"", BigNum.ToString(), "17");

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBigNum_SetString, "Uncryptool.UnitTests.BigNum.SetString", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBigNum_SetString::RunTest(const FString& Parameters)
{
	FUncryptoolBigNum BigNum;
	BigNum.SetString("17171717");

	TestEqual("BigNum.ToString() == \"17171717\"", BigNum.ToString(), "17171717");

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBigNum_IsOnCurve, "Uncryptool.FunctionalTests.BigNum.IsOnCurve", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBigNum_IsOnCurve::RunTest(const FString& Parameters)
{
	FUncryptoolBigNum A;
	FUncryptoolBigNum B;
	FUncryptoolBigNum P;

	A.SetInt64(2);
	B.SetInt64(2);
	P.SetInt64(17);

	FUncryptoolBigNum PX;
	FUncryptoolBigNum PY;

	PX.SetInt64(5);
	PY.SetInt64(1);

	auto IsOnCurve = [](const FUncryptoolBigNum& X, const FUncryptoolBigNum& Y, const FUncryptoolBigNum& A, const FUncryptoolBigNum& B, const FUncryptoolBigNum& P)
		{
			// Y^2 = X^3 + AX + B
			const FUncryptoolBigNum Y2 = Y.Sqr().Mod(P);
			const FUncryptoolBigNum X3 = X.Sqr().ModMul(X, P);
			const FUncryptoolBigNum AX = A.ModMul(X, P);
			const FUncryptoolBigNum X3AXB = X3.ModAdd(AX, P).ModAdd(B, P);
			return Y2.Cmp(X3AXB);
		};

	TestTrue("IsOnCurve(5, 1, 2, 2, 17) == true", IsOnCurve(PX, PY, A, B, P));

	PX.SetInt64(1);
	PY.SetInt64(2);

	TestFalse("IsOnCurve(1, 2, 2, 2, 17) == false", IsOnCurve(PX, PY, A, B, P));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBigNum_Add, "Uncryptool.UnitTests.BigNum.Add", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBigNum_Add::RunTest(const FString& Parameters)
{
	FUncryptoolBigNum A;
	A.SetString("1");

	FUncryptoolBigNum B;
	B.SetInt64(2);

	TestEqual("A + B == \"3\"", A.Add(B).ToString(), "3");

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBigNum_ModAdd, "Uncryptool.UnitTests.BigNum.ModAdd", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBigNum_ModAdd::RunTest(const FString& Parameters)
{
	FUncryptoolBigNum A;
	A.SetString("1");

	FUncryptoolBigNum B;
	B.SetInt64(2);

	FUncryptoolBigNum P;
	P.SetInt64(2);

	TestEqual("(A + B) mod(P) == \"1\"", A.ModAdd(B, P).ToString(), "1");

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBigNum_Mul, "Uncryptool.UnitTests.BigNum.Mul", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBigNum_Mul::RunTest(const FString& Parameters)
{
	FUncryptoolBigNum A;
	A.SetString("5");

	FUncryptoolBigNum B;
	B.SetInt64(2);

	TestEqual("A * B == \"10\"", A.Mul(B).ToString(), "10");

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBigNum_ModMul, "Uncryptool.UnitTests.BigNum.ModMul", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBigNum_ModMul::RunTest(const FString& Parameters)
{
	FUncryptoolBigNum A;
	A.SetString("5");

	FUncryptoolBigNum B;
	B.SetInt64(3);

	FUncryptoolBigNum P;
	P.SetInt64(10);

	TestEqual("(A * B) mod(P) == \"5\"", A.ModMul(B, P).ToString(), "5");

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBigNum_Sub, "Uncryptool.UnitTests.BigNum.Sub", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBigNum_Sub::RunTest(const FString& Parameters)
{
	FUncryptoolBigNum A;
	A.SetString("1");

	FUncryptoolBigNum B;
	B.SetInt64(2);

	TestEqual("A - B == \"-1\"", A.Sub(B).ToString(), "-1");

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBigNum_ModSub, "Uncryptool.UnitTests.BigNum.ModSub", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBigNum_ModSub::RunTest(const FString& Parameters)
{
	FUncryptoolBigNum A;
	A.SetString("1");

	FUncryptoolBigNum B;
	B.SetInt64(2);

	FUncryptoolBigNum P;
	P.SetInt64(2);

	TestEqual("(A + B) mod(P) == \"1\"", A.ModSub(B, P).ToString(), "1");

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBigNum_Sqr, "Uncryptool.UnitTests.BigNum.Sqr", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBigNum_Sqr::RunTest(const FString& Parameters)
{
	FUncryptoolBigNum A;
	A.SetString("9");

	TestEqual("A * A == \"81\"", A.Sqr().ToString(), "81");

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBigNum_NumBits, "Uncryptool.UnitTests.BigNum.NumBits", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBigNum_NumBits::RunTest(const FString& Parameters)
{
	FUncryptoolBigNum A;
	A.SetString("1");

	TestEqual("NumBits(1) == 1", A.NumBits(), 1);

	A.SetInt64(3);
	TestEqual("NumBits(3) == 2", A.NumBits(), 2);

	return true;
}

#endif