// Copyright 2025 - Roberto De Ioris

#if WITH_DEV_AUTOMATION_TESTS
#include "UncryptoolFunctionLibrary.h"
#include "Misc/AutomationTest.h"

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBigNum_ToString, "Uncryptool.UnitTests.BigNum.ToString", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBigNum_ToString::RunTest(const FString& Parameters)
{
	FUncryptoolBigNum BigNum;
	BigNum.FromInt64(17);

	TestEqual("BigNum.ToString() == \"17\"", BigNum.ToString(), "17");

	return true;
}

#endif