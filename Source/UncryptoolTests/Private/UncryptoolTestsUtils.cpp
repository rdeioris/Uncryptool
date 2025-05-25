// Copyright 2025 - Roberto De Ioris

#if WITH_DEV_AUTOMATION_TESTS
#include "Uncryptool.h"
#include "UncryptoolFunctionLibrary.h"
#include "Misc/AutomationTest.h"

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsUtils_BytesToHexString, "Uncryptool.UnitTests.Utils.BytesToHexString", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsUtils_BytesToHexString::RunTest(const FString& Parameters)
{
	return TestEqual("{ 1, 2, 3, 4 } == 01020304",
		Uncryptool::BytesToHexString({ 1, 2, 3, 4 }),
		"01020304");
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsUtils_BytesToUTF8String, "Uncryptool.UnitTests.Utils.BytesToUTF8String", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsUtils_BytesToUTF8String::RunTest(const FString& Parameters)
{
	return TestEqual("{ 0x68, 0x65, 0x6c, 0x6c, 0x6f } == hello",
		Uncryptool::BytesToUTF8String({ 0x68,  0x65, 0x6c, 0x6c, 0x6f }),
		"hello");
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsUtils_RandomBytes, "Uncryptool.UnitTests.Utils.RandomBytes", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsUtils_RandomBytes::RunTest(const FString& Parameters)
{
	TArray<uint8> RandomBytes;
	const bool bSuccess = Uncryptool::RandomBytes(1024, RandomBytes);
	TestTrue("bSuccess == true", bSuccess);

	return TestEqual("RandomBytes.Num() == 1024", RandomBytes.Num(), 1024);
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBPUtils_RandomBytes, "Uncryptool.UnitTests.BP.Utils.RandomBytes", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBPUtils_RandomBytes::RunTest(const FString& Parameters)
{
	TArray<uint8> RandomBytes = UUncryptoolFunctionLibrary::RandomBytes(1024);
	return TestEqual("RandomBytes.Num() == 1024", RandomBytes.Num(), 1024);
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBPUtils_BytesToHexString, "Uncryptool.UnitTests.BP.Utils.BytesToHexString", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBPUtils_BytesToHexString::RunTest(const FString& Parameters)
{
	return TestEqual("{ 1, 2, 3, 4 } == 01020304",
		UUncryptoolFunctionLibrary::BytesToHexString({ 1, 2, 3, 4 }),
		"01020304");
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBPUtils_BytesToUTF8String, "Uncryptool.UnitTests.BP.Utils.BytesToUTF8String", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBPUtils_BytesToUTF8String::RunTest(const FString& Parameters)
{
	return TestEqual("{ 0x68, 0x65, 0x6c, 0x6c, 0x6f } == hello",
		UUncryptoolFunctionLibrary::BytesToUTF8String({ 0x68,  0x65, 0x6c, 0x6c, 0x6f }),
		"hello");
}

#endif
