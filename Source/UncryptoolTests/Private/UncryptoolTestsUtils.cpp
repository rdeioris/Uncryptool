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

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsUtils_StructPackInt32, "Uncryptool.UnitTests.Utils.StructPackInt32", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsUtils_StructPackInt32::RunTest(const FString& Parameters)
{
	TArray<uint8> OutputBytes;
	FString ErrorMessage;
	bool bSuccess = Uncryptool::StructPack("<iii", { 1, 2, 3 }, OutputBytes, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestEqual("OutputBytes == { 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0 }", OutputBytes, { 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0 });

	OutputBytes.Empty();
	bSuccess = Uncryptool::StructPack(">iii", { 1, 2, 3 }, OutputBytes, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestEqual("OutputBytes == { 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3 }", OutputBytes, { 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3 });

	OutputBytes.Empty();
	bSuccess = Uncryptool::StructPack(">3i", { 1, 2, 3 }, OutputBytes, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestEqual("OutputBytes == { 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3 }", OutputBytes, { 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3 });

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsUtils_StructPackPadding, "Uncryptool.UnitTests.Utils.StructPackPadding", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsUtils_StructPackPadding::RunTest(const FString& Parameters)
{
	TArray<uint8> OutputBytes;
	FString ErrorMessage;
	bool bSuccess = Uncryptool::StructPack("xxx", { }, OutputBytes, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestEqual("OutputBytes == { 0, 0, 0 }", OutputBytes, { 0, 0, 0 });

	OutputBytes.Empty();
	bSuccess = Uncryptool::StructPack("5x", { 1, 2, 3 }, OutputBytes, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestEqual("OutputBytes == { 0, 0, 0, 0, 0 }", OutputBytes, { 0, 0, 0, 0, 0 });

	OutputBytes.Empty();
	bSuccess = Uncryptool::StructPack("5x", {}, OutputBytes, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestEqual("OutputBytes == { 0, 0, 0, 0, 0 }", OutputBytes, { 0, 0, 0, 0, 0 });

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsUtils_StructPackInt16, "Uncryptool.UnitTests.Utils.StructPackInt16", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsUtils_StructPackInt16::RunTest(const FString& Parameters)
{
	TArray<uint8> OutputBytes;
	FString ErrorMessage;
	bool bSuccess = Uncryptool::StructPack("<hhh", { 1, 2, 3 }, OutputBytes, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestEqual("OutputBytes == { 1, 0, 2, 0, 3, 0 }", OutputBytes, { 1, 0, 2, 0, 3, 0 });

	OutputBytes.Empty();
	bSuccess = Uncryptool::StructPack(">hhh", { 1, 2, 3 }, OutputBytes, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestEqual("OutputBytes == { 0, 1, 0, 2, 0, 3 }", OutputBytes, { 0, 1, 0, 2, 0, 3 });

	OutputBytes.Empty();
	bSuccess = Uncryptool::StructPack(">2h", { 1, 2 }, OutputBytes, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestEqual("OutputBytes == { 0, 1, 0, 2 }", OutputBytes, { 0, 1, 0, 2 });

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsUtils_StructPackUInt16, "Uncryptool.UnitTests.Utils.StructPackUInt16", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsUtils_StructPackUInt16::RunTest(const FString& Parameters)
{
	TArray<uint8> OutputBytes;
	FString ErrorMessage;
	bool bSuccess = Uncryptool::StructPack("<HHH", { 1, 2, 3 }, OutputBytes, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestEqual("OutputBytes == { 1, 0, 2, 0, 3, 0 }", OutputBytes, { 1, 0, 2, 0, 3, 0 });

	OutputBytes.Empty();
	bSuccess = Uncryptool::StructPack(">HHH", { 1, 2, 3 }, OutputBytes, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestEqual("OutputBytes == { 0, 1, 0, 2, 0, 3 }", OutputBytes, { 0, 1, 0, 2, 0, 3 });

	OutputBytes.Empty();
	bSuccess = Uncryptool::StructPack(">2H", { 1, 2 }, OutputBytes, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestEqual("OutputBytes == { 0, 1, 0, 2 }", OutputBytes, { 0, 1, 0, 2 });

	OutputBytes.Empty();
	bSuccess = Uncryptool::StructPack(">2H", { -1, -2 }, OutputBytes, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestEqual("OutputBytes == { 0xff, 0xff, 0xff, 0xfe }", OutputBytes, { 0xff, 0xff, 0xff, 0xfe });

	return true;
}

#endif
