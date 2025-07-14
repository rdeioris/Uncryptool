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

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsUtils_Bech32Encode, "Uncryptool.UnitTests.Utils.Bech32Encode", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsUtils_Bech32Encode::RunTest(const FString& Parameters)
{
	TArray<uint8> Data;
	for (int32 Index = 0; Index < 256; Index++)
	{
		Data.Add(Index);
	}
	TArray<uint8> OutputBytes;
	FString ErrorMessage;
	bool bSuccess = Uncryptool::Bech32Encode("age", Data, OutputBytes, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestEqual("Bech32Encode == age1...", Uncryptool::BytesToUTF8String(OutputBytes),
		"age1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqgfzyvjz2f389q5j52ev95hz7vp3xgengdfkxuurjw3m8s7nu06qg9pyx3z9ger5sj22fdxy6nj02pg4y56524t9wkzetfd4ch27tasxzcnrv3jkvemgd94xkmrddehhqutjwd682anh0puh57mu04l8lqyps2pcfpvxs7ygnz5t3jxcarusjxff89y4j6te3xv6nwwfm85l5zs69gay5kn2029f4246etdw47ctrv4nkj6mddachxath09ah6lupswzc0zvt3k8eryu4j7veh8vl5x36tfaf4wk6lvdnkkmmnwaahlqu83w8e89umn73602a0kwmmh07rcl9ul57hm0078eltalel07luqk05e0");
	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsUtils_Bech32EncodeUpper, "Uncryptool.UnitTests.Utils.Bech32EncodeUpper", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsUtils_Bech32EncodeUpper::RunTest(const FString& Parameters)
{
	TArray<uint8> Data;
	for (int32 Index = 0; Index < 256; Index++)
	{
		Data.Add(Index);
	}
	TArray<uint8> OutputBytes;
	FString ErrorMessage;
	bool bSuccess = Uncryptool::Bech32Encode("AGE", Data, OutputBytes, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestEqual("Bech32Encode == AGE1...", Uncryptool::BytesToUTF8String(OutputBytes),
		"AGE1QQQSYQCYQ5RQWZQFPG9SCRGWPUGPZYSNZS23V9CCRYDPK8QARC0JQGFZYVJZ2F389Q5J52EV95HZ7VP3XGENGDFKXUURJW3M8S7NU06QG9PYX3Z9GER5SJ22FDXY6NJ02PG4Y56524T9WKZETFD4CH27TASXZCNRV3JKVEMGD94XKMRDDEHHQUTJWD682ANH0PUH57MU04L8LQYPS2PCFPVXS7YGNZ5T3JXCARUSJXFF89Y4J6TE3XV6NWWFM85L5ZS69GAY5KN2029F4246ETDW47CTRV4NKJ6MDDACHXATH09AH6LUPSWZC0ZVT3K8ERYU4J7VEH8VL5X36TFAF4WK6LVDNKKMMNWAAHLQU83W8E89UMN73602A0KWMMH07RCL9UL57HM0078ELTALEL07LUQK05E0");
	return true;
}


IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsUtils_Bech32Decode, "Uncryptool.UnitTests.Utils.Bech32Decode", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsUtils_Bech32Decode::RunTest(const FString& Parameters)
{
	TArray<uint8> Data;
	for (int32 Index = 0; Index < 256; Index++)
	{
		Data.Add(Index);
	}

	const char* Address = "age1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqgfzyvjz2f389q5j52ev95hz7vp3xgengdfkxuurjw3m8s7nu06qg9pyx3z9ger5sj22fdxy6nj02pg4y56524t9wkzetfd4ch27tasxzcnrv3jkvemgd94xkmrddehhqutjwd682anh0puh57mu04l8lqyps2pcfpvxs7ygnz5t3jxcarusjxff89y4j6te3xv6nwwfm85l5zs69gay5kn2029f4246etdw47ctrv4nkj6mddachxath09ah6lupswzc0zvt3k8eryu4j7veh8vl5x36tfaf4wk6lvdnkkmmnwaahlqu83w8e89umn73602a0kwmmh07rcl9ul57hm0078eltalel07luqk05e0";

	TArray<uint8> OutputBytes;
	FString ErrorMessage;
	bool bSuccess = Uncryptool::Bech32Decode("age", Address, OutputBytes, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestEqual("Bech32Decode == Data", OutputBytes, Data);
	return true;
}

#endif
