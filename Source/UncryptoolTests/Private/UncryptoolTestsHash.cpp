// Copyright 2025 - Roberto De Ioris

#if WITH_DEV_AUTOMATION_TESTS
#include "UncryptoolFunctionLibrary.h"
#include "Misc/AutomationTest.h"

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBPHash_Sha256, "Uncryptool.UnitTests.BP.Hash.Sha256", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBPHash_Sha256::RunTest(const FString& Parameters)
{
	return TestEqual("Hello World == a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
		UUncryptoolFunctionLibrary::SHA256HexDigest(UUncryptoolFunctionLibrary::UTF8StringToBytes("Hello World")),
		"a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e");
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBPHash_Sha512, "Uncryptool.UnitTests.BP.Hash.Sha512", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBPHash_Sha512::RunTest(const FString& Parameters)
{
	return TestEqual("Hello World == 2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b",
		UUncryptoolFunctionLibrary::SHA512HexDigest(UUncryptoolFunctionLibrary::UTF8StringToBytes("Hello World")),
		"2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b");
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBPHash_Ripemd160, "Uncryptool.UnitTests.BP.Hash.Ripemd160", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBPHash_Ripemd160::RunTest(const FString& Parameters)
{
	return TestEqual("Hello World == a830d7beb04eb7549ce990fb7dc962e499a27230",
		UUncryptoolFunctionLibrary::RIPEMD160HexDigest(UUncryptoolFunctionLibrary::UTF8StringToBytes("Hello World")),
		"a830d7beb04eb7549ce990fb7dc962e499a27230");
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsHash_Hash, "Uncryptool.UnitTests.Hash.Hash", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsHash_Hash::RunTest(const FString& Parameters)
{
	TArray<uint8> OutputBytes;
	FString ErrorMessage;
	bool bSuccess = Uncryptool::Hash(EUncryptoolHash::SHA256, UUncryptoolFunctionLibrary::UTF8StringToBytes("Hello World"), OutputBytes, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);

	return TestEqual("Hello World == a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
		Uncryptool::BytesToHexString(OutputBytes),
		"a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e");
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsHash_HMAC, "Uncryptool.UnitTests.Hash.HMAC", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsHash_HMAC::RunTest(const FString& Parameters)
{
	TArray<uint8> OutputBytes;
	FString ErrorMessage;
	bool bSuccess = Uncryptool::HMAC(EUncryptoolHash::SHA256, "Hello World", "test", OutputBytes, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);

	return TestEqual("Hello World == 1a90645c09ac62827b12e8ed501b9d502f1df962c84f77107453a6df7124f82f",
		Uncryptool::BytesToHexString(OutputBytes),
		"1a90645c09ac62827b12e8ed501b9d502f1df962c84f77107453a6df7124f82f");
}

#endif
