// Copyright 2025 - Roberto De Ioris

#if WITH_DEV_AUTOMATION_TESTS
#include "UncryptoolFunctionLibrary.h"
#include "Misc/AutomationTest.h"

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsPKCS5_PBKDF2HMAC_BIP39, "Uncryptool.UnitTests.PKCS5.PBKDF2HMAC.BIP39", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsPKCS5_PBKDF2HMAC_BIP39::RunTest(const FString& Parameters)
{
	TArray<uint8> OutputBytes;
	FString ErrorMessage;
	const bool bSuccess = Uncryptool::PBKDF2HMAC("abandon amount liar amount expire adjust cage candy arch gather drum buyer", "mnemonic", 2048, EUncryptoolHash::SHA512, 64, OutputBytes, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestEqual(
		"OutputBytes == {55, 121, 176, 65, 250, 180, 37, 233, 192, 253, 85, 132, 107, 42, 3, 233, 163, 136, 251, 18, 120, 64, 103, 189, 142, 189, 180, 100, 194, 87, 74, 5, 188, 199, 168, 235, 84, 215, 178, 162, 200, 66, 15, 246, 15, 99, 7, 34, 234, 81, 50, 210, 134, 5, 219, 201, 150, 200, 202, 125, 122, 131, 17, 192}",
		OutputBytes,
		{ 55, 121, 176, 65, 250, 180, 37, 233, 192, 253, 85, 132, 107, 42, 3, 233, 163, 136, 251, 18, 120, 64, 103, 189, 142, 189, 180, 100, 194, 87, 74, 5, 188, 199, 168, 235, 84, 215, 178, 162, 200, 66, 15, 246, 15, 99, 7, 34, 234, 81, 50, 210, 134, 5, 219, 201, 150, 200, 202, 125, 122, 131, 17, 192 }
	);

	return true;
}

#endif