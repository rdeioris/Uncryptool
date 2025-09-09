// Copyright 2025 - Roberto De Ioris

#if WITH_DEV_AUTOMATION_TESTS
#include "UncryptoolFunctionLibrary.h"
#include "Misc/AutomationTest.h"

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsKeychain_StoreAndLoad, "Uncryptool.FunctionalTests.Keychain.StoreAndLoad", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsKeychain_StoreAndLoad::RunTest(const FString& Parameters)
{
	FString ErrorMessage;
	TArray<uint8> EncryptedBlob;
	bool bSuccess = Uncryptool::KeychainStore("Hello World", EncryptedBlob, "Test", ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);

	FString Description;
	TArray<uint8> DescryptedBlob;
	bSuccess = Uncryptool::KeychainLoad(EncryptedBlob, DescryptedBlob, Description, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);

	TestEqual("Description == \"Test\"", Description, "Test");

	TestEqual("DescryptedBlob == \"Hello World\"", Uncryptool::BytesToUTF8String(DescryptedBlob), "Hello World");

	return true;
}

#endif