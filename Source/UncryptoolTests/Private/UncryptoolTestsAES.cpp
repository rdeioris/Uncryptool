// Copyright 2025 - Roberto De Ioris

#if WITH_DEV_AUTOMATION_TESTS
#include "UncryptoolFunctionLibrary.h"
#include "Misc/AutomationTest.h"

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsAES_EncryptAES256CBC, "Uncryptool.UnitTests.AES.EncryptAES256CBC", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsAES_EncryptAES256CBC::RunTest(const FString& Parameters)
{
	const TArray<uint8> Key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
	const TArray<uint8> Iv = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	bool bSuccess = false;
	FString ErrorMessage;
	TArray<uint8> Encrypted = UUncryptoolFunctionLibrary::EncryptAES256CBC(UUncryptoolFunctionLibrary::UTF8StringToBytes("Hello World"), Key, Iv, bSuccess, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestTrue("ErrorMessage == \"\"", ErrorMessage.IsEmpty());

	TArray<uint8> Decrypted = UUncryptoolFunctionLibrary::DecryptAES256CBC(Encrypted, Key, Iv, bSuccess, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestTrue("ErrorMessage == \"\"", ErrorMessage.IsEmpty());

	return TestEqual("Decrypted == \"Hello World\"", UUncryptoolFunctionLibrary::BytesToUTF8String(Decrypted), "Hello World");
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsAES_EncryptAES256CBCWrongKey, "Uncryptool.UnitTests.AES.EncryptAES256CBCWrongKey", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsAES_EncryptAES256CBCWrongKey::RunTest(const FString& Parameters)
{
	const TArray<uint8> Key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e };
	const TArray<uint8> Iv = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	bool bSuccess = false;
	FString ErrorMessage;
	TArray<uint8> Encrypted = UUncryptoolFunctionLibrary::EncryptAES256CBC(UUncryptoolFunctionLibrary::UTF8StringToBytes("Hello World"), Key, Iv, bSuccess, ErrorMessage);

	TestTrue("bSuccess == false", !bSuccess);
	return TestEqual("ErrorMessage == \"Invalid Key size for AES256\"", ErrorMessage, "Invalid Key size for AES256");
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsAES_EncryptAES256CBCWrongIv, "Uncryptool.UnitTests.AES.EncryptAES256CBCWrongIv", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsAES_EncryptAES256CBCWrongIv::RunTest(const FString& Parameters)
{
	const TArray<uint8> Key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
	const TArray<uint8> Iv = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e };
	bool bSuccess = false;
	FString ErrorMessage;
	TArray<uint8> Encrypted = UUncryptoolFunctionLibrary::EncryptAES256CBC(UUncryptoolFunctionLibrary::UTF8StringToBytes("Hello World"), Key, Iv, bSuccess, ErrorMessage);

	TestTrue("bSuccess == false", !bSuccess);
	return TestEqual("ErrorMessage == \"Invalid Iv size for AES256\"", ErrorMessage, "Invalid Iv size for AES256");
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsAES_EncryptAES256CBCEmptyKey, "Uncryptool.UnitTests.AES.EncryptAES256CBCEmptyKey", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsAES_EncryptAES256CBCEmptyKey::RunTest(const FString& Parameters)
{
	const TArray<uint8> Key;
	const TArray<uint8> Iv = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	bool bSuccess = false;
	FString ErrorMessage;
	TArray<uint8> Encrypted = UUncryptoolFunctionLibrary::EncryptAES256CBC(UUncryptoolFunctionLibrary::UTF8StringToBytes("Hello World"), Key, Iv, bSuccess, ErrorMessage);

	TestTrue("bSuccess == false", !bSuccess);
	return TestEqual("ErrorMessage == \"Invalid Key size for AES256\"", ErrorMessage, "Invalid Key size for AES256");
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsAES_EncryptAES256CBCEmptyIv, "Uncryptool.UnitTests.AES.EncryptAES256CBCEmptyIv", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsAES_EncryptAES256CBCEmptyIv::RunTest(const FString& Parameters)
{
	const TArray<uint8> Key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
	const TArray<uint8> Iv;
	bool bSuccess = false;
	FString ErrorMessage;
	TArray<uint8> Encrypted = UUncryptoolFunctionLibrary::EncryptAES256CBC(UUncryptoolFunctionLibrary::UTF8StringToBytes("Hello World"), Key, Iv, bSuccess, ErrorMessage);

	TestTrue("bSuccess == false", !bSuccess);
	return TestEqual("ErrorMessage == \"Invalid Iv size for AES256\"", ErrorMessage, "Invalid Iv size for AES256");
}

#endif
