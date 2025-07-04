// Copyright 2025 - Roberto De Ioris

#if WITH_DEV_AUTOMATION_TESTS
#include "UncryptoolFunctionLibrary.h"
#include "Misc/AutomationTest.h"

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsChaCha20_EncryptChaCha20, "Uncryptool.UnitTests.ChaCha20.EncryptChaCha20", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsChaCha20_EncryptChaCha20::RunTest(const FString& Parameters)
{
	const TArray<uint8> Key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
	const TArray<uint8> Nonce = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	bool bSuccess = false;
	FString ErrorMessage;
	TArray<uint8> Encrypted = UUncryptoolFunctionLibrary::EncryptChaCha20(UUncryptoolFunctionLibrary::UTF8StringToBytes("Hello World"), Key, Nonce, bSuccess, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestTrue("ErrorMessage == \"\"", ErrorMessage.IsEmpty());

	TArray<uint8> Decrypted = UUncryptoolFunctionLibrary::DecryptChaCha20(Encrypted, Key, Nonce, bSuccess, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestTrue("ErrorMessage == \"\"", ErrorMessage.IsEmpty());

	return TestEqual("Decrypted == \"Hello World\"", UUncryptoolFunctionLibrary::BytesToUTF8String(Decrypted), "Hello World");
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsChaCha20_EncryptChaCha20WrongKey, "Uncryptool.UnitTests.ChaCha20.EncryptChaCha20WrongKey", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsChaCha20_EncryptChaCha20WrongKey::RunTest(const FString& Parameters)
{
	const TArray<uint8> Key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e };
	const TArray<uint8> Nonce = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	bool bSuccess = false;
	FString ErrorMessage;
	TArray<uint8> Encrypted = UUncryptoolFunctionLibrary::EncryptChaCha20(UUncryptoolFunctionLibrary::UTF8StringToBytes("Hello World"), Key, Nonce, bSuccess, ErrorMessage);

	TestTrue("bSuccess == false", !bSuccess);
	return TestEqual("ErrorMessage == \"Invalid Key size for ChaCha20\"", ErrorMessage, "Invalid Key size for ChaCha20");
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsChaCha20_EncryptChaCha20WrongNonce, "Uncryptool.UnitTests.ChaCha20.EncryptChaCha20WrongNonce", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsChaCha20_EncryptChaCha20WrongNonce::RunTest(const FString& Parameters)
{
	const TArray<uint8> Key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
	const TArray<uint8> Nonce = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e };
	bool bSuccess = false;
	FString ErrorMessage;
	TArray<uint8> Encrypted = UUncryptoolFunctionLibrary::EncryptChaCha20(UUncryptoolFunctionLibrary::UTF8StringToBytes("Hello World"), Key, Nonce, bSuccess, ErrorMessage);

	TestTrue("bSuccess == false", !bSuccess);
	return TestEqual("ErrorMessage == \"Invalid Nonce size for ChaCha20\"", ErrorMessage, "Invalid Nonce size for ChaCha20");
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsChaCha20_EncryptChaCha20EmptyKey, "Uncryptool.UnitTests.ChaCha20.EncryptChaCha20EmptyKey", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsChaCha20_EncryptChaCha20EmptyKey::RunTest(const FString& Parameters)
{
	const TArray<uint8> Key;
	const TArray<uint8> Nonce = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	bool bSuccess = false;
	FString ErrorMessage;
	TArray<uint8> Encrypted = UUncryptoolFunctionLibrary::EncryptChaCha20(UUncryptoolFunctionLibrary::UTF8StringToBytes("Hello World"), Key, Nonce, bSuccess, ErrorMessage);

	TestTrue("bSuccess == false", !bSuccess);
	return TestEqual("ErrorMessage == \"Invalid Key size for ChaCha20\"", ErrorMessage, "Invalid Key size for ChaCha20");
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsChaCha20_EncryptChaCha20EmptyNonce, "Uncryptool.UnitTests.ChaCha20.EncryptChaCha20EmptyNonce", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsChaCha20_EncryptChaCha20EmptyNonce::RunTest(const FString& Parameters)
{
	const TArray<uint8> Key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
	const TArray<uint8> Nonce;
	bool bSuccess = false;
	FString ErrorMessage;
	TArray<uint8> Encrypted = UUncryptoolFunctionLibrary::EncryptChaCha20(UUncryptoolFunctionLibrary::UTF8StringToBytes("Hello World"), Key, Nonce, bSuccess, ErrorMessage);

	TestTrue("bSuccess == false", !bSuccess);
	return TestEqual("ErrorMessage == \"Invalid Nonce size for ChaCha20\"", ErrorMessage, "Invalid Nonce size for ChaCha20");
}

#endif
