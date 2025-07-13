// Copyright 2025 - Roberto De Ioris

#if WITH_DEV_AUTOMATION_TESTS
#include "UncryptoolFunctionLibrary.h"
#include "Misc/AutomationTest.h"

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBPChaCha20_EncryptChaCha20, "Uncryptool.UnitTests.BP.ChaCha20.EncryptChaCha20", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBPChaCha20_EncryptChaCha20::RunTest(const FString& Parameters)
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

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBPChaCha20_EncryptChaCha20WrongKey, "Uncryptool.UnitTests.BP.ChaCha20.EncryptChaCha20WrongKey", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBPChaCha20_EncryptChaCha20WrongKey::RunTest(const FString& Parameters)
{
	const TArray<uint8> Key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e };
	const TArray<uint8> Nonce = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	bool bSuccess = false;
	FString ErrorMessage;
	TArray<uint8> Encrypted = UUncryptoolFunctionLibrary::EncryptChaCha20(UUncryptoolFunctionLibrary::UTF8StringToBytes("Hello World"), Key, Nonce, bSuccess, ErrorMessage);

	TestTrue("bSuccess == false", !bSuccess);
	return TestEqual("ErrorMessage == \"Invalid Key size for ChaCha20\"", ErrorMessage, "Invalid Key size for ChaCha20");
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBPChaCha20_EncryptChaCha20WrongNonce, "Uncryptool.UnitTests.BP.ChaCha20.EncryptChaCha20WrongNonce", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBPChaCha20_EncryptChaCha20WrongNonce::RunTest(const FString& Parameters)
{
	const TArray<uint8> Key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
	const TArray<uint8> Nonce = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e };
	bool bSuccess = false;
	FString ErrorMessage;
	TArray<uint8> Encrypted = UUncryptoolFunctionLibrary::EncryptChaCha20(UUncryptoolFunctionLibrary::UTF8StringToBytes("Hello World"), Key, Nonce, bSuccess, ErrorMessage);

	TestTrue("bSuccess == false", !bSuccess);
	return TestEqual("ErrorMessage == \"Invalid Nonce size for ChaCha20\"", ErrorMessage, "Invalid Nonce size for ChaCha20");
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBPChaCha20_EncryptChaCha20EmptyKey, "Uncryptool.UnitTests.BP.ChaCha20.EncryptChaCha20EmptyKey", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBPChaCha20_EncryptChaCha20EmptyKey::RunTest(const FString& Parameters)
{
	const TArray<uint8> Key;
	const TArray<uint8> Nonce = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	bool bSuccess = false;
	FString ErrorMessage;
	TArray<uint8> Encrypted = UUncryptoolFunctionLibrary::EncryptChaCha20(UUncryptoolFunctionLibrary::UTF8StringToBytes("Hello World"), Key, Nonce, bSuccess, ErrorMessage);

	TestTrue("bSuccess == false", !bSuccess);
	return TestEqual("ErrorMessage == \"Invalid Key size for ChaCha20\"", ErrorMessage, "Invalid Key size for ChaCha20");
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBPChaCha20_EncryptChaCha20EmptyNonce, "Uncryptool.UnitTests.BP.ChaCha20.EncryptChaCha20EmptyNonce", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBPChaCha20_EncryptChaCha20EmptyNonce::RunTest(const FString& Parameters)
{
	const TArray<uint8> Key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
	const TArray<uint8> Nonce;
	bool bSuccess = false;
	FString ErrorMessage;
	TArray<uint8> Encrypted = UUncryptoolFunctionLibrary::EncryptChaCha20(UUncryptoolFunctionLibrary::UTF8StringToBytes("Hello World"), Key, Nonce, bSuccess, ErrorMessage);

	TestTrue("bSuccess == false", !bSuccess);
	return TestEqual("ErrorMessage == \"Invalid Nonce size for ChaCha20\"", ErrorMessage, "Invalid Nonce size for ChaCha20");
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBPChaCha20_DecryptChaCha20Salted, "Uncryptool.UnitTests.ChaCha20.DecryptChaCha20Salted", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBPChaCha20_DecryptChaCha20Salted::RunTest(const FString& Parameters)
{
	TArray<uint8> EncryptedBytes;
	Uncryptool::HexStringToBytes("53 61 6c 74 65 64 5f 5f 20 fb 06 8f 59 9d 0f 9d 3c d0 31 8e 0c d0 39 57 e4 73 a4", EncryptedBytes);
	
	TArray<uint8> DecryptedBytes;
	FString ErrorMessage;
	const bool bSuccess = Uncryptool::DecryptChaCha20Salted(EncryptedBytes, "test", EUncryptoolKeyDerivation::PBKDF2, 10000, DecryptedBytes, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestTrue("ErrorMessage == \"\"", ErrorMessage.IsEmpty());

	return TestEqual("Decrypted == \"Hello World\"", UUncryptoolFunctionLibrary::BytesToUTF8String(DecryptedBytes), "Hello World");
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBPChaCha20_DecryptChaCha20SaltedIter, "Uncryptool.UnitTests.ChaCha20.DecryptChaCha20SaltedIter", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBPChaCha20_DecryptChaCha20SaltedIter::RunTest(const FString& Parameters)
{
	TArray<uint8> EncryptedBytes;
	Uncryptool::HexStringToBytes("53 61 6c 74 65 64 5f 5f 25 84 b0 af d0 64 7d f8 f0 34 34 57 79 e4 5d ab af 94 bf", EncryptedBytes);

	TArray<uint8> DecryptedBytes;
	FString ErrorMessage;
	const bool bSuccess = Uncryptool::DecryptChaCha20Salted(EncryptedBytes, "test", EUncryptoolKeyDerivation::PBKDF2, 17, DecryptedBytes, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestTrue("ErrorMessage == \"\"", ErrorMessage.IsEmpty());

	return TestEqual("Decrypted == \"Hello World\"", UUncryptoolFunctionLibrary::BytesToUTF8String(DecryptedBytes), "Hello World");
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsBPChaCha20_DecryptChaCha20SaltedLegacy, "Uncryptool.UnitTests.ChaCha20.DecryptChaCha20SaltedLegacy", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsBPChaCha20_DecryptChaCha20SaltedLegacy::RunTest(const FString& Parameters)
{
	TArray<uint8> EncryptedBytes;
	Uncryptool::HexStringToBytes("53 61 6c 74 65 64 5f 5f 73 c3 30 e3 3f b1 41 83 db 10 b1 cf 11 cc 04 24 42 20 69", EncryptedBytes);

	TArray<uint8> DecryptedBytes;
	FString ErrorMessage;
	const bool bSuccess = Uncryptool::DecryptChaCha20Salted(EncryptedBytes, "test", EUncryptoolKeyDerivation::Legacy, 1, DecryptedBytes, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestTrue("ErrorMessage == \"\"", ErrorMessage.IsEmpty());

	return TestEqual("Decrypted == \"Hello World\"", UUncryptoolFunctionLibrary::BytesToUTF8String(DecryptedBytes), "Hello World");
}


#endif
