// Copyright 2025 - Roberto De Ioris

#if WITH_DEV_AUTOMATION_TESTS
#include "UncryptoolFunctionLibrary.h"
#include "Misc/AutomationTest.h"

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsRSA_GenerateKey, "Uncryptool.UnitTests.RSA.GenerateKey", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsRSA_GenerateKey::RunTest(const FString& Parameters)
{
	FUncryptoolPrivateKey PrivateKey;
	FUncryptoolPublicKey PublicKey;
	FString ErrorMessage;

	bool bSuccess = Uncryptool::GenerateRSAKey(0, PrivateKey, PublicKey, ErrorMessage);
	TestFalse("bSuccess == false", bSuccess);

	bSuccess = Uncryptool::GenerateRSAKey(-1, PrivateKey, PublicKey, ErrorMessage);
	TestFalse("bSuccess == false", bSuccess);

	bSuccess = Uncryptool::GenerateRSAKey(-8, PrivateKey, PublicKey, ErrorMessage);
	TestFalse("bSuccess == false", bSuccess);

	bSuccess = Uncryptool::GenerateRSAKey(511, PrivateKey, PublicKey, ErrorMessage);
	TestFalse("bSuccess == false", bSuccess);

	bSuccess = Uncryptool::GenerateRSAKey(8, PrivateKey, PublicKey, ErrorMessage);
	TestFalse("bSuccess == false", bSuccess);

	bSuccess = Uncryptool::GenerateRSAKey(512, PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Type == RSA", PrivateKey.Type, EUncryptoolKey::RSA);
	TestEqual("PublicKey.Type == RSA", PublicKey.Type, EUncryptoolKey::RSA);
	TestEqual("PrivateKey.Bits == 512", PrivateKey.Bits, 512);
	TestEqual("PublicKey.Bits == 512", PublicKey.Bits, 512);
	TestTrue("PublicKeyMatchesPrivateKey == true", Uncryptool::PublicKeyMatchesPrivateKey(PublicKey, PrivateKey, ErrorMessage));

	bSuccess = Uncryptool::GenerateRSAKey(1024, PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Type == RSA", PrivateKey.Type, EUncryptoolKey::RSA);
	TestEqual("PublicKey.Type == RSA", PublicKey.Type, EUncryptoolKey::RSA);
	TestEqual("PrivateKey.Bits == 1024", PrivateKey.Bits, 1024);
	TestEqual("PublicKey.Bits == 1024", PublicKey.Bits, 1024);
	TestTrue("PublicKeyMatchesPrivateKey == true", Uncryptool::PublicKeyMatchesPrivateKey(PublicKey, PrivateKey, ErrorMessage));

	bSuccess = Uncryptool::GenerateRSAKey(2048, PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Type == RSA", PrivateKey.Type, EUncryptoolKey::RSA);
	TestEqual("PublicKey.Type == RSA", PublicKey.Type, EUncryptoolKey::RSA);
	TestEqual("PrivateKey.Bits == 2048", PrivateKey.Bits, 2048);
	TestEqual("PublicKey.Bits == 2048", PublicKey.Bits, 2048);
	TestTrue("PublicKeyMatchesPrivateKey == true", Uncryptool::PublicKeyMatchesPrivateKey(PublicKey, PrivateKey, ErrorMessage));

	bSuccess = Uncryptool::GenerateRSAKey(4096, PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Type == RSA", PrivateKey.Type, EUncryptoolKey::RSA);
	TestEqual("PublicKey.Type == RSA", PublicKey.Type, EUncryptoolKey::RSA);
	TestEqual("PrivateKey.Bits == 4096", PrivateKey.Bits, 4096);
	TestEqual("PublicKey.Bits == 4096", PublicKey.Bits, 4096);
	TestTrue("PublicKeyMatchesPrivateKey == true", Uncryptool::PublicKeyMatchesPrivateKey(PublicKey, PrivateKey, ErrorMessage));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsRSA_SignAndVerify, "Uncryptool.UnitTests.RSA.SignAndVerify", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsRSA_SignAndVerify::RunTest(const FString& Parameters)
{
	FUncryptoolPrivateKey PrivateKey;
	FUncryptoolPublicKey PublicKey;
	FString ErrorMessage;

	bool bSuccess = Uncryptool::GenerateRSAKey(2048, PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Bits == 2048", PrivateKey.Bits, 2048);
	TestEqual("PublicKey.Bits == 2048", PublicKey.Bits, 2048);

	TArray<uint8> Signature;
	bSuccess = Uncryptool::RSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::SHA256, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestTrue("Signature.Num() > 64", Signature.Num() > 64);

	bSuccess = Uncryptool::ECDSADigestVerify(PublicKey, "Hello World", EUncryptoolHash::SHA256, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsRSA_SignAndVerifyRIPEMD160, "Uncryptool.UnitTests.RSA.SignAndVerifyRIPEMD160", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsRSA_SignAndVerifyRIPEMD160::RunTest(const FString& Parameters)
{
	FUncryptoolPrivateKey PrivateKey;
	FUncryptoolPublicKey PublicKey;
	FString ErrorMessage;

	bool bSuccess = Uncryptool::GenerateRSAKey(2048, PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Bits == 2048", PrivateKey.Bits, 2048);
	TestEqual("PublicKey.Bits == 2048", PublicKey.Bits, 2048);

	TArray<uint8> Signature;
	bSuccess = Uncryptool::RSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::RIPEMD160, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("Signature.Num() == 256", Signature.Num(), 256);

	bSuccess = Uncryptool::RSADigestVerify(PublicKey, "Hello World", EUncryptoolHash::RIPEMD160, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsRSA_SignHash, "Uncryptool.UnitTests.RSA.SignHash", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsRSA_SignHash::RunTest(const FString& Parameters)
{
	FUncryptoolPrivateKey PrivateKey;
	FUncryptoolPublicKey PublicKey;
	FString ErrorMessage;

	bool bSuccess = Uncryptool::GenerateRSAKey(2048, PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Bits == 2048", PrivateKey.Bits, 2048);
	TestEqual("PublicKey.Bits == 2048", PublicKey.Bits, 2048);

	TArray<uint8> Signature;
	bSuccess = Uncryptool::RSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::SHA256, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("Signature.Num() == 256", Signature.Num(), 256);

	bSuccess = Uncryptool::RSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::SHA512, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("Signature.Num() == 256", Signature.Num(), 256);

	bSuccess = Uncryptool::RSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::BLAKE2b512, Signature, ErrorMessage);
	TestFalse("bSuccess == false", bSuccess);

	bSuccess = Uncryptool::RSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::BLAKE2s256, Signature, ErrorMessage);
	TestFalse("bSuccess == false", bSuccess);

	bSuccess = Uncryptool::RSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::RIPEMD160, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("Signature.Num() == 256", Signature.Num(), 256);

	bSuccess = Uncryptool::RSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::SHA1, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("Signature.Num() == 256", Signature.Num(), 256);

	bSuccess = Uncryptool::RSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::SHA224, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("Signature.Num() == 256", Signature.Num(), 256);

	bSuccess = Uncryptool::RSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::SHA384, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("Signature.Num() == 256", Signature.Num(), 256);

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsRSA_EncryptAndDecrypt, "Uncryptool.UnitTests.RSA.EncryptAndDecrypt", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsRSA_EncryptAndDecrypt::RunTest(const FString& Parameters)
{
	FUncryptoolPrivateKey PrivateKey;
	FUncryptoolPublicKey PublicKey;
	FString ErrorMessage;

	bool bSuccess = Uncryptool::GenerateRSAKey(2048, PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Bits == 2048", PrivateKey.Bits, 2048);
	TestEqual("PublicKey.Bits == 2048", PublicKey.Bits, 2048);

	TArray<uint8> Encrypted;
	bSuccess = Uncryptool::RSAEncrypt(PublicKey, "Hello World", Encrypted, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestTrue("ErrorMessage == """, ErrorMessage.IsEmpty());

	TArray<uint8> Decrypted;
	bSuccess = Uncryptool::RSADecrypt(PrivateKey, Encrypted, Decrypted, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("Decrypted == \"Hello World\"", Uncryptool::BytesToUTF8String(Decrypted), "Hello World");

	return true;
}

#endif
