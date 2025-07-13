// Copyright 2025 - Roberto De Ioris

#if WITH_DEV_AUTOMATION_TESTS
#include "UncryptoolFunctionLibrary.h"
#include "Misc/AutomationTest.h"

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsECDH_X25519, "Uncryptool.UnitTests.ECDH.X25519", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsECDH_X25519::RunTest(const FString& Parameters)
{
	FUncryptoolPrivateKey PrivateKeyAlice;
	FUncryptoolPublicKey PublicKeyAlice;
	FUncryptoolPrivateKey PrivateKeyBob;
	FUncryptoolPublicKey PublicKeyBob;

	FString ErrorMessage;

	bool bSuccess = Uncryptool::GenerateECKey(EUncryptoolEllipticCurve::X25519, PrivateKeyAlice, PublicKeyAlice, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	bSuccess = Uncryptool::GenerateECKey(EUncryptoolEllipticCurve::X25519, PrivateKeyBob, PublicKeyBob, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);

	TArray<uint8> SharedSecretAlice;
	bSuccess = Uncryptool::ECDH(PrivateKeyAlice, PublicKeyBob, SharedSecretAlice, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);

	TArray<uint8> SharedSecretBob;
	bSuccess = Uncryptool::ECDH(PrivateKeyBob, PublicKeyAlice, SharedSecretBob, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);

	TestEqual("SharedSecretAlice == SharedSecretBob", SharedSecretAlice, SharedSecretBob);

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsECDH_SECP256K1, "Uncryptool.UnitTests.ECDH.SECP256K1", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsECDH_SECP256K1::RunTest(const FString& Parameters)
{
	FUncryptoolPrivateKey PrivateKeyAlice;
	FUncryptoolPublicKey PublicKeyAlice;
	FUncryptoolPrivateKey PrivateKeyBob;
	FUncryptoolPublicKey PublicKeyBob;

	FString ErrorMessage;

	bool bSuccess = Uncryptool::GenerateECKey(EUncryptoolEllipticCurve::SECP256K1, PrivateKeyAlice, PublicKeyAlice, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	bSuccess = Uncryptool::GenerateECKey(EUncryptoolEllipticCurve::SECP256K1, PrivateKeyBob, PublicKeyBob, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);

	TArray<uint8> SharedSecretAlice;
	bSuccess = Uncryptool::ECDH(PrivateKeyAlice, PublicKeyBob, SharedSecretAlice, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);

	TArray<uint8> SharedSecretBob;
	bSuccess = Uncryptool::ECDH(PrivateKeyBob, PublicKeyAlice, SharedSecretBob, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);

	TestEqual("SharedSecretAlice == SharedSecretBob", SharedSecretAlice, SharedSecretBob);

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsECDH_PRIME256V1, "Uncryptool.UnitTests.ECDH.PRIME256V1", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsECDH_PRIME256V1::RunTest(const FString& Parameters)
{
	FUncryptoolPrivateKey PrivateKeyAlice;
	FUncryptoolPublicKey PublicKeyAlice;
	FUncryptoolPrivateKey PrivateKeyBob;
	FUncryptoolPublicKey PublicKeyBob;

	FString ErrorMessage;

	bool bSuccess = Uncryptool::GenerateECKey(EUncryptoolEllipticCurve::PRIME256V1, PrivateKeyAlice, PublicKeyAlice, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	bSuccess = Uncryptool::GenerateECKey(EUncryptoolEllipticCurve::PRIME256V1, PrivateKeyBob, PublicKeyBob, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);

	TArray<uint8> SharedSecretAlice;
	bSuccess = Uncryptool::ECDH(PrivateKeyAlice, PublicKeyBob, SharedSecretAlice, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);

	TArray<uint8> SharedSecretBob;
	bSuccess = Uncryptool::ECDH(PrivateKeyBob, PublicKeyAlice, SharedSecretBob, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);

	TestEqual("SharedSecretAlice == SharedSecretBob", SharedSecretAlice, SharedSecretBob);

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsECDH_Invalid, "Uncryptool.UnitTests.ECDH.Invalid", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsECDH_Invalid::RunTest(const FString& Parameters)
{
	FUncryptoolPrivateKey PrivateKeyAlice;
	FUncryptoolPublicKey PublicKeyAlice;
	FUncryptoolPrivateKey PrivateKeyBob;
	FUncryptoolPublicKey PublicKeyBob;

	FString ErrorMessage;

	TArray<uint8> SharedSecret;
	bool bSuccess = Uncryptool::ECDH(PrivateKeyAlice, PublicKeyBob, SharedSecret, ErrorMessage);
	TestTrue("bSuccess == false", !bSuccess);

	bSuccess = Uncryptool::ECDH(PrivateKeyBob, PublicKeyAlice, SharedSecret, ErrorMessage);
	TestTrue("bSuccess == false", !bSuccess);

	return true;
}

#endif
