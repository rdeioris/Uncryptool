// Copyright 2025 - Roberto De Ioris

#if WITH_DEV_AUTOMATION_TESTS
#include "UncryptoolFunctionLibrary.h"
#include "Misc/AutomationTest.h"

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsECDSA_GenerateKey, "Uncryptool.UnitTests.ECDSA.GenerateKey", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsECDSA_GenerateKey::RunTest(const FString& Parameters)
{
	FUncryptoolPrivateKey PrivateKey;
	FUncryptoolPublicKey PublicKey;
	FString ErrorMessage;

	bool bSuccess = Uncryptool::GenerateECKey(EUncryptoolEllipticCurve::PRIME256V1, PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Bits == 256", PrivateKey.Bits, 256);
	TestEqual("PublicKey.Bits == 256", PublicKey.Bits, 256);
	TestTrue("PublicKeyMatchesPrivateKey == true", Uncryptool::PublicKeyMatchesPrivateKey(PublicKey, PrivateKey, ErrorMessage));

	bSuccess = Uncryptool::GenerateECKey(EUncryptoolEllipticCurve::SECP256K1, PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Bits == 256", PrivateKey.Bits, 256);
	TestEqual("PublicKey.Bits == 256", PublicKey.Bits, 256);
	TestTrue("PublicKeyMatchesPrivateKey == true", Uncryptool::PublicKeyMatchesPrivateKey(PublicKey, PrivateKey, ErrorMessage));

	bSuccess = Uncryptool::GenerateECKey(EUncryptoolEllipticCurve::SECP384R1, PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Bits == 384", PrivateKey.Bits, 384);
	TestEqual("PublicKey.Bits == 384", PublicKey.Bits, 384);
	TestTrue("PublicKeyMatchesPrivateKey == true", Uncryptool::PublicKeyMatchesPrivateKey(PublicKey, PrivateKey, ErrorMessage));

	bSuccess = Uncryptool::GenerateECKey(EUncryptoolEllipticCurve::SECP521R1, PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Bits == 521", PrivateKey.Bits, 521);
	TestEqual("PublicKey.Bits == 521", PublicKey.Bits, 521);
	TestTrue("PublicKeyMatchesPrivateKey == true", Uncryptool::PublicKeyMatchesPrivateKey(PublicKey, PrivateKey, ErrorMessage));

	bSuccess = Uncryptool::GenerateECKey(EUncryptoolEllipticCurve::X25519, PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Bits == 253", PrivateKey.Bits, 253);
	TestEqual("PublicKey.Bits == 253", PublicKey.Bits, 253);
	TestTrue("PublicKeyMatchesPrivateKey == true", Uncryptool::PublicKeyMatchesPrivateKey(PublicKey, PrivateKey, ErrorMessage));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsECDSA_SignAndVerify, "Uncryptool.UnitTests.ECDSA.SignAndVerify", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsECDSA_SignAndVerify::RunTest(const FString& Parameters)
{
	FUncryptoolPrivateKey PrivateKey;
	FUncryptoolPublicKey PublicKey;
	FString ErrorMessage;

	bool bSuccess = Uncryptool::GenerateECKey(EUncryptoolEllipticCurve::SECP256K1, PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Bits == 256", PrivateKey.Bits, 256);
	TestEqual("PublicKey.Bits == 256", PublicKey.Bits, 256);

	TArray<uint8> Signature;
	bSuccess = Uncryptool::ECDSADigestSign(PrivateKey, { 1,2,3 }, EUncryptoolHash::SHA256, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestTrue("Signature.Num() > 64", Signature.Num() > 64);

	bSuccess = Uncryptool::ECDSADigestVerify(PublicKey, { 1,2,3 }, EUncryptoolHash::SHA256, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);

	bSuccess = Uncryptool::ECDSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::SHA256, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestTrue("Signature.Num() > 64", Signature.Num() > 64);

	bSuccess = Uncryptool::ECDSADigestVerify(PublicKey, "Hello World", EUncryptoolHash::SHA256, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsECDSA_SignHash, "Uncryptool.UnitTests.ECDSA.SignHash", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsECDSA_SignHash::RunTest(const FString& Parameters)
{
	FUncryptoolPrivateKey PrivateKey;
	FUncryptoolPublicKey PublicKey;
	FString ErrorMessage;

	bool bSuccess = Uncryptool::GenerateECKey(EUncryptoolEllipticCurve::SECP256K1, PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Bits == 256", PrivateKey.Bits, 256);
	TestEqual("PublicKey.Bits == 256", PublicKey.Bits, 256);

	TArray<uint8> Signature;
	bSuccess = Uncryptool::ECDSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::SHA256, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestTrue("Signature.Num() > 64", Signature.Num() > 64);

	bSuccess = Uncryptool::ECDSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::SHA512, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestTrue("Signature.Num() > 64", Signature.Num() > 64);

	bSuccess = Uncryptool::ECDSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::SHA384, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestTrue("Signature.Num() > 64", Signature.Num() > 64);

	bSuccess = Uncryptool::ECDSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::RIPEMD160, Signature, ErrorMessage);
	TestFalse("bSuccess == false", bSuccess);

	bSuccess = Uncryptool::ECDSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::SHA1, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestTrue("Signature.Num() > 64", Signature.Num() > 64);

	bSuccess = Uncryptool::ECDSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::SHA224, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestTrue("Signature.Num() > 64", Signature.Num() > 64);

	bSuccess = Uncryptool::ECDSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::BLAKE2b512, Signature, ErrorMessage);
	TestFalse("bSuccess == false", bSuccess);

	bSuccess = Uncryptool::ECDSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::BLAKE2s256, Signature, ErrorMessage);
	TestFalse("bSuccess == false", bSuccess);

	return true;
}

#endif
