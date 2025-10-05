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
	TestEqual("Signature.Num() == 64", Signature.Num(), 64);

	bSuccess = Uncryptool::ECDSADigestVerify(PublicKey, { 1,2,3 }, EUncryptoolHash::SHA256, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);

	bSuccess = Uncryptool::ECDSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::SHA256, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("Signature.Num() == 64", Signature.Num(), 64);

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
	TestEqual("Signature.Num() == 64", Signature.Num(), 64);

	bSuccess = Uncryptool::ECDSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::SHA512, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("Signature.Num() == 128", Signature.Num(), 128);

	bSuccess = Uncryptool::ECDSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::SHA384, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("Signature.Num() == 96", Signature.Num(), 96);

	bSuccess = Uncryptool::ECDSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::RIPEMD160, Signature, ErrorMessage);
	TestFalse("bSuccess == false", bSuccess);

	bSuccess = Uncryptool::ECDSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::SHA1, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("Signature.Num() == 40", Signature.Num(), 40);

	bSuccess = Uncryptool::ECDSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::SHA224, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("Signature.Num() == 56", Signature.Num(), 56);

	bSuccess = Uncryptool::ECDSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::BLAKE2b512, Signature, ErrorMessage);
	TestFalse("bSuccess == false", bSuccess);

	bSuccess = Uncryptool::ECDSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::BLAKE2s256, Signature, ErrorMessage);
	TestFalse("bSuccess == false", bSuccess);

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsECDSA_ToCustomEllipticCurve, "Uncryptool.UnitTests.ECDSA.ToCustomEllipticCurve", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsECDSA_ToCustomEllipticCurve::RunTest(const FString& Parameters)
{
	FUncryptoolPrivateKey PrivateKey;
	FUncryptoolPublicKey PublicKey;
	FString ErrorMessage;

	bool bSuccess = Uncryptool::GenerateECKey(EUncryptoolEllipticCurve::SECP256K1, PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Bits == 256", PrivateKey.Bits, 256);
	TestEqual("PublicKey.Bits == 256", PublicKey.Bits, 256);

	FUncryptoolEllipticCurve EllipticCurve;
	FUncryptoolBigNum D;
	bSuccess = Uncryptool::ECPrivateKeyToCustomEllipticCurve(PrivateKey, EllipticCurve, D, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);

	TestEqual("EllipticCurve.P == 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", EllipticCurve.P.ToHexString(), "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
	TestEqual("EllipticCurve.A == 0x0", EllipticCurve.A.ToHexString(), "0");
	TestEqual("EllipticCurve.B == 0x07", EllipticCurve.B.ToHexString(), "07");

	TestEqual("EllipticCurve.Gx == 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", EllipticCurve.Gx.ToHexString(), "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
	TestEqual("EllipticCurve.Gy == 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", EllipticCurve.Gy.ToHexString(), "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");

	TestEqual("EllipticCurve.Order == 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", EllipticCurve.Order.ToHexString(), "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
	TestEqual("EllipticCurve.Cofactor == 0x01", EllipticCurve.Cofactor.ToHexString(), "01");

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsECDSA_ToyEllipticCurve, "Uncryptool.UnitTests.ECDSA.ToyEllipticCurve", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsECDSA_ToyEllipticCurve::RunTest(const FString& Parameters)
{
	FUncryptoolPrivateKey PrivateKey;
	FUncryptoolPublicKey PublicKey;
	FString ErrorMessage;

	FUncryptoolBigNum D;
	D.SetHexString("0x12345");

	bool bSuccess = Uncryptool::ECPrivateKeyFromBigNum(EUncryptoolEllipticCurve::SECP256K1, D, PrivateKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Bits == 256", PrivateKey.Bits, 256);

	bSuccess = Uncryptool::PublicKeyFromPrivateKey(PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PublicKey.Bits == 256", PublicKey.Bits, 256);

	FUncryptoolEllipticCurve EllipticCurve;
	FUncryptoolBigNum Qx;
	FUncryptoolBigNum Qy;
	bSuccess = Uncryptool::ECPublicKeyToCustomEllipticCurve(PublicKey, EllipticCurve, Qx, Qy, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);

	TestEqual("Qx == 0xE963FFDFE34E63B68AEB42A5826E08AF087660E0DAC1C3E79F7625CA4E6AE482", Qx.ToHexString(), "E963FFDFE34E63B68AEB42A5826E08AF087660E0DAC1C3E79F7625CA4E6AE482");
	TestEqual("Qy == 0x2A78E81B57D80C4C65C94692FA281D1A1A8875F9874C197E71A52C11D9D44C40", Qy.ToHexString(), "2A78E81B57D80C4C65C94692FA281D1A1A8875F9874C197E71A52C11D9D44C40");

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsECDSA_ToySignAndVerify, "Uncryptool.UnitTests.ECDSA.ToySignAndVerify", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsECDSA_ToySignAndVerify::RunTest(const FString& Parameters)
{
	FUncryptoolPrivateKey PrivateKey;
	FUncryptoolPublicKey PublicKey;
	FString ErrorMessage;

	FUncryptoolBigNum D;
	D.SetHexString("0x12345");

	bool bSuccess = Uncryptool::ECPrivateKeyFromBigNum(EUncryptoolEllipticCurve::SECP256K1, D, PrivateKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Bits == 256", PrivateKey.Bits, 256);

	bSuccess = Uncryptool::PublicKeyFromPrivateKey(PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PublicKey.Bits == 256", PublicKey.Bits, 256);

	TArray<uint8> Signature;
	bSuccess = Uncryptool::ECDSADigestSign(PrivateKey, "Hello World", EUncryptoolHash::SHA256, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("Signature.Num() == 64", Signature.Num(), 64);

	bSuccess = Uncryptool::ECDSADigestVerify(PublicKey, "Hello World", EUncryptoolHash::SHA256, Signature, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);

	// TODO manage recoverable
#if 0
	TestEqual("Signature == 0xdfc0804599388b4d5a9f608c00a5e2dad20c49d5761b57cec494aa2ef88c4d6f4613d9b2b29939621136328678cb3c5eceb390a2017d978ba6424038f3abf83301",
		Uncryptool::BytesToHexString(Signature),
		"dfc0804599388b4d5a9f608c00a5e2dad20c49d5761b57cec494aa2ef88c4d6f4613d9b2b29939621136328678cb3c5eceb390a2017d978ba6424038f3abf83301");
#endif

	return true;
}

#endif
