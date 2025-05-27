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

	bSuccess = Uncryptool::GenerateECKey(EUncryptoolEllipticCurve::SECP256K1, PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Bits == 256", PrivateKey.Bits, 256);
	TestEqual("PublicKey.Bits == 256", PublicKey.Bits, 256);

	bSuccess = Uncryptool::GenerateECKey(EUncryptoolEllipticCurve::SECP384R1, PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Bits == 384", PrivateKey.Bits, 384);
	TestEqual("PublicKey.Bits == 384", PublicKey.Bits, 384);

	bSuccess = Uncryptool::GenerateECKey(EUncryptoolEllipticCurve::SECP521R1, PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Bits == 521", PrivateKey.Bits, 521);
	TestEqual("PublicKey.Bits == 521", PublicKey.Bits, 521);

	return true;
}

#endif
