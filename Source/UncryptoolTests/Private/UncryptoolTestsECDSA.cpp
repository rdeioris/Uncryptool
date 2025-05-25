// Copyright 2025 - Roberto De Ioris

#if WITH_DEV_AUTOMATION_TESTS
#include "Uncryptool.h"
#include "UncryptoolFunctionLibrary.h"
#include "Misc/AutomationTest.h"

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsECDSA_GenerateKey, "Uncryptool.UnitTests.ECDSA.GenerateKey", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsECDSA_GenerateKey::RunTest(const FString& Parameters)
{
	TArray<uint8> PrivateKey;
	TArray<uint8> PublicKey;
	FString ErrorMessage;

	bool bSuccess = Uncryptool::GenerateECKey(EUncryptoolEllipticCurve::PRIME256V1, PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Num() == 32", PrivateKey.Num(), 32);
	TestEqual("PublicKey.Num() == 65", PublicKey.Num(), 65);

	bSuccess = Uncryptool::GenerateECKey(EUncryptoolEllipticCurve::SECP256K1, PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Num() == 32", PrivateKey.Num(), 32);
	TestEqual("PublicKey.Num() == 65", PublicKey.Num(), 65);

	bSuccess = Uncryptool::GenerateECKey(EUncryptoolEllipticCurve::SECP384R1, PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Num() == 48", PrivateKey.Num(), 48);
	TestEqual("PublicKey.Num() == 97", PublicKey.Num(), 97);

	bSuccess = Uncryptool::GenerateECKey(EUncryptoolEllipticCurve::SECP521R1, PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Num() == 66", PrivateKey.Num(), 66);
	return TestEqual("PublicKey.Num() == 133", PublicKey.Num(), 133);
}

#endif
