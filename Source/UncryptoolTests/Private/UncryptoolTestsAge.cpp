// Copyright 2025 - Roberto De Ioris

#if WITH_DEV_AUTOMATION_TESTS
#include "UncryptoolFunctionLibrary.h"
#include "Misc/AutomationTest.h"

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsAge_LoadIdentity0, "Uncryptool.FunctionalTests.Age.LoadIdentity0", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsAge_LoadIdentity0::RunTest(const FString& Parameters)
{
	const char* Identity = R"(# created: 2025-07-12T15:56:23+02:00
# public key: age1rdsm622jdfvdgyhvq2jdaypnv8zzc4wqae6qt0dd8836js0zl38qhftexr
AGE-SECRET-KEY-1AQYLW9QNW4K7JLUY79UG0VGVULUU9895NWCE05PEXH7SCN94DVDS8CRMAT)";

	FUncryptoolPrivateKey PrivateKey;
	FUncryptoolPublicKey PublicKey;
	FString ErrorMessage;
	bool bSuccess = Uncryptool::LoadAgeIdentity(Identity, PrivateKey, PublicKey, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Type == EC", PrivateKey.Type, EUncryptoolKey::EC);

	TArray<uint8> PublicKeyRaw;
	bSuccess = Uncryptool::PublicKeyToRaw(PublicKey, PublicKeyRaw, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);

	TArray<uint8> PublicKeyAge;
	bSuccess = Uncryptool::Bech32Encode("age", PublicKeyRaw, PublicKeyAge, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);

	TestEqual("PublicKeyAge == \"age1rdsm622jdfvdgyhvq2jdaypnv8zzc4wqae6qt0dd8836js0zl38qhftexr\"", Uncryptool::BytesToUTF8String(PublicKeyAge), "age1rdsm622jdfvdgyhvq2jdaypnv8zzc4wqae6qt0dd8836js0zl38qhftexr");

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsAge_LoadIdentity1, "Uncryptool.FunctionalTests.Age.LoadIdentity1", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsAge_LoadIdentity1::RunTest(const FString& Parameters)
{
	const char* Identity = R"(# created: 2025-07-12T15:56:27+02:00
# public key: age1x6lv70x4dndfulxsdhkq285a4qg5vcr94x5j5t54gh4xkp8l4e6q8lhac3
AGE-SECRET-KEY-1ZAMFFTFK7W02MKCKW8SHNW3AWXZFZQAGY9PL4W2PTPTD66NHYASQH0QX7W)";

	FUncryptoolPrivateKey PrivateKey;
	FUncryptoolPublicKey PublicKey;
	FString ErrorMessage;
	bool bSuccess = Uncryptool::LoadAgeIdentity(Identity, PrivateKey, PublicKey, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Type == EC", PrivateKey.Type, EUncryptoolKey::EC);

	TArray<uint8> PublicKeyRaw;
	bSuccess = Uncryptool::PublicKeyToRaw(PublicKey, PublicKeyRaw, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);

	TArray<uint8> PublicKeyAge;
	bSuccess = Uncryptool::Bech32Encode("age", PublicKeyRaw, PublicKeyAge, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);

	TestEqual("PublicKeyAge == \"age1x6lv70x4dndfulxsdhkq285a4qg5vcr94x5j5t54gh4xkp8l4e6q8lhac3\"", Uncryptool::BytesToUTF8String(PublicKeyAge), "age1x6lv70x4dndfulxsdhkq285a4qg5vcr94x5j5t54gh4xkp8l4e6q8lhac3");

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsAge_LoadIdentity2, "Uncryptool.FunctionalTests.Age.LoadIdentity2", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsAge_LoadIdentity2::RunTest(const FString& Parameters)
{
	const char* Identity = R"(# created: 2025-07-12T15:56:29+02:00
# public key: age1tutrjsnedjev66sldsnsvqczrsknkcg8rk24zpp7aa06jetapefqgza3gk
AGE-SECRET-KEY-16MJXTEVCHRY347XGPGPPUQVV8H43DDRWZ8SXS8LJ7KYTZ5XPXQXSHLN8PD)";

	FUncryptoolPrivateKey PrivateKey;
	FUncryptoolPublicKey PublicKey;
	FString ErrorMessage;
	bool bSuccess = Uncryptool::LoadAgeIdentity(Identity, PrivateKey, PublicKey, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Type == EC", PrivateKey.Type, EUncryptoolKey::EC);

	TArray<uint8> PublicKeyRaw;
	bSuccess = Uncryptool::PublicKeyToRaw(PublicKey, PublicKeyRaw, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);

	TArray<uint8> PublicKeyAge;
	bSuccess = Uncryptool::Bech32Encode("age", PublicKeyRaw, PublicKeyAge, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);

	TestEqual("PublicKeyAge == \"age1tutrjsnedjev66sldsnsvqczrsknkcg8rk24zpp7aa06jetapefqgza3gk\"", Uncryptool::BytesToUTF8String(PublicKeyAge), "age1tutrjsnedjev66sldsnsvqczrsknkcg8rk24zpp7aa06jetapefqgza3gk");

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsAge_LoadIdentity3, "Uncryptool.FunctionalTests.Age.LoadIdentity3", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsAge_LoadIdentity3::RunTest(const FString& Parameters)
{
	const char* Identity = R"(# created: 2025-07-12T15:56:31+02:00
# public key: age1ncafq029y8mzv4erksg3ws5s4mskuygejdcjzfuj2wztphv0fdeqda52hm
AGE-SECRET-KEY-1J0PUQQ598M3R8ST3K42XQLJTYDPUW95HC584GL2RPADMKE3Y25VQ5C3UZY)";

	FUncryptoolPrivateKey PrivateKey;
	FUncryptoolPublicKey PublicKey;
	FString ErrorMessage;
	bool bSuccess = Uncryptool::LoadAgeIdentity(Identity, PrivateKey, PublicKey, ErrorMessage);

	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Type == EC", PrivateKey.Type, EUncryptoolKey::EC);

	TArray<uint8> PublicKeyRaw;
	bSuccess = Uncryptool::PublicKeyToRaw(PublicKey, PublicKeyRaw, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);

	TArray<uint8> PublicKeyAge;
	bSuccess = Uncryptool::Bech32Encode("age", PublicKeyRaw, PublicKeyAge, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);

	TestEqual("PublicKeyAge == \"age1ncafq029y8mzv4erksg3ws5s4mskuygejdcjzfuj2wztphv0fdeqda52hm\"", Uncryptool::BytesToUTF8String(PublicKeyAge), "age1ncafq029y8mzv4erksg3ws5s4mskuygejdcjzfuj2wztphv0fdeqda52hm");

	return true;
}

#endif