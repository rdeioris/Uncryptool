// Copyright 2025 - Roberto De Ioris

#if WITH_DEV_AUTOMATION_TESTS
#include "UncryptoolFunctionLibrary.h"
#include "Misc/AutomationTest.h"

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsPEM_RSA2048, "Uncryptool.UnitTests.PEM.RSA2048", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsPEM_RSA2048::RunTest(const FString& Parameters)
{
	FUncryptoolPrivateKey PrivateKey;
	FString ErrorMessage;

	const FString RSA2048 = R"(
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDovQMLvG8OuL4d
FbvaHMLswTwBY3DIxKiYcI9Q28dvlAP2LLkt2ysA0m36M+TvHY+MGKUwnhd3735g
Fc5XOGSNKDPPvFv5Ex9ovQm9YMKpEU2nCW3tLDtcWWFZMi/COklewMwLAOvjoJOm
dAvdS6CT/CsssOabjLfEhJfVYL+xabz49oM+IvfYM1OnhGnmeh6jN/htLlP5q14i
uqi0kAxnjmT6XG6shky4zy6zkeIdTgFRia0SPY87LW0xMWHLIYLwavJw+nhq5HjY
KK2IclYtJb7Ph9BgJa8mJHwQZLkH4jLwbwkLB2Gszttpr5ngdWaOZzz1Q/QXwaZr
33utCOJbAgMBAAECggEAMu8OiBZ8fY3LuWTEwDaUKCkf3zPqfl2fggD8NFds3YvY
lBr0iccRsbPbsqqBuxzOifvoxuuKOkq07wVGq4rhYoz+TcOsoyVetdbNF19iKorp
Yhlrr8CC2zKKXfFgR1LnNK/f17ajaST+uyphYFRJN6mzryulxDv3CbB05BMw0Hvn
JkeUsVA63u7VN/9kobSZdnLl4eMKSQiEwuEzrCz5VzHzVceKd6XVrSVOWfzyxcm+
YhjvmmvxPVEi/fsaU3ax7V5nk8XSsr0pgebtHmsdb3Tv5F7wMH8Bx1qPBkNdAMTT
ZUpP3AwF8btCGqiOzYo5KF0vwP2mo7Br1bEy/7gMHQKBgQD7sNbnzV0hhFqFNM9M
zmb2QIPxsnxXqcI5JkyPslRm+CQAe53KVR+RoYbNzsilRDTNj/Kfjk48rtO6/dG0
ERUGPO5z/02t+RuEK0pK/em4DRfW4iB2AeG+8w7ox/IP1C9GZ7+PGxGyWDgVian5
R0Da53Tb79EpuhI7cbmlnnvg1QKBgQDsuRqVSxzZGaMz+fvCBHs7iWcHS5zyidos
PA29GOPGatBz8HjdmQkpCpw3LNruLJQCbuYMkmjc2NOrxd49oi8pLOO+Ip1HzmEh
4sGTgP06ZrrbZpfGwfwJkw+/8cryTy47Lwal/cbnFhiHkMc6TcZS+I4wrtHaKkv2
aXHnyEvObwKBgQCRQ7p1ZTjoPFyGXzl6KfKRFCFTIWHUsrzPgURU92bxWyxkPvSO
L90dj22fYUa65AfZ0MgGwPp02a6IUTB0ThulUwuJVYO+8nSoLtgdOjlnqd7lffOg
SGvDasNjJOuXqS5z4zNTZBstpO8RtzesESzkawwuWFaPT75wIq40Yak71QKBgDWF
/M64twMXWuFLqnLJ1Js3jAYIQKpOJPhPc8PHtuiMCinMu2dPTNTswzlueOnVRnnu
XTGGgRM+K03xZTiGTSeAMNYyuWEc9rVUsfQJ/DeSNrmYzsRv4+6+Q5dgskRrRsa2
8Ufiw3BIfK9aOtGh+C+WZ3/2Zxhu69IBMXH4xbsdAoGBAKwYKCpJi8eq62h8+kFZ
V2VYdkWnT7jNF1ZpFHvMGk7QsNcNpZQZtsBOKPQALR/2pwOuM/p96vZrMvVrCzSN
0ZyBwLe50EqnJVp+WS1+X8E8DQHm3pPBqsAP9adb5TY7vbbrvTchIdmjymiPp/NZ
dssbRyP51b+sjKAE76lZq569
-----END PRIVATE KEY-----
	)";

	bool bSuccess = Uncryptool::PEMToPrivateKey(RSA2048, PrivateKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Type == RSA", PrivateKey.Type, EUncryptoolKey::RSA);
	TestEqual("PrivateKey.Bits == 2048", PrivateKey.Bits, 2048);

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsPEM_RSA4096, "Uncryptool.UnitTests.PEM.RSA4096", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsPEM_RSA4096::RunTest(const FString& Parameters)
{
	FUncryptoolPrivateKey PrivateKey;
	FString ErrorMessage;

	const FString RSA4096 = R"(
-----BEGIN PRIVATE KEY-----
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
kHbgieDTiE3ICTL3edZyO4Zxqkc7+W0=
-----END PRIVATE KEY-----
	)";

	bool bSuccess = Uncryptool::PEMToPrivateKey(RSA4096, PrivateKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Type == RSA", PrivateKey.Type, EUncryptoolKey::RSA);
	TestEqual("PrivateKey.Bits == 4096", PrivateKey.Bits, 4096);

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsPEM_DSA2048, "Uncryptool.UnitTests.PEM.DSA2048", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsPEM_DSA2048::RunTest(const FString& Parameters)
{
	FUncryptoolPrivateKey PrivateKey;
	FString ErrorMessage;

	const FString DSA2048 = R"(
-----BEGIN PRIVATE KEY-----
MIICXAIBADCCAjUGByqGSM44BAEwggIoAoIBAQCx4qZfRRhvH2a0VLeGCUD6QWau
zmFdDTfyirIMT1Tg2y6FgEI1O7rtZQItGR8Z/nyJVR+mK/g+Cl51x6nNsjmdHkt5
rK2RXAHaI0Xj/PbC6S+6UcGY8Dwez0Io+WIgDl6DaSKOwk83s4s+NHlRxF0YC7YH
XfGvd9jr794heawUZp7O3ucJsaVo2aOkNcxYVYVkRYDh7zXJLKB1zd5wmUIKvjCt
vpW1b71k+CZJ5vbwIt8dAHI9sLyUDh2qfTEgEkt9GcVKtanFoWmdvDIF9rU5BdB0
ojdRT+/YMd+sLihNJ/I2BITz4FyBL05wQwUYGLPLW6bm2vhrBhvjhhgQEPNLAh0A
0K6KyCgZTx8dEzGhT9VSryPPHZonRzHD82H/nQKCAQB7qW4IeJyYjY0XCt68uoUG
5n+1aG6X+ODyOdI+qX9Hpaa5vUc2KwJvWc26lOH9At669wTCvdkQWvGTmkGjKZY7
KDiHMzNWnyYGd3rDrV5VbLZLAypAnriqba/ZJVUb6s4fTO6b/XLa47YFUSbi0FiS
NGNcOaX8BndYQSMef3keTf7GThv6PcGGIDLayFiBYmqMTZGjsDOKiEm2yV1de0Ex
mZRbXW9FsulClipH3kN8ta2gxGnhw8t8ySEfYW/OdmOgjMtOxA34yrB2sJCTILMh
cxKHYd8E8hicSgw7bmXLcodKjMkow62ttGUHf58x/GoRTo1J/3JRgJdildSxUoMm
BB4CHEL0ikalLTDthMHb7rEIug3M+huRUyoH42ZI05E=
-----END PRIVATE KEY-----
	)";

	bool bSuccess = Uncryptool::PEMToPrivateKey(DSA2048, PrivateKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Type == RSA", PrivateKey.Type, EUncryptoolKey::DSA);
	TestEqual("PrivateKey.Bits == 2048", PrivateKey.Bits, 2048);

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsPEM_DSA3072, "Uncryptool.UnitTests.PEM.DSA3072", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsPEM_DSA3072::RunTest(const FString& Parameters)
{
	FUncryptoolPrivateKey PrivateKey;
	FString ErrorMessage;

	const FString DSA3072 = R"(
-----BEGIN PRIVATE KEY-----
MIIDXAIBADCCAzUGByqGSM44BAEwggMoAoIBgQCqrx2TX8HO0JqydFcyB920MrzR
wvigHDTh3Zg7+HEONKcMh6CuXu/kmmX/1n3TcWU5AGRyW+rxWy+k9A5yf3siJcdN
MeR6bWJA+dxT9wGcLpeZPpHrmF6dn1EZc1+AVg2ZYTy+6WoB1X1AvxC6UbOVKGlP
Q6u6ZYSzIAvVpEkFijJwAdo2vfaLSxWXCYwcANFkDvoFE6tzz7eAZCFTgEigIrPM
mJkjmoVv1swLcyRQ6vfk28am59bbAOMcLuJn0JNZxXyrQSuHH0tsvXLnYc4aOPkW
O7U4xBl5LlQcPibgZKsVr7nB8drsIg5JmYiwa7Js8DofPMy8b/zhJcJeaiCWVOR0
fxf8HK+qshYwJvqOJ98NXv+oIIM8GyrBMDAeQ0NbUrvyW/RyIKUdie+VQtbjv4oW
adrSp3+kEwt9q2z358i/Mzl0H2YNjPOW1sljpb0XO2UDpMXxq/FomX3hOVXf6GH5
KSqIZ5Doxq9UITl4JgrKdemD0NOuEcXQnsZhF5cCHQD2TAUr8nFcJ963t79y/yiF
TG3+H7ybw4RDhYpdAoIBgBcDPFVY/eLo9YAezvvEa+QKfvsxw94i9dtff6eqt13N
5gplHDu+PIW76mGDadyQxyIQBxBGAdOTrOJvf7/b/oPMpenXSirEsuJf1vsGQo8p
COqfQhPf3JdTV6d+Cw1/NQBowLGuJL2IlWQL769d+F9ojswO0gpNtSTO2BtOBFSw
pxp5mPPykDa3f6oQM/W9X59dlOp+4cyBlHQJqVXigKBqaqv8Iw1fn0acbzBMGj7r
zqv/DatOihI4S5CPpk0KKkcbPMjH0vrptRldI/j76hKMaZwm+9gjf7+McnjxzbQK
FvJ8v2fKKdSyprR1JZgzlgNF/8msYYg0ZNxiady3RfItu2NeT5j2pUmTCExPvpp6
VaB/JseWVRmcWaaTFNwCU/jQgw6AKsOgqbHlw243Ao3ueyz6FZYvGrkrWA8gOAwQ
0ZZfORkctrxcYqhKL6BO2CsuL4bBMf56idwvwuBe/Ofvf5B5V9uEwHOzCH9TlP3v
okBafPis3+BtIEk9tNpn+gQeAhx9zMnXwMju3Fby1kHAFkw7HmS+l4j90u6MR9eC
-----END PRIVATE KEY-----
	)";

	bool bSuccess = Uncryptool::PEMToPrivateKey(DSA3072, PrivateKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Type == RSA", PrivateKey.Type, EUncryptoolKey::DSA);
	TestEqual("PrivateKey.Bits == 3072", PrivateKey.Bits, 3072);

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsPEM_ED448, "Uncryptool.UnitTests.PEM.ED448", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsPEM_ED448::RunTest(const FString& Parameters)
{
	FUncryptoolPrivateKey PrivateKey;
	FString ErrorMessage;

	const FString ED448 = R"(
-----BEGIN PRIVATE KEY-----
MEcCAQAwBQYDK2VxBDsEOYUbIWDj68xO9mDHfwC48koDkKcetO/U21eiBbEJD6+k
UNnjcrVG2xbzdj5O03iQXqMRDIqifI9ksg==
-----END PRIVATE KEY-----
	)";

	bool bSuccess = Uncryptool::PEMToPrivateKey(ED448, PrivateKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Type == ED448", PrivateKey.Type, EUncryptoolKey::ED448);
	TestEqual("PrivateKey.Bits == 456", PrivateKey.Bits, 456);

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsPEM_ED25519, "Uncryptool.UnitTests.PEM.ED25519", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsPEM_ED25519::RunTest(const FString& Parameters)
{
	FUncryptoolPrivateKey PrivateKey;
	FString ErrorMessage;

	const FString ED25519 = R"(
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIHHWB3i/6MKozd33Aq0FwyWZEyjn6MeOafOIrC9IZYgv
-----END PRIVATE KEY-----
	)";

	bool bSuccess = Uncryptool::PEMToPrivateKey(ED25519, PrivateKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Type == ED25519", PrivateKey.Type, EUncryptoolKey::ED25519);
	TestEqual("PrivateKey.Bits == 253", PrivateKey.Bits, 253);

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsPEM_ED25519ToPublicKey, "Uncryptool.UnitTests.PEM.ED25519ToPublicKey", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsPEM_ED25519ToPublicKey::RunTest(const FString& Parameters)
{
	FUncryptoolPrivateKey PrivateKey;
	FString ErrorMessage;

	const FString ED25519 = R"(
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIHHWB3i/6MKozd33Aq0FwyWZEyjn6MeOafOIrC9IZYgv
-----END PRIVATE KEY-----
	)";

	const FString ED25519Pub = R"(
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA7TT3AmCfoUcwEuWH+kVtnx195rVGHJNV7lwtSPdu8lk=
-----END PUBLIC KEY-----
	)";

	bool bSuccess = Uncryptool::PEMToPrivateKey(ED25519, PrivateKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PrivateKey.Type == ED25519", PrivateKey.Type, EUncryptoolKey::ED25519);
	TestEqual("PrivateKey.Bits == 253", PrivateKey.Bits, 253);

	FUncryptoolPublicKey PublicKey;
	bSuccess = Uncryptool::PublicKeyFromPrivateKey(PrivateKey, PublicKey, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("PublicKey.Type == ED25519", PrivateKey.Type, EUncryptoolKey::ED25519);
	TestEqual("PublicKey.Bits == 253", PrivateKey.Bits, 253);

	FString ED25519PubPEM;
	bSuccess = Uncryptool::PublicKeyToPEM(PublicKey, ED25519PubPEM, ErrorMessage);
	TestTrue("bSuccess == true", bSuccess);
	TestEqual("ED25519Pub == ED25519PubPEM", ED25519Pub.TrimStart().TrimEnd(), ED25519PubPEM.TrimStart().TrimEnd());

	return true;
}

#endif
