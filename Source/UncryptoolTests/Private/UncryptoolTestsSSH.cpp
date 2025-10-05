// Copyright 2025 - Roberto De Ioris

#if WITH_DEV_AUTOMATION_TESTS
#include "UncryptoolFunctionLibrary.h"
#include "HAL/PlatformProcess.h"
#include "Interfaces/IPluginManager.h"
#include "Misc/AutomationTest.h"

struct FUncryptoolTestSSHServer
{
	static FUncryptoolTestSSHServer Spawn(const FString& Script)
	{
		const FString PluginDir = IPluginManager::Get().FindPlugin(TEXT("Uncryptool"))->GetBaseDir();
		const FString ScriptPath = FPaths::Combine(PluginDir, TEXT("Source/UncryptoolTests/Private/Scripts"), Script);

		FUncryptoolTestSSHServer SSHServer;

		if (!FPlatformProcess::CreatePipe(SSHServer.ReadPipe, SSHServer.WritePipe))
		{
			return SSHServer;
		}

		SSHServer.ProcHandle = FPlatformProcess::CreateProc(
#if PLATFORM_WINDOWS
			TEXT("python.exe")
#else
			TEXT("python3")
#endif
			,
			*FString::Printf(TEXT("\"%s\""), *ScriptPath),
			true,
			true,
			false,
			nullptr,
			0,
			nullptr,
			SSHServer.WritePipe,
			SSHServer.ReadPipe);

		if (!SSHServer.ProcHandle.IsValid())
		{
			return SSHServer;
		}

		TArray<uint8> PortData;
		for (;;)
		{
			TArray<uint8> PortDataChunk;
			if (!FPlatformProcess::ReadPipeToArray(SSHServer.ReadPipe, PortDataChunk))
			{
				if (!FPlatformProcess::IsProcRunning(SSHServer.ProcHandle))
				{
					break;
				}
				continue;
			}

			if (PortDataChunk.Num() < 1)
			{
				break;
			}

			PortData.Append(PortDataChunk);

			if (PortData.Contains(0))
			{
				break;
			}
		}

		if (!PortData.Contains(0))
		{
			return SSHServer;
		}

		SSHServer.Port = FCString::Atoi(UTF8_TO_TCHAR(PortData.GetData()));

		return SSHServer;
	}

	~FUncryptoolTestSSHServer()
	{
		if (ReadPipe && WritePipe)
		{
			FPlatformProcess::ClosePipe(ReadPipe, WritePipe);
		}

		if (ProcHandle.IsValid())
		{
			FPlatformProcess::CloseProc(ProcHandle);
		}
	}

	bool IsValid()
	{
		return Port > 0;
	}

	int32 Port = -1;
	void* ReadPipe = nullptr;
	void* WritePipe = nullptr;
	FProcHandle ProcHandle;
};

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FUncryptoolTestsSSH_Banner, "Uncryptool.FunctionalTests.SSH.Banner", EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter)

bool FUncryptoolTestsSSH_Banner::RunTest(const FString& Parameters)
{
	FUncryptoolTestSSHServer SSHServer = FUncryptoolTestSSHServer::Spawn("banner.py");

	TestTrue("SSHServer.IsValid() == true", SSHServer.IsValid());

	return true;
}

#endif