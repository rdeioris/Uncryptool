// Copyright 2025 - Roberto De Ioris

#include "UncryptoolFunctionLibrary.h"

#if PLATFORM_WINDOWS
#include "Windows/AllowWindowsPlatformTypes.h"
#include <wincrypt.h>
#include "Windows/HideWindowsPlatformTypes.h"
#endif

namespace Uncryptool
{
	bool KeychainLoad(const FUncryptoolBytes& InputBytes, TArray<uint8>& OutputBytes, FString& Description, FString& ErrorMessage)
	{
#if PLATFORM_WINDOWS
		DATA_BLOB InputBlob = {};

		// unfortunately we need to make a copy...
		TArray<uint8> InputCopy;
		InputCopy.Append(InputBytes.GetData(), InputBytes.Num());

		InputBlob.cbData = InputCopy.Num();
		InputBlob.pbData = InputCopy.GetData();

		DATA_BLOB OutputBlob = {};

		LPWSTR DataDescription = nullptr;
		bool bSuccess = false;
		if (CryptUnprotectData(&InputBlob, &DataDescription, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &OutputBlob))
		{
			bSuccess = true;
			Description = DataDescription;

			OutputBytes.SetNum(OutputBlob.cbData, EAllowShrinking::No);
			FMemory::Memcpy(OutputBytes.GetData(), OutputBlob.pbData, OutputBlob.cbData);
		}

		if (DataDescription)
		{
			LocalFree(DataDescription);
		}

		if (OutputBlob.pbData)
		{
			LocalFree(OutputBlob.pbData);
		}

		return bSuccess;
#else
		return false;
#endif
	}

	bool KeychainStore(const FUncryptoolBytes& InputBytes, TArray<uint8>& OutputBytes, const FString& Description, FString& ErrorMessage)
	{
#if PLATFORM_WINDOWS
		DATA_BLOB InputBlob = {};

		// unfortunately we need to make a copy...
		TArray<uint8> InputCopy;
		InputCopy.Append(InputBytes.GetData(), InputBytes.Num());

		InputBlob.cbData = InputCopy.Num();
		InputBlob.pbData = InputCopy.GetData();

		DATA_BLOB OutputBlob = {};

		LPWSTR DataDescription = nullptr;
		bool bSuccess = false;
		if (CryptProtectData(&InputBlob, *Description, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &OutputBlob))
		{
			bSuccess = true;
			OutputBytes.SetNum(OutputBlob.cbData, EAllowShrinking::No);
			FMemory::Memcpy(OutputBytes.GetData(), OutputBlob.pbData, OutputBlob.cbData);
		}

		if (DataDescription)
		{
			LocalFree(DataDescription);
		}

		if (OutputBlob.pbData)
		{
			LocalFree(OutputBlob.pbData);
		}

		return bSuccess;
#else
		return false;
#endif
	}
}