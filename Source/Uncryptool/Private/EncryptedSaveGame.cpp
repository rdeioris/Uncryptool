// Copyright 2025 - Roberto De Ioris


#include "EncryptedSaveGame.h"
#include "UncryptoolFunctionLibrary.h"

void UEncryptedSaveGame::Serialize(FArchive& Ar)
{
	if (Ar.IsSaving())
	{
		UE_LOG(LogTemp, Error, TEXT("UEncryptedSaveGame::Serialize IsSaving %lld"), Ar.Tell());

		
		TArray<uint8> RawData;
		FMemoryWriter EncryptedArchive(RawData, true);
		Super::Serialize(EncryptedArchive);

		UE_LOG(LogTemp, Error, TEXT("EncryptedArchive %lld %d"), EncryptedArchive.Tell(), RawData.Num());

		TArray<uint8> EncryptedRawData;
		FString ErrorMessage;
		Uncryptool::EncryptChaCha20(RawData, "hello world", "x", EncryptedRawData, ErrorMessage);

		Ar << EncryptedRawData;
	}
	else
	{
		UE_LOG(LogTemp, Error, TEXT("UEncryptedSaveGame::Serialize IsLoading %lld"), Ar.Tell());
		
		TArray<uint8> RawData;
		Ar << RawData;


		UE_LOG(LogTemp, Error, TEXT("RawData %lld"), RawData.Num());

		FMemoryReader EncryptedArchive(RawData, false);

		Super::Serialize(EncryptedArchive);
	}
}