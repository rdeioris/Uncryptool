// Copyright 2025 - Roberto De Ioris

#pragma once

#include "CoreMinimal.h"
#include "GameFramework/SaveGame.h"
#include "EncryptedSaveGame.generated.h"

/**
 * 
 */
UCLASS()
class UNCRYPTOOL_API UEncryptedSaveGame : public USaveGame
{
	GENERATED_BODY()

public:
	virtual void Serialize(FArchive& Ar) override;

	void SetPassword(const FString& Password);

protected:
	FString PasswordForKeyDerivation;
	
	UPROPERTY()
	TArray<uint8> EncryptedData;
};
