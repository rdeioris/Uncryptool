// Copyright 2025 - Roberto De Ioris

#include "UncryptoolFunctionLibrary.h"

#define UI UI_ST
THIRD_PARTY_INCLUDES_START
#include "openssl/evp.h"
THIRD_PARTY_INCLUDES_END
#undef UI

namespace Uncryptool
{

	bool CheckEVPKeySize(EVP_CIPHER_CTX* Context, const FUncryptoolBytes& Key)
	{
		return EVP_CIPHER_CTX_key_length(Context) == Key.Num();
	}

	bool CheckEVPIvSize(EVP_CIPHER_CTX* Context, const FUncryptoolBytes& Key)
	{
		return EVP_CIPHER_CTX_iv_length(Context) == Key.Num();
	}

	bool DecryptAES256CBC(const FUncryptoolBytes& EncryptedBytes, const FUncryptoolBytes& Key, const FUncryptoolBytes& Iv, TArray<uint8>& OutputBytes, FString& ErrorMessage)
	{
		EVP_CIPHER_CTX* Context = EVP_CIPHER_CTX_new();
		if (!Context)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		if (EVP_DecryptInit_ex(Context, EVP_aes_256_cbc(), nullptr, Key.GetData(), Iv.GetData()) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_CIPHER_CTX_free(Context);
			return false;
		}

		if (!CheckEVPKeySize(Context, Key))
		{
			ErrorMessage = "Invalid Key size for AES256";
			EVP_CIPHER_CTX_free(Context);
			return false;
		}

		if (!CheckEVPIvSize(Context, Iv))
		{
			ErrorMessage = "Invalid Iv size for AES256";
			EVP_CIPHER_CTX_free(Context);
			return false;
		}

		OutputBytes.SetNum(EncryptedBytes.Num() + EVP_CIPHER_block_size(EVP_aes_256_cbc()), EAllowShrinking::No);
		int32 OutputSize = OutputBytes.Num();
		if (EVP_DecryptUpdate(Context, OutputBytes.GetData(), &OutputSize, EncryptedBytes.GetData(), EncryptedBytes.Num()) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_CIPHER_CTX_free(Context);
			OutputBytes.Empty();
			return false;
		}

		if (EVP_DecryptFinal_ex(Context, OutputBytes.GetData(), &OutputSize) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_CIPHER_CTX_free(Context);
			OutputBytes.Empty();
			return false;
		}

		EVP_CIPHER_CTX_free(Context);

		OutputBytes.SetNum(OutputSize, EAllowShrinking::No);

		return true;
	}

	bool EncryptAES256CBC(const FUncryptoolBytes& InputBytes, const FUncryptoolBytes& Key, const FUncryptoolBytes& Iv, TArray<uint8>& EncryptedBytes, FString& ErrorMessage)
	{
		EVP_CIPHER_CTX* Context = EVP_CIPHER_CTX_new();
		if (!Context)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		if (EVP_EncryptInit_ex(Context, EVP_aes_256_cbc(), nullptr, Key.GetData(), Iv.GetData()) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_CIPHER_CTX_free(Context);
			return false;
		}

		if (!CheckEVPKeySize(Context, Key))
		{
			ErrorMessage = "Invalid Key size for AES256";
			EVP_CIPHER_CTX_free(Context);
			return false;
		}

		if (!CheckEVPIvSize(Context, Iv))
		{
			ErrorMessage = "Invalid Iv size for AES256";
			EVP_CIPHER_CTX_free(Context);
			return false;
		}

		EncryptedBytes.SetNum(InputBytes.Num() + EVP_CIPHER_block_size(EVP_aes_256_cbc()), EAllowShrinking::No);
		int32 OutputSize = EncryptedBytes.Num();
		if (EVP_EncryptUpdate(Context, EncryptedBytes.GetData(), &OutputSize, InputBytes.GetData(), InputBytes.Num()) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_CIPHER_CTX_free(Context);
			EncryptedBytes.Empty();
			return false;
		}

		if (EVP_EncryptFinal_ex(Context, EncryptedBytes.GetData(), &OutputSize) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_CIPHER_CTX_free(Context);
			EncryptedBytes.Empty();
			return false;
		}

		EVP_CIPHER_CTX_free(Context);

		EncryptedBytes.SetNum(OutputSize, EAllowShrinking::No);

		return true;
	}

	bool DecryptChaCha20(const FUncryptoolBytes& EncryptedBytes, const FUncryptoolBytes& Key, const FUncryptoolBytes& Nonce, TArray<uint8>& OutputBytes, FString& ErrorMessage)
	{
		EVP_CIPHER_CTX* Context = EVP_CIPHER_CTX_new();
		if (!Context)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		if (EVP_DecryptInit_ex(Context, EVP_chacha20(), nullptr, Key.GetData(), Nonce.GetData()) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_CIPHER_CTX_free(Context);
			return false;
		}

		if (!CheckEVPKeySize(Context, Key))
		{
			ErrorMessage = "Invalid Key size for ChaCha20";
			EVP_CIPHER_CTX_free(Context);
			return false;
		}

		if (!CheckEVPIvSize(Context, Nonce))
		{
			ErrorMessage = "Invalid Nonce size for ChaCha20";
			EVP_CIPHER_CTX_free(Context);
			return false;
		}

		OutputBytes.SetNum(EncryptedBytes.Num(), EAllowShrinking::No);
		int32 OutputSize = OutputBytes.Num();
		if (EVP_DecryptUpdate(Context, OutputBytes.GetData(), &OutputSize, EncryptedBytes.GetData(), EncryptedBytes.Num()) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_CIPHER_CTX_free(Context);
			OutputBytes.Empty();
			return false;
		}

		if (EVP_DecryptFinal_ex(Context, OutputBytes.GetData(), &OutputSize) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_CIPHER_CTX_free(Context);
			OutputBytes.Empty();
			return false;
		}

		EVP_CIPHER_CTX_free(Context);

		return true;
	}

	bool EncryptChaCha20(const FUncryptoolBytes& InputBytes, const FUncryptoolBytes& Key, const FUncryptoolBytes& Nonce, TArray<uint8>& EncryptedBytes, FString& ErrorMessage)
	{
		EVP_CIPHER_CTX* Context = EVP_CIPHER_CTX_new();
		if (!Context)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		if (EVP_EncryptInit_ex(Context, EVP_chacha20(), nullptr, Key.GetData(), Nonce.GetData()) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_CIPHER_CTX_free(Context);
			return false;
		}

		if (!CheckEVPKeySize(Context, Key))
		{
			ErrorMessage = "Invalid Key size for ChaCha20";
			EVP_CIPHER_CTX_free(Context);
			return false;
		}

		if (!CheckEVPIvSize(Context, Nonce))
		{
			ErrorMessage = "Invalid Nonce size for ChaCha20";
			EVP_CIPHER_CTX_free(Context);
			return false;
		}

		EncryptedBytes.SetNum(InputBytes.Num(), EAllowShrinking::No);
		int32 OutputSize = EncryptedBytes.Num();
		if (EVP_EncryptUpdate(Context, EncryptedBytes.GetData(), &OutputSize, InputBytes.GetData(), InputBytes.Num()) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_CIPHER_CTX_free(Context);
			EncryptedBytes.Empty();
			return false;
		}

		if (EVP_EncryptFinal_ex(Context, EncryptedBytes.GetData(), &OutputSize) <= 0)
		{
			ErrorMessage = GetOpenSSLError();
			EVP_CIPHER_CTX_free(Context);
			EncryptedBytes.Empty();
			return false;
		}

		EVP_CIPHER_CTX_free(Context);

		return true;
	}

}