// Copyright 2025 - Roberto De Ioris

#include "UncryptoolFunctionLibrary.h"

#define UI UI_ST
THIRD_PARTY_INCLUDES_START
#include "openssl/evp.h"
#include "openssl/hmac.h"
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

	bool DecryptChaCha20Salted(const FUncryptoolBytes& EncryptedBytes, const FUncryptoolBytes& Password, const EUncryptoolKeyDerivation KeyDerivation, const int32 Iterations, TArray<uint8>& OutputBytes, FString& ErrorMessage)
	{
		if (EncryptedBytes.Num() < 16 || FMemory::Memcmp(EncryptedBytes.GetData(), "Salted__", 8))
		{
			ErrorMessage = "Salted__ prefix not found";
			return false;
		}

		TArray<uint8> KeyAndIV;

		if (KeyDerivation == EUncryptoolKeyDerivation::PBKDF2)
		{
			if (!PBKDF2HMAC(Password, FUncryptoolBytes(EncryptedBytes.GetData() + 8, 8), Iterations, EUncryptoolHash::SHA256, 32 + 16 /* KeySize + IVSize */, KeyAndIV, ErrorMessage))
			{
				return false;
			}
		}
		else if (KeyDerivation == EUncryptoolKeyDerivation::Legacy)
		{
			KeyAndIV.SetNum(32 + 16, EAllowShrinking::No);
			if (EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), EncryptedBytes.GetData() + 8, Password.GetData(), Password.Num(), Iterations, KeyAndIV.GetData(), KeyAndIV.GetData() + 32) <= 0)
			{
				ErrorMessage = GetOpenSSLError();
				return false;
			}
		}
		else
		{
			ErrorMessage = "Unsupported Key Derivation Function";
			return false;
		}

		return DecryptChaCha20(FUncryptoolBytes(EncryptedBytes.GetData() + 16, EncryptedBytes.Num() - 16), FUncryptoolBytes(KeyAndIV.GetData(), 32), FUncryptoolBytes(KeyAndIV.GetData() + 32, 16), OutputBytes, ErrorMessage);
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

	bool EncryptChaCha20Poly1305(const FUncryptoolBytes& InputBytes, const FUncryptoolBytes& Key, const FUncryptoolBytes& Nonce, const FUncryptoolBytes& AAD, TArray<uint8>& EncryptedBytes, FString& ErrorMessage)
	{
		EVP_CIPHER_CTX* Context = EVP_CIPHER_CTX_new();
		if (!Context)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		if (EVP_EncryptInit_ex(Context, EVP_chacha20_poly1305(), nullptr, Key.GetData(), Nonce.GetData()) <= 0)
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

		if (AAD.Num() > 0)
		{
			if (EVP_EncryptUpdate(Context, nullptr, nullptr, AAD.GetData(), AAD.Num()) <= 0)
			{
				ErrorMessage = GetOpenSSLError();
				EVP_CIPHER_CTX_free(Context);
				EncryptedBytes.Empty();
				return false;
			}
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

	bool DecryptAES256CTR(const FUncryptoolBytes& EncryptedBytes, const FUncryptoolBytes& Key, const FUncryptoolBytes& Counter, TArray<uint8>& OutputBytes, FString& ErrorMessage)
	{
		EVP_CIPHER_CTX* Context = EVP_CIPHER_CTX_new();
		if (!Context)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		if (EVP_DecryptInit_ex(Context, EVP_aes_256_ctr(), nullptr, Key.GetData(), Counter.GetData()) <= 0)
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

		if (!CheckEVPIvSize(Context, Counter))
		{
			ErrorMessage = "Invalid Counter size for AES256";
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

	bool HMAC(const EUncryptoolHash Hash, const FUncryptoolBytes& InputBytes, const FUncryptoolBytes& Key, TArray<uint8>& OutputBytes, FString& ErrorMessage)
	{
		const EVP_MD* HashAlgo = nullptr;
		switch (Hash)
		{
		case EUncryptoolHash::SHA256:
			HashAlgo = EVP_sha256();
			break;
		case EUncryptoolHash::SHA512:
			HashAlgo = EVP_sha512();
			break;
		case EUncryptoolHash::RIPEMD160:
			HashAlgo = EVP_ripemd160();
			break;
		case EUncryptoolHash::SHA1:
			HashAlgo = EVP_sha1();
			break;
		default:
			ErrorMessage = "Unsupported Hash Algorithm";
			return false;
		}

		uint32 OutputSize = 0;
		const uint8* OutputStaticPtr = ::HMAC(HashAlgo, Key.GetData(), Key.Num(), InputBytes.GetData(), InputBytes.Num(), nullptr, &OutputSize);
		if (!OutputStaticPtr)
		{
			ErrorMessage = GetOpenSSLError();
			return false;
		}

		OutputBytes.SetNum(OutputSize, EAllowShrinking::No);
		FMemory::Memcpy(OutputBytes.GetData(), OutputStaticPtr, OutputSize);

		return true;
	}

	bool DecryptAESZIP(const FUncryptoolBytes& EncryptedBytes, const uint8 EncryptionStrength, const FUncryptoolBytes& Password, TArray<uint8>& OutputBytes, FString& ErrorMessage)
	{
		constexpr int32 Iterations = 1000;
		TArray<uint8> KeyAndPasswordVerification;

		// AES256
		if (EncryptionStrength == 3)
		{
			if (EncryptedBytes.Num() < 16 + 2 + 10)
			{
				ErrorMessage = "Unable to extract Salt and Password verification value";
				return false;
			}

			// key + password verifier
			KeyAndPasswordVerification.AddZeroed(32 + 32 + 2);

			if (PKCS5_PBKDF2_HMAC_SHA1(reinterpret_cast<const char*>(Password.GetData()), Password.Num(), EncryptedBytes.GetData(), 16, Iterations, KeyAndPasswordVerification.Num(), KeyAndPasswordVerification.GetData()) <= 0)
			{
				ErrorMessage = GetOpenSSLError();
				return false;
			}

			const uint16* PasswordVerificationInBytes = reinterpret_cast<const uint16*>(EncryptedBytes.GetData() + 16);
			const uint16* PasswordVerificationDerived = reinterpret_cast<const uint16*>(KeyAndPasswordVerification.GetData() + 32 + 32);

			if (*PasswordVerificationInBytes != *PasswordVerificationDerived)
			{
				ErrorMessage = "Wrong password";
				return false;
			}

			TArrayView<const uint8> Key = TArrayView<const uint8>(KeyAndPasswordVerification.GetData(), 32);

			// unfortunately openssl does not support little endian counter for EVP_aes_256_ctr so I need to do the counting manually :(
			uint64 RemainingBytes = EncryptedBytes.Num() - 16 - 2 - 10;
			// zip aes starts from 1
			uint64 Counter = 1;
			TArray<uint8> IVCounter;
			IVCounter.AddZeroed(16);
			const uint8* EncryptedBytesPtr = EncryptedBytes.GetData() + 16 + 2;
			OutputBytes.Empty();
			OutputBytes.Reserve(RemainingBytes);
			while (RemainingBytes > 0)
			{
				uint64 NextChunkSize = FMath::Min<uint64>(16, RemainingBytes);
				TArrayView<const uint8> EncryptedData = TArrayView<const uint8>(EncryptedBytesPtr, NextChunkSize);
				// update the Counter
				FMemory::Memcpy(IVCounter.GetData(), &Counter, sizeof(uint64));
				TArray<uint8> ChunkOutput;
				if (!DecryptAES256CTR(EncryptedData, Key, IVCounter, ChunkOutput, ErrorMessage))
				{
					return false;
				}
				OutputBytes.Append(ChunkOutput);
				EncryptedBytesPtr += NextChunkSize;
				RemainingBytes -= NextChunkSize;
				Counter++;
			}

			// compute the HMAC for verification
			TArrayView<const uint8> HMACKey = TArrayView<const uint8>(KeyAndPasswordVerification.GetData() + 32, 32);
			TArrayView<const uint8> HMACInput = TArrayView<const uint8>(EncryptedBytes.GetData() + EncryptedBytes.Num() - 10, 10);
			TArrayView<const uint8> OriginalEncryptedData = TArrayView<const uint8>(EncryptedBytes.GetData() + 16 + 2, EncryptedBytes.Num() - 16 - 2 - 10);
			TArray<uint8> HMACOutput;
			if (!HMAC(EUncryptoolHash::SHA1, OriginalEncryptedData, HMACKey, HMACOutput, ErrorMessage))
			{
				return false;
			}

			if (FMemory::Memcmp(HMACOutput.GetData(), HMACInput.GetData(), 10) != 0)
			{
				ErrorMessage = "HMAC verification failed";
				return false;
			}

			return true;
		}

		ErrorMessage = "Unsupported Encryption Strength";
		return false;
	}

}