// Copyright 2025 - Roberto De Ioris

#include "UncryptoolFunctionLibrary.h"

#if PLATFORM_WINDOWS
#include "Windows/AllowWindowsPlatformTypes.h"
#include "winscard.h"
#include "Windows/HideWindowsPlatformTypes.h"
#define SCARD_E_UNKNOWN_RES_MSG SCARD_E_UNKNOWN_RES_MNG
#endif

namespace Uncryptool
{
	FString GetPCSCError(LONG ResultValue)
	{
		switch (ResultValue)
		{
		case(SCARD_F_INTERNAL_ERROR):
			return "An internal consistency check failed";
		case(SCARD_E_CANCELLED):
			return "The action was cancelled by an SCardCancel request";
		case(SCARD_E_INVALID_HANDLE):
			return "The supplied handle was invalid";
		case(SCARD_E_INVALID_PARAMETER):
			return "One or more of the supplied parameters could not be properly interpreted";
		case(SCARD_E_INVALID_TARGET):
			return "Registry startup information is missing or invalid";
		case(SCARD_E_NO_MEMORY):
			return "Not enough memory available to complete this command";
		case(SCARD_F_WAITED_TOO_LONG):
			return "An internal consistency timer has expired";
		case(SCARD_E_INSUFFICIENT_BUFFER):
			return "The data buffer to receive returned data is too small for the returned data";
		case(SCARD_E_UNKNOWN_READER):
			return "The specified reader name is not recognized";
		case(SCARD_E_TIMEOUT):
		case(SCARD_E_SHARING_VIOLATION):
		case(SCARD_E_NO_SMARTCARD):
		case(SCARD_E_UNKNOWN_CARD):
		case(SCARD_E_CANT_DISPOSE):
		case(SCARD_E_PROTO_MISMATCH):
		case(SCARD_E_NOT_READY):
		case(SCARD_E_INVALID_VALUE):
		case(SCARD_E_SYSTEM_CANCELLED):
		case(SCARD_F_COMM_ERROR):
		case(SCARD_F_UNKNOWN_ERROR):
		case(SCARD_E_INVALID_ATR):
			return "An ATR obtained from the registry is not a valid ATR string";
		case(SCARD_E_NOT_TRANSACTED):
		case(SCARD_E_READER_UNAVAILABLE):
		case(SCARD_P_SHUTDOWN):
		case(SCARD_E_PCI_TOO_SMALL):
		case(SCARD_E_READER_UNSUPPORTED):
		case(SCARD_E_DUPLICATE_READER):
		case(SCARD_E_CARD_UNSUPPORTED):
		case(SCARD_E_NO_SERVICE):
		case(SCARD_E_SERVICE_STOPPED):
			return "The Smart card resource manager has shut down";
		case(SCARD_E_UNEXPECTED):
		case(SCARD_E_UNSUPPORTED_FEATURE):
			return "This smart card does not support the requested feature";
		case(SCARD_E_ICC_INSTALLATION):
		case(SCARD_E_ICC_CREATEORDER):
			return "The requested order of object creation is not supported";
		case(SCARD_E_DIR_NOT_FOUND):
			return "The identified directory does not exist in the smart card";
		case(SCARD_E_FILE_NOT_FOUND):
			return "The identified file does not exist in the smart card";
		case(SCARD_E_NO_DIR):
		case(SCARD_E_NO_FILE):
		case(SCARD_E_NO_ACCESS):
		case(SCARD_E_WRITE_TOO_MANY):
		case(SCARD_E_BAD_SEEK):
		case(SCARD_E_INVALID_CHV):
		case(SCARD_E_UNKNOWN_RES_MSG):
			//case(SCARD_E_UNKNOWN_RES_MNG):
		case(SCARD_E_NO_SUCH_CERTIFICATE):
		case(SCARD_E_CERTIFICATE_UNAVAILABLE):
		case(SCARD_E_NO_READERS_AVAILABLE):
		case(SCARD_E_COMM_DATA_LOST):
		case(SCARD_E_NO_KEY_CONTAINER):
		case(SCARD_E_SERVER_TOO_BUSY):
		case(SCARD_W_UNSUPPORTED_CARD):
		case(SCARD_W_UNRESPONSIVE_CARD):
		case(SCARD_W_UNPOWERED_CARD):
		case(SCARD_W_RESET_CARD):
		case(SCARD_W_REMOVED_CARD):
		case(SCARD_W_SECURITY_VIOLATION):
		case(SCARD_W_WRONG_CHV):
		case(SCARD_W_CHV_BLOCKED):
			return "The card cannot be accessed because the maximum number of PIN entry attempts has been reached";
		case(SCARD_W_EOF):
			return "The end of the smart card file has been reached";
		case(SCARD_W_CANCELLED_BY_USER):
			return "The user pressed \"Cancel\" on a Smart Card Selection Dialog";
		case(SCARD_W_CARD_NOT_AUTHENTICATED):
			return "No PIN was presented to the smart card";
		default:
			break;
		}

		return "Unknown PCSC Error";
	}

	bool PCSCGetReaders(TArray<FString>& Readers, FString& ErrorMessage)
	{
#if PLATFORM_WINDOWS
		SCARDCONTEXT CardContext;
		LONG ReturnValue = SCardEstablishContext(SCARD_SCOPE_USER, nullptr, nullptr, &CardContext);
		if (ReturnValue != SCARD_S_SUCCESS)
		{
			return false;
		}

		DWORD ReadersLength;

		ReturnValue = SCardListReadersA(CardContext, nullptr, nullptr, &ReadersLength);
		if (ReturnValue != SCARD_S_SUCCESS)
		{
			ErrorMessage = GetPCSCError(ReturnValue);
			SCardReleaseContext(CardContext);
			return false;
		}

		TArray<char> ReadersChars;
		ReadersChars.AddUninitialized(ReadersLength);

		ReturnValue = SCardListReadersA(CardContext, nullptr, ReadersChars.GetData(), &ReadersLength);
		if (ReturnValue != SCARD_S_SUCCESS)
		{
			ErrorMessage = GetPCSCError(ReturnValue);
			SCardReleaseContext(CardContext);
			return false;
		}

		FString CurrentReader;
		for (int32 CharIndex = 0; CharIndex < ReadersChars.Num(); CharIndex++)
		{
			const char CurrentChar = ReadersChars[CharIndex];
			if (CurrentChar == 0)
			{
				if (!CurrentReader.IsEmpty())
				{
					Readers.Add(CurrentReader);
					CurrentReader = "";
				}
			}
			else
			{
				CurrentReader += CurrentChar;
			}
		}

		SCardReleaseContext(CardContext);
		return true;
#else
		return false;
#endif
	}

	bool PCSCGetPublicKey(const FString& Reader, const uint8 Slot, const FString& Pin, FUncryptoolPublicKey& PublicKey, FString& ErrorMessage)
	{
#if PLATFORM_WINDOWS
		SCARDCONTEXT CardContext;
		LONG ReturnValue = SCardEstablishContext(SCARD_SCOPE_USER, nullptr, nullptr, &CardContext);
		if (ReturnValue != SCARD_S_SUCCESS)
		{
			return false;
		}

		SCARDHANDLE CardHandle;
		DWORD ActiveProtocols;


		ReturnValue = SCardConnectA(CardContext, TCHAR_TO_UTF8(*Reader), SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &CardHandle, &ActiveProtocols);
		if (ReturnValue != SCARD_S_SUCCESS)
		{
			ErrorMessage = GetPCSCError(ReturnValue);
			SCardReleaseContext(CardContext);
			return false;
		}

		//const uint8 APDU[] = { 0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x9A, 0x00 };
		//const uint8 APDU[] = { 0x00, 0x20, 0x00, 0x80, 0x08, '0', '0', '0', '0', '0', '0', 0, 0 };
		const uint8 APDU0[] = { 0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08 };
		DWORD sendLen = sizeof(APDU0);
		BYTE recvBuf[4096];
		DWORD recvLen = sizeof(recvBuf);

		ReturnValue = SCardTransmit(CardHandle, SCARD_PCI_T1, APDU0, sendLen, nullptr, recvBuf, &recvLen);
		if (ReturnValue != SCARD_S_SUCCESS)
		{
			ErrorMessage = GetPCSCError(ReturnValue);
			SCardDisconnect(CardHandle, SCARD_LEAVE_CARD);
			SCardReleaseContext(CardContext);
			return false;
		}

		const uint8 APDU[] = { 0x00, 0x20, 0x00, 0x80, 0x06, '0', '0', '0', '0', '0', '0' };
		sendLen = sizeof(APDU);

		ReturnValue = SCardTransmit(CardHandle, SCARD_PCI_T1, APDU, sendLen, nullptr, recvBuf, &recvLen);
		if (ReturnValue != SCARD_S_SUCCESS)
		{
			ErrorMessage = GetPCSCError(ReturnValue);
			SCardDisconnect(CardHandle, SCARD_LEAVE_CARD);
			SCardReleaseContext(CardContext);
			return false;
		}

		SCardDisconnect(CardHandle, SCARD_LEAVE_CARD);
		SCardReleaseContext(CardContext);
		return true;
#else
		return false;
#endif
	}
}

FUncryptoolPublicKey UUncryptoolFunctionLibrary::PCSCGetPublicKey(const FString& Reader, const uint8 Slot, const FString& Pin, bool& bSuccess, FString& ErrorMessage)
{
	FUncryptoolPublicKey PublicKey;
	bSuccess = Uncryptool::PCSCGetPublicKey(Reader, Slot, Pin, PublicKey, ErrorMessage);
	return PublicKey;
}

TArray<FString> UUncryptoolFunctionLibrary::PCSCGetReaders(FString& ErrorMessage)
{
	TArray<FString> Readers;
	if (!Uncryptool::PCSCGetReaders(Readers, ErrorMessage))
	{
		return {};
	}
	return Readers;
}