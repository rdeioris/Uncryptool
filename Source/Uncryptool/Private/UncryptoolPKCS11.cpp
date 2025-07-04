// Copyright 2025 - Roberto De Ioris

#include "UncryptoolFunctionLibrary.h"

THIRD_PARTY_INCLUDES_START
#define CK_PTR *

#if PLATFORM_WINDOWS
#define CK_DECLARE_FUNCTION(returnType, name) \
   returnType __declspec(dllimport) name
#else
#define CK_DECLARE_FUNCTION(returnType, name) \
   returnType name
#endif

#if PLATFORM_WINDOWS
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
   returnType __declspec(dllimport) (* name)
#else
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
   returnType (* name)
#endif

#define CK_CALLBACK_FUNCTION(returnType, name) \
   returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "ThirdParty/PKCS11/pkcs11.h"
THIRD_PARTY_INCLUDES_END

namespace Uncryptool
{
	bool PKCS11GetPublicKeys(const FString& PKCS11LibPath, FString& ErrorMessage)
	{
		void* LibHandle = FPlatformProcess::GetDllHandle(*PKCS11LibPath);
		if (!LibHandle)
		{
			ErrorMessage = FString::Printf(TEXT("Unable to load library \"%s\""), *PKCS11LibPath);
			return false;
		}

		CK_C_GetFunctionList PKCS11APIGetFunctionListPtr = (CK_C_GetFunctionList)FPlatformProcess::GetDllExport(LibHandle, TEXT("C_GetFunctionList"));
		if (!PKCS11APIGetFunctionListPtr)
		{
			ErrorMessage = FString::Printf(TEXT("Unable to find symbol C_GetFunctionList in \"%s\""), *PKCS11LibPath);
			FPlatformProcess::FreeDllHandle(LibHandle);
			return false;
		}

		CK_FUNCTION_LIST_PTR PKCS11Ptr = {};
		CK_RV CKReturnValue = PKCS11APIGetFunctionListPtr(&PKCS11Ptr);
		if (CKReturnValue != CKR_OK)
		{
			ErrorMessage = FString::Printf(TEXT("C_GetFunctionList failed: 0x%lX"), CKReturnValue);
			FPlatformProcess::FreeDllHandle(LibHandle);
			return false;
		}

		CKReturnValue = PKCS11Ptr->C_Initialize(nullptr);
		if (CKReturnValue != CKR_OK)
		{
			ErrorMessage = FString::Printf(TEXT("C_Initialize failed: 0x%lX"), CKReturnValue);
			FPlatformProcess::FreeDllHandle(LibHandle);
			return false;
		}
#if 0

		CK_ULONG SlotNum = 0;
		PKCS11Ptr->C_GetSlotList(CK_TRUE, nullptr, &SlotNum);

		CK_ATTRIBUTE

		CK_SLOT_INFO SlotInfo;

		CK_SESSION_HANDLE Session = {};
		p11->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
#endif

		PKCS11Ptr->C_Finalize(nullptr);
		FPlatformProcess::FreeDllHandle(LibHandle);
		return true;
	}
}
