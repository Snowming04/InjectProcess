#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <iostream>
#include <tchar.h>
#include <strsafe.h>

#define MAX_NAME 256


using namespace std;


//定义函数：获取系统当前的所有进程
BOOL GetProcessList();
void ErrorExit(LPTSTR lpszFunction);
void ShowProcessUser(HANDLE hToken, HANDLE hProcess);
string ShowProcessIntegrityLevel(HANDLE hToken, HANDLE hProcess);

int main()
{
	GetProcessList();
	cout << endl << endl;
	system("pause");

}


void ErrorExit(LPTSTR lpszFunction)
{
	// Retrieve the system error message for the last-error code

	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and exit the process

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("%s failed with error %d: %s"),
		lpszFunction, dw, lpMsgBuf);
	MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	ExitProcess(dw);
}

string ShowProcessIntegrityLevel(HANDLE hToken, HANDLE hProcess)
{
	DWORD dwLengthNeeded;
	DWORD dwError = ERROR_SUCCESS;

	PTOKEN_MANDATORY_LABEL pTIL = NULL;
	LPWSTR pStringSid;
	DWORD dwIntegrityLevel;
	string a = "";
	

	if (OpenProcessToken(hProcess, TOKEN_QUERY |
		TOKEN_QUERY_SOURCE, &hToken))
	{
		// Get the Integrity level.
		if (!GetTokenInformation(hToken, TokenIntegrityLevel,
			NULL, 0, &dwLengthNeeded))
		{
			dwError = GetLastError();
			if (dwError == ERROR_INSUFFICIENT_BUFFER)
			{
				pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0,
					dwLengthNeeded);
				if (pTIL != NULL)
				{
					if (GetTokenInformation(hToken, TokenIntegrityLevel,
						pTIL, dwLengthNeeded, &dwLengthNeeded))
					{
						dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid,
							(DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));
						if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
							dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
						{
							// Medium Integrity
							//wprintf(L"\r\n  Integrity:         Medium Process");
							a = "\r\n  Integrity:         Medium Process";
							
						}
						
						else if (dwIntegrityLevel < SECURITY_MANDATORY_MEDIUM_RID)
						{
							
							// Low Integrity
							//wprintf(L"\r\n  Integrity:         Low Process");		
							a = "";
						}
						
						else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
						{
							// High Integrity
							//wprintf(L"\r\n  Integrity:         High Integrity Process");
							a = "";
						}
					}
					LocalFree(pTIL);
				}
			}
		}
		CloseHandle(hToken);	
	}
	return a;
}



void ShowProcessUser(HANDLE hToken, HANDLE hProcess)
{
	DWORD dwLengthNeeded;
	DWORD dwError = ERROR_SUCCESS;

	PTOKEN_USER pTIL = NULL;
	LPWSTR pStringSid;
	DWORD dwUser;
	//hProcess = GetCurrentProcess();
	if (OpenProcessToken(hProcess, TOKEN_QUERY |
		TOKEN_QUERY_SOURCE, &hToken))
	{
		// Get the Integrity level.
		if (!GetTokenInformation(hToken, TokenUser,
			NULL, 0, &dwLengthNeeded))
		{
			dwError = GetLastError();
			if (dwError == ERROR_INSUFFICIENT_BUFFER)
			{
				pTIL = (PTOKEN_USER)LocalAlloc(0,
					dwLengthNeeded);
				if (pTIL != NULL)
				{
					if (GetTokenInformation(hToken, TokenUser,
						pTIL, dwLengthNeeded, &dwLengthNeeded))
					{
						//sid to username api
						//W是宽字节,A是ASCII
						WCHAR lpName[MAX_NAME] = { 0 };
						WCHAR lpDomain[MAX_NAME] = { 0 };
						SID_NAME_USE SidType;
						DWORD dwLength1 = MAX_NAME;
						DWORD dwLength2 = MAX_NAME;
						dwUser = LookupAccountSid(NULL, pTIL->User.Sid,
							lpName, &dwLength1, lpDomain,
							&dwLength2, &SidType);
						//dwUser = *LookupAccountSidA(pTIL->Label.Sid,(DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));
						if (dwUser)
						{
							wprintf(L"\r\n  User Name:         %s\\%s", lpDomain,lpName);
							//_tprintf(TEXT("\n  USER NAME:      %s"), lpName);
						}
					}
					LocalFree(pTIL);
				}
			}
		}
		CloseHandle(hToken);
	}
}


//函数实现：获取到进程列表
BOOL GetProcessList()
{
	//在拍完快照不需要使用快照了之后需要关闭快照句柄，低版本 TlHelp32.h 中有 CloseToolhelp32Snapshot 函数，但是高版本 SDK 只能调用 CloseHandle 来实现关闭了
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	HANDLE hProcessSnap;
	DWORD dwPriorityClass;
	HANDLE token = 0;
	// 对系统中当前所有的进程拍下快照
	// dwFlags #define TH32CS_SNAPPROCESS  0x00000002
	// 第二个参数 DWORD th32ProcessID 传入 0 时代表当前进程
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	//在使用 PROCESSENTRY32 结构之间需要先设置好该结构的大小 
	pe32.dwSize = sizeof(PROCESSENTRY32);

	//获取第一个进程
	//LPPROCESSENTRY32 lppe；微软 API 中 LP、P、*打头的都是指针
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return FALSE;
	}
	//PPROCESSENTRY32W1 pe31 = (PPROCESSENTRY32W1)&pe32;
	//采用 Do - While 遍历所有进程 
	do
	{
		dwPriorityClass = 0;
		DWORD m = 0;
		DWORD dwIntegrityLevel = 0;
		string b = "";
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
		if (hProcess == NULL) {
			continue;
		}
		if (ShowProcessIntegrityLevel(token, hProcess) == "") {
			continue;
		}
		
		printf("\n-----------------------------------------------------");
		_tprintf(TEXT("\n  PROCESS NAME:      %s"), pe32.szExeFile);
		printf("\n  parent process ID = %d", pe32.th32ParentProcessID);
		printf("\n  process ID        = %d", pe32.th32ProcessID);
		printf("\n  Priority Base     = %d", pe32.pcPriClassBase);
		
		
		TOKEN_MANDATORY_LABEL label = { 0 };
		if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &token)) {
			continue;
		}
		//printf("%#p", token);
			
		ShowProcessUser(token, hProcess);
		b = ShowProcessIntegrityLevel(token, hProcess);

		printf(b.c_str());
		//wprintf(L"\r\n  Integrity:         Medium Process");
		//	a = "\r\n  Integrity:         Medium Process";
		CloseHandle(hProcess);
		
		//遍历获取下一个进程 
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return TRUE;
}

