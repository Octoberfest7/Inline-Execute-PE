#pragma once
#include <windows.h>
#include <stdio.h>
#include <corecrt.h>
#include <winternl.h>
#include <stdlib.h>
#include <io.h>
#include <fcntl.h>
#include <inttypes.h>
#include <tlhelp32.h>

//MSVCRT
WINBASEAPI void __cdecl MSVCRT$free(void *_Memory);
WINBASEAPI void *__cdecl MSVCRT$malloc(size_t size);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char*);
WINBASEAPI void *__cdecl MSVCRT$memcpy(void*, void*, size_t);
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t _NumOfElements, size_t _SizeOfElements);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t *_Str);
WINBASEAPI int __cdecl MSVCRT$_stricmp (LPCSTR lpString1, LPCSTR lpString2);
WINBASEAPI int __cdecl MSVCRT$_dup (int _FileHandle);
WINBASEAPI int __cdecl MSVCRT$_dup2(int _FileHandleSrc, int _FileHandleDst);
WINBASEAPI int __cdecl MSVCRT$_open_osfhandle(intptr_t _OSFileHandle, int _Flags);
WINBASEAPI int __cdecl MSVCRT$_fileno(FILE* _Stream);
WINBASEAPI int __cdecl MSVCRT$setvbuf(FILE* _Stream, char* _Buffer, int _Mode, size_t _Size);
WINBASEAPI int __cdecl MSVCRT$_close(int _FileHandle);
WINBASEAPI int __cdecl MSVCRT$_flushall(void);
WINBASEAPI int __cdecl MSVCRT$printf(const char* format);
WINBASEAPI errno_t __cdecl MSVCRT$freopen_s (FILE** stream, const char* fileName, const char* mode, FILE* oldStream);
WINBASEAPI FILE* __cdecl MSVCRT$__iob_func();
WINBASEAPI int __cdecl MSVCRT$fclose(FILE* stream);
WINBASEAPI char* __cdecl MSVCRT$_itoa(int value, char* str, int base);
WINBASEAPI int __cdecl MSVCRT$_atoi(const char* str);
WINBASEAPI int __cdecl MSVCRT$sprintf_s(char* buffer, size_t sizeOfBuffer, const char* format, ...);
WINBASEAPI unsigned long long __cdecl MSVCRT$_strtoull(const char* strSource, char** endptr, int base);
WINBASEAPI __int64 __cdecl MSVCRT$_strtoi64(const char* strSource, char** endptr, int base);
WINBASEAPI void __cdecl MSVCRT$_cexit();
WINBASEAPI int __cdecl MSVCRT$strcmp(const char* string1, const char* string2);
WINBASEAPI int __cdecl MSVCRT$wcscmp(const wchar_t* string1, const wchar_t* string2);

//K32
WINBASEAPI int WINAPI KERNEL32$WideCharToMultiByte (UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
WINBASEAPI int WINAPI  KERNEL32$MultiByteToWideChar ( UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
WINBASEAPI DECLSPEC_NORETURN VOID WINAPI KERNEL32$ExitThread (DWORD dwExitCode);
WINBASEAPI HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL hMem);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA (LPCSTR lpLibFileName);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress (HMODULE hModule, LPCSTR lpProcName);
WINBASEAPI void * WINAPI KERNEL32$VirtualAlloc (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI int WINAPI KERNEL32$VirtualFree (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
WINBASEAPI BOOL WINAPI KERNEL32$CreatePipe(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateThread (LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject (HANDLE hHandle, DWORD dwMilliseconds);
WINBASEAPI BOOL WINAPI KERNEL32$PeekNamedPipe(HANDLE hNamedPipe, LPVOID lpBuffer, DWORD nBufferSize, LPDWORD lpBytesRead, LPDWORD lpTotalBytesAvail, LPDWORD lpBytesLeftThisMessage);
WINBASEAPI WINBOOL WINAPI KERNEL32$ReadFile (HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (VOID);
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI HWND  WINAPI KERNEL32$GetConsoleWindow(void);
WINBASEAPI BOOL WINAPI KERNEL32$AllocConsole(void);
WINBASEAPI BOOL WINAPI KERNEL32$FreeConsole(void);
WINBASEAPI HANDLE WINAPI KERNEL32$GetStdHandle(DWORD nStdHandle);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplatefile);
WINBASEAPI BOOL WINAPI KERNEL32$SetStdHandle(DWORD nStdHandle, HANDLE hHandle);
WINBASEAPI void WINAPI KERNEL32$SetLastError(DWORD dwErrCode);
WINBASEAPI BOOL WINAPI KERNEL32$FreeConsole(void);
WINBASEAPI void WINAPI KERNEL32$Sleep(DWORD dwMilliseconds);
WINBASEAPI DWORD WINAPI KERNEL32$GetProcessId(HANDLE Process);
WINBASEAPI HWND WINAPI KERNEL32$GetConsoleWindow(void);
WINBASEAPI HLOCAL WINAPI KERNEL32$LocalAlloc(UINT uFlags, SIZE_T uBytes); 
WINBASEAPI DWORD WINAPI KERNEL32$GetCurrentProcessId();
WINBASEAPI DWORD WINAPI KERNEL32$ProcessIdToSessionId(DWORD dwProcessID, DWORD* pSessionId);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
WINBASEAPI BOOL WINAPI KERNEL32$Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
WINBASEAPI BOOL WINAPI KERNEL32$Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI BOOL WINAPI KERNEL32$TerminateProcess(HANDLE hProcess, UINT uExitcode);
WINBASEAPI DWORD WINAPI KERNEL32$GetProcessHeaps(DWORD NumberOfHeaps, PHANDLE ProcessHeaps);
WINBASEAPI BOOL WINAPI KERNEL32$QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount);
WINBASEAPI BOOL WINAPI KERNEL32$QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency);
WINBASEAPI BOOL WINAPI KERNEL32$TerminateThread(HANDLE hthread, DWORD dwExitCode);
WINBASEAPI BOOL WINAPI KERNEL32$FreeLibrary(HANDLE hLibModule);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpfOldProtect);
WINBASEAPI DWORD WINAPI KERNEL32$QueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData);
WINBASEAPI DWORD WINAPI KERNEL32$SuspendThread(HANDLE hThread);
WINBASEAPI BOOL WINAPI KERNEL32$SetThreadContext(HANDLE hThread, CONTEXT *lpContext);
WINBASEAPI BOOL WINAPI KERNEL32$GetThreadContext(HANDLE hThread, LPCONTEXT lpContext);
WINBASEAPI DWORD WINAPI KERNEL32$ResumeThread(HANDLE hThread);
WINBASEAPI DWORD WINAPI KERNEL32$GetThreadId(HANDLE hThread);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
WINBASEAPI DWORD WINAPI KERNEL32$GetModuleFileNameA(HANDLE hModule, LPSTR lpFilename, DWORD nSize);
WINBASEAPI BOOL WINAPI KERNEL32$GetFileSizeEx(HANDLE hFile, PLARGE_INTEGER lpFileSize);

//PSAPI
WINBASEAPI BOOL WINAPI PSAPI$EnumProcessModules(HANDLE HProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded);

//USER32
WINBASEAPI BOOL WINAPI USER32$ShowWindow(HWND hWnd, int nCmdShow);
WINBASEAPI int WINAPI USER32$MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

//SHELL32
WINBASEAPI LPWSTR* WINAPI SHELL32$CommandLineToArgvW(LPCWSTR lpCMdLine, int* pNumArgs);

//NTDLL
WINBASEAPI NTSTATUS NTAPI NTDLL$NtQueryInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

//MSVCRT
#define malloc                      MSVCRT$malloc
#define free                        MSVCRT$free
#define strlen                      MSVCRT$strlen
#define memcpy                      MSVCRT$memcpy
#define calloc                      MSVCRT$calloc
#define memset                      MSVCRT$memset
#define wcslen                      MSVCRT$wcslen
#define _stricmp                    MSVCRT$_stricmp
#define _dup                        MSVCRT$_dup
#define _dup2                       MSVCRT$_dup2
#define _open_osfhandle             MSVCRT$_open_osfhandle
#define _fileno                     MSVCRT$_fileno
#define setvbuf                     MSVCRT$setvbuf
#define _close                      MSVCRT$_close
#define _flushall                   MSVCRT$_flushall
#define printf                      MSVCRT$printf
#define freopen_s                   MSVCRT$freopen_s
#define __iob_func                  MSVCRT$__iob_func
#define fclose                      MSVCRT$fclose
#define _itoa                       MSVCRT$_itoa
#define _atoi                       MSVCRT$_atoi
#define sprintf_s                   MSVCRT$sprintf_s
#define _strtoull                   MSVCRT$_strtoull
#define _strtoi64                   MSVCRT$_strtoi64
#define _cexit 						MSVCRT$_cexit
#define strcmp 						MSVCRT$strcmp
#define wcscmp 						MSVCRT$wcscmp
#define sscanf 						MSVCRT$sscanf


//K32
#define ReadProcessMemory           KERNEL32$ReadProcessMemory
#define GetCurrentProcess           KERNEL32$GetCurrentProcess 
#define WideCharToMultiByte         KERNEL32$WideCharToMultiByte
#define MultiByteToWideChar         KERNEL32$MultiByteToWideChar
#define ExitThread                  KERNEL32$ExitThread
#define LocalFree                   KERNEL32$LocalFree
#define LoadLibraryA                KERNEL32$LoadLibraryA
#define GetProcAddress              KERNEL32$GetProcAddress
#define VirtualAlloc                KERNEL32$VirtualAlloc
#define VirtualFree                 KERNEL32$VirtualFree
#define CreatePipe                  KERNEL32$CreatePipe
#define CreateThread                KERNEL32$CreateThread
#define WaitForSingleObject         KERNEL32$WaitForSingleObject
#define PeekNamedPipe               KERNEL32$PeekNamedPipe
#define ReadFile                    KERNEL32$ReadFile
#define GetLastError                KERNEL32$GetLastError
#define CloseHandle                 KERNEL32$CloseHandle
#define GetConsoleWindow            KERNEL32$GetConsoleWindow
#define AllocConsole                KERNEL32$AllocConsole
#define FreeConsole                 KERNEL32$FreeConsole
#define GetStdHandle                KERNEL32$GetStdHandle
#define SetStdHandle                KERNEL32$SetStdHandle
#define CreateFileA                 KERNEL32$CreateFileA
#define SetLastError                KERNEL32$SetLastError
#define FreeConsole                 KERNEL32$FreeConsole
#define Sleep                       KERNEL32$Sleep
#define GetProcessId                KERNEL32$GetProcessId
#define GetConsoleWindow            KERNEL32$GetConsoleWindow
#define LocalAlloc 					KERNEL32$LocalAlloc
#define GetCurrentProcessId 		KERNEL32$GetCurrentProcessId
#define ProcessIdToSessionId 		KERNEL32$ProcessIdToSessionId
#define CreateToolhelp32Snapshot 	KERNEL32$CreateToolhelp32Snapshot
#define Process32First				KERNEL32$Process32First
#define Process32Next 				KERNEL32$Process32Next
#define OpenProcess 				KERNEL32$OpenProcess
#define TerminateProcess 			KERNEL32$TerminateProcess
#define GetProcessHeaps 			KERNEL32$GetProcessHeaps
#define QueryPerformanceCounter 	KERNEL32$QueryPerformanceCounter
#define QueryPerformanceFrequency 	KERNEL32$QueryPerformanceFrequency
#define TerminateThread 			KERNEL32$TerminateThread
#define FreeLibrary 				KERNEL32$FreeLibrary
#define VirtualProtect 				KERNEL32$VirtualProtect
#define SuspendThread 				KERNEL32$SuspendThread
#define GetThreadContext 			KERNEL32$GetThreadContext
#define SetThreadContext 			KERNEL32$SetThreadContext
#define ResumeThread 				KERNEL32$ResumeThread
#define GetThreadId 				KERNEL32$GetThreadId
#define OpenThread 					KERNEL32$OpenThread
#define GetModuleFileNameA 			KERNEL32$GetModuleFileNameA
#define GetFileSizeEx 				KERNEL32$GetFileSizeEx

//PSAPI
#define EnumProcessModules 			PSAPI$EnumProcessModules

//USER32
#define ShowWindow                  USER32$ShowWindow
#define MessageBoxA 				USER32$MessageBoxA

//SHELL32
#define CommandLineToArgvW          SHELL32$CommandLineToArgvW

//NTDLL
#define NtQueryInformationProcess   NTDLL$NtQueryInformationProcess

//Structures invovled in parsing PEB

#define RTL_MAX_DRIVE_LETTERS 32

typedef UNICODE_STRING* PUNICODE_STRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
	USHORT                  Flags;
	USHORT                  Length;
	ULONG                   TimeStamp;
	UNICODE_STRING          DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;


typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, * PCURDIR;

typedef struct _uRTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

	ULONG EnvironmentSize;
	ULONG EnvironmentVersion;
	PVOID PackageDependencyData; //8+
	ULONG ProcessGroupId;
	// ULONG LoaderThreads;
} uRTL_USER_PROCESS_PARAMETERS, * uPRTL_USER_PROCESS_PARAMETERS;

struct MemAddrs {
	BYTE* pImageBase;
	BYTE* pBackupImage;
	DWORD AddressOfEntryPoint;
	DWORD SizeOfImage;
	FILE* fout;
	FILE* ferr;
	HANDLE hreadout;
	HANDLE hwriteout;
	int fo;
	DWORD dwNumModules;
	BOOL bCloseFHandles;
};