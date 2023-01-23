#include "bofdefs.h"
#include "beacon.h"

#pragma warning (disable: 4996)
#define _CRT_SECURE_NO_WARNINGS
#define ARRAY_MODULES_SIZE 128

struct MemAddrs *pMemAddrs;
BOOL bUnloadLibraries;

FILE *__cdecl __acrt_iob_funcs(unsigned index)
{
    return &(__iob_func()[index]);
}

#define stdin (__acrt_iob_funcs(0))
#define stdout (__acrt_iob_funcs(1))
#define stderr (__acrt_iob_funcs(2))


void cleanupModules(DWORD numberOfLoadedModules) {
    DWORD cbNeeded = -1;
	char modName[255] = {0};

	HMODULE* hMods = calloc(ARRAY_MODULES_SIZE, sizeof(HMODULE));

	//Populate list of DLL's in process and then iterate over them (starting from the index of the number of DLL's loaded before peload) freeing each one
	//Note that while the FreeLibrary calls seem to succeed (GetLastError returns 0), sometimes certain DLL's don't get unloaded...
    if (EnumProcessModules((HANDLE)-1, hMods, ARRAY_MODULES_SIZE * sizeof(HMODULE), &cbNeeded)) {
        for (DWORD i = numberOfLoadedModules; i < (cbNeeded / sizeof(HMODULE)); i++) {
			SetLastError(0);
            FreeLibrary(hMods[i]);

			/* //Debug- print module name of each DLL that we try and free.
			memset(modName, 0, 255);
			GetModuleFileNameA(hMods[i], modName, 255);
			BeaconPrintf(CALLBACK_OUTPUT, "Freeing module: %s GetLastError: %d\n", modName, GetLastError());
			*/
        }
		BeaconPrintf(CALLBACK_OUTPUT, "Attempted to free DLL's loaded by PE!");
    }
	free(hMods);

    return;
}

void KillConhost()
{
	HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    DWORD result;
	char* processname = "conhost.exe";

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcessSnap)
		return;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process,
    // and exit if unsuccessful
    if (!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap); // clean the snapshot object
		return;
    }

	//Get current PID
	DWORD procID = GetCurrentProcessId();

	//Iterate over every process, find all the conhost.exe
    do
    {   		
        if (0 == strcmp(processname, pe32.szExeFile))
        {
			//If conhost.exe parent PID matches current procID (beacon), terminate the conhost
            if(pe32.th32ParentProcessID == procID)
			{
				HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0, (DWORD)pe32.th32ProcessID);
				TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
				break;
			}
        }
		
    } while (Process32Next(hProcessSnap, &pe32));
    CloseHandle(hProcessSnap);

	return;
}

BOOL peUnload()
{
	//Clean-up handles
	//Close write-end stdout and stderr pipe handles that were converted using open_osfhandle
	_close(pMemAddrs->fo);

	//Close read-end stdout and stderr pipe handles
	CloseHandle((VOID*)pMemAddrs->hreadout);

	//Close re-opened stdout/stderr FILE* fout and ferr
	//Default is to perform this action
	//If we timed out during execution we assume something went wrong and don't try to close these as it can cause beacon to hang.
	
	if(pMemAddrs->bCloseFHandles == TRUE)
	{
		fclose(pMemAddrs->fout);
		fclose(pMemAddrs->ferr);
	}
	
	//Free conhost.exe
	FreeConsole();

	//Sometimes conhost.exe doesn't actually exit (observed with powershell.exe), so walk process list and kill conhost.exe if it exists
	KillConhost();

	//Free PE memory
	memset((void*)pMemAddrs->pImageBase, 0, pMemAddrs->SizeOfImage);
	VirtualFree((LPVOID)pMemAddrs->pImageBase, 0, MEM_RELEASE);

	//Free Backup PE memory
	memset((void*)pMemAddrs->pBackupImage, 0, pMemAddrs->SizeOfImage);
	VirtualFree((LPVOID)pMemAddrs->pBackupImage, 0, MEM_RELEASE);

	//If bUnloadLibraries == TRUE, unload DLL's.  This is default, but some PE's will crash if you try and unload the DLL's.
	//Observed with Powershell.exe, believe this is due to CLR being loaded by Powershell.
	if(bUnloadLibraries)
		cleanupModules(pMemAddrs->dwNumModules);

	//Free pMemAddr struct
	free(pMemAddrs);

	BeaconPrintf(CALLBACK_OUTPUT, "peunload successful");
}

int go(IN PCHAR Buffer, IN ULONG Length) 
{
	datap parser;
	BeaconDataParse(&parser, Buffer, Length);

	int dataextracted = 0;    
	char* pEnd;
	
	char* pMemAddrstr = BeaconDataExtract(&parser, &dataextracted);
	pMemAddrs = (struct MemAddrs*)_strtoi64(pMemAddrstr, &pEnd, 10);
	bUnloadLibraries = BeaconDataInt(&parser);

	/* //Debug
	BeaconPrintf(CALLBACK_OUTPUT, "beaconarg pMemAddrstr is: %s", pMemAddrstr);
	BeaconPrintf(CALLBACK_OUTPUT, "pMemAddrs is: %p!", pMemAddrs);
	BeaconPrintf(CALLBACK_OUTPUT, "bUnloadLibraries is: %d!", bUnloadLibraries);
	*/

	//Clear PE from memory and clean up handles, DLL's, etc
	peUnload();

	return 0;
}