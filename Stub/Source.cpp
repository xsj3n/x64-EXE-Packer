#include <iostream>
#include <cstdlib>
#include <Windows.h>



#define VirtAddr2Pointer(T, VirtualBase, VirtualOffset) (T)((PBYTE)VirtualBase + VirtualOffset)
extern "C" DWORDLONG * _fastcall Dncr_lilith(DWORDLONG * data, DWORDLONG[2], DWORDLONG len_of_data);

struct MemoryPE
{
	LPVOID pPEBase = NULL;
	PIMAGE_NT_HEADERS64 cpNTROOT = NULL;

};

void FlagCorrect(PIMAGE_SECTION_HEADER pSec)
{
	/*Needs to set writable permissions on the stub's headers in order to correct XSS section permission to please DEP*/
	DWORD pOld = NULL;
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)GetModuleHandleA(NULL);
	PIMAGE_NT_HEADERS64 pNT = VirtAddr2Pointer(PIMAGE_NT_HEADERS64, pDos, pDos->e_lfanew);
	DWORD dHeaderSize = pNT->OptionalHeader.SizeOfHeaders;
	int x = VirtualProtect(pDos, dHeaderSize, PAGE_READWRITE, &pOld);
	if (x == 0)
	{
		printf("[-] Stub Failure to Self-Modify\n");
		exit(1);
	}

	DWORD CodeFlag = 0x60000020; // Flag for executeable code to be set on the XSS section 
	pSec->Characteristics = CodeFlag;


	x = VirtualProtect(pDos, dHeaderSize, PAGE_READONLY, &pOld);
	if (x == 0)
	{
		printf("[-] Stub Failure to Self-Modify\n");
		exit(1);
	}

}





LPVOID Unpack(LPVOID SrcBuffer, DWORD sz) {

	LPVOID lptmpbuf = malloc(sz);
	if (lptmpbuf == NULL) {
		printf("[-] Failure allocating w/ malloc..\n");
		exit(1);
	}
	memcpy_s(lptmpbuf, sz, SrcBuffer, sz);
	
	PBYTE data_ptr = (PBYTE)lptmpbuf;
	for (int i = 0; i < sz; ++i) {
		*data_ptr ^= 80;
		data_ptr++;
	}

	return lptmpbuf;
}

LPVOID Unpack_Dncr_L(LPVOID SrcBuffer, DWORD sz) {


	if (sz % 8 != 0) {
		printf("[-] Provided byte count for unpacking not aligned to 8 bytes\n");
		exit(1);
	}


	DWORDLONG k[2] = { 0x4226452948404D63, 0x294A404E63526655 };

	LPVOID lptmpbuf = malloc(sz);
	if (lptmpbuf == NULL) {
		printf("[-] Failure allocating w/ malloc..\n");
		exit(1);
	}
	memcpy_s(lptmpbuf, sz, SrcBuffer, sz);

	PDWORDLONG data_ptr = PDWORDLONG(lptmpbuf);
	Dncr_lilith(data_ptr, k, sz / 8);

	return lptmpbuf;
}












// Byte count = XSS.misc.virtualsize || SrcBuffer = Pointer to start of Src Data in XSS Section
LPVOID MapData(LPVOID SrcBuffer, DWORD dByteCount, PIMAGE_SECTION_HEADER pXSSHeader)
{
	printf("============== MAPPING HEADERS\n");



	//------------Header mapping
	LPVOID lpunpacked = Unpack_Dncr_L(SrcBuffer, dByteCount);
	PIMAGE_DOS_HEADER pSrcDos = (PIMAGE_DOS_HEADER)lpunpacked;
	PIMAGE_NT_HEADERS64 pNTSrc = VirtAddr2Pointer(PIMAGE_NT_HEADERS64, lpunpacked, pSrcDos->e_lfanew);
	PIMAGE_SECTION_HEADER pSecSrc = IMAGE_FIRST_SECTION(pNTSrc);

	// allocate mem & transfer from section
	LPVOID lpVirtBase = VirtualAlloc(NULL, pNTSrc->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (lpVirtBase == NULL)
	{
		printf("[-] Failure Allocating Memory\n");
		exit(1);
	}


	memcpy_s(lpVirtBase, pNTSrc->OptionalHeader.SizeOfImage, lpunpacked, pNTSrc->OptionalHeader.SizeOfHeaders);



	PIMAGE_DOS_HEADER pDOs = (PIMAGE_DOS_HEADER)lpVirtBase;
	PIMAGE_NT_HEADERS64 pNT = VirtAddr2Pointer(PIMAGE_NT_HEADERS64, lpVirtBase, pDOs->e_lfanew);
	PIMAGE_SECTION_HEADER pSecHeader = IMAGE_FIRST_SECTION(pNT);


	printf("\t[*] Virtual PE Image Base: 0x%p\n", lpVirtBase);
	printf("\t[*] Virtual PE Image Size: 0x%x\n", pNT->OptionalHeader.SizeOfImage);
	printf("\t[*] Virtual PE Signature: 0x%x\n", pNT->Signature);



	//-------------Section Mapping
	printf("============== MAPPING SECTIONS\n");
	printf("\t===== Virtual PE Image Section Count: %d\n", pNT->FileHeader.NumberOfSections);






	for (; pSecHeader->VirtualAddress != 0; pSecHeader++)
	{
		LPVOID lpDest = VirtAddr2Pointer(LPVOID, lpVirtBase, pSecHeader->VirtualAddress);
		LPVOID lpDataSrc = VirtAddr2Pointer(LPVOID, lpunpacked, pSecSrc->PointerToRawData);

		printf("\t===== %s\n", (char*)pSecHeader->Name);
		printf("\t\t[*] Loading at VirtualAddress: 0x%p\n", lpDest);
		printf("\t\t[*] Section Raw Data Count:    0x%x\n", pSecHeader->SizeOfRawData);


		if (pSecHeader->SizeOfRawData > 0) memcpy_s(lpDest, pNTSrc->OptionalHeader.SizeOfImage, lpDataSrc, pSecHeader->SizeOfRawData);
		else memset(lpDest, 0, pSecHeader->Misc.VirtualSize);


		pSecSrc++;
	}

	return lpVirtBase;

}



MemoryPE LoadPEFromSection()
{
	LPVOID hCurrentProcess = NULL;
	LPVOID lpVirtBase = NULL;


	MemoryPE sMemPE;

	PIMAGE_DOS_HEADER pDosHead = NULL;
	PIMAGE_NT_HEADERS64 pNTHead = NULL;
	PIMAGE_SECTION_HEADER pSecHeadog = NULL;



	// Get Mem Image base of current process && Err Check
	hCurrentProcess = GetModuleHandleA(NULL);
	if (hCurrentProcess == NULL)
	{
		printf("[-] Failed to get Base Memory Address\n");
		exit(1);
	}


	// Parse PE
	pDosHead = (PIMAGE_DOS_HEADER)hCurrentProcess;
	pNTHead = VirtAddr2Pointer(PIMAGE_NT_HEADERS64, hCurrentProcess, pDosHead->e_lfanew);
	pSecHeadog = IMAGE_FIRST_SECTION(pNTHead);




	for (int i = 0; i < pNTHead->FileHeader.NumberOfSections; i++)
	{

		PIMAGE_SECTION_HEADER pSecHead = (PIMAGE_SECTION_HEADER)((DWORDLONG)pSecHeadog + (IMAGE_SIZEOF_SECTION_HEADER * i));

		BYTE cTargetName[8] = ".xss\0\0\0";
		BYTE cSecName[8] = { pSecHead->Name[0],pSecHead->Name[1], pSecHead->Name[2], pSecHead->Name[3], pSecHead->Name[4], pSecHead->Name[5], pSecHead->Name[6], pSecHead->Name[7] };



		//cout << (char*)pSecHead->Name << "\n";
		//cout << "\n";

		printf("[*} Searching Section: %s\n", cSecName);
		if (strcmp((char*)cTargetName, (char*)cSecName) == 0)
		{
			DWORD dSize = pSecHead->SizeOfRawData;
			PBYTE bSecData = VirtAddr2Pointer(PBYTE, hCurrentProcess, pSecHead->VirtualAddress);
			FlagCorrect(pSecHead);



			printf("[*] XSS Section Found\n");

			// returns pointer to image in memory 
			lpVirtBase = MapData(bSecData, pSecHead->Misc.VirtualSize, pSecHead);





			sMemPE.pPEBase = lpVirtBase;
			return sMemPE;




		}


	}

}



MemoryPE ParseUnpackedPE()
{
	// Transfered pointers of PE DAT in memory
	MemoryPE sMemPE = LoadPEFromSection();

	// NT + DOS
	PIMAGE_DOS_HEADER pDOS = (PIMAGE_DOS_HEADER)sMemPE.pPEBase;
	PIMAGE_NT_HEADERS64 pNT = VirtAddr2Pointer(PIMAGE_NT_HEADERS64, sMemPE.pPEBase, pDOS->e_lfanew);
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNT);


	// Save the nt headers for later use as just about all the useful info from the first few headers are in there
	sMemPE.cpNTROOT = pNT;


	// Print some details for Sanity

	printf("[*]======== NT OPTIONAL HEADERS ========\n");
	printf("\t[*] Virtual NT Magic:           0x%x\n", pNT->OptionalHeader.Magic);
	printf("\t[*] Virtual MajorLinkerVersion: 0x%x\n", pNT->OptionalHeader.MajorLinkerVersion);
	printf("\t[*] Virtual MinorLinkerVersion: 0x%x\n", pNT->OptionalHeader.MinorLinkerVersion);
	printf("\t[*] Virtual SizeOfCode:         0x%x\n", pNT->OptionalHeader.SizeOfCode);
	printf("\t[*] Virtual SizeOfUninitData:   0x%x\n", pNT->OptionalHeader.SizeOfUninitializedData);


	// ------------- LOGGING ---------------//
	printf("[*] Number of Sections: %d\n", pNT->FileHeader.NumberOfSections);



	// --------------IMPORT DESCRIPTOR NAVIGATION----------//
	/*
	 The Import descrip array contains elements which are also
	 two arrays.

	 ImportDescrip[i] -> OG THUNK -> IDT
	 ImportDescrip[i] -> 1st THUNK - IAT

	 IDT is the map you read from- the IAT is the actual path
	 your program shall take. Read required elements from IDT
	 -> IAT
	*/
	// -----------------------------------------------------//
	DWORD dImportRVA = pNT->OptionalHeader.DataDirectory[1].VirtualAddress;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = VirtAddr2Pointer(PIMAGE_IMPORT_DESCRIPTOR, sMemPE.pPEBase, dImportRVA);




	printf("[*] Searching For DLL Names...\n");


	for (; pImportDescriptor->Name != NULL; pImportDescriptor++)
	{
		LPCSTR cModuleName = VirtAddr2Pointer(LPCSTR, sMemPE.pPEBase, pImportDescriptor->Name);

		HMODULE hImportModule = LoadLibrary(cModuleName);
		if (hImportModule == NULL)
		{


			printf("[-] Failure Loaidng Module...\n");
		}

		printf("\n\n============ %s \n", cModuleName);


		PIMAGE_THUNK_DATA64 pIDTEntry = NULL;
		if (pImportDescriptor->OriginalFirstThunk != NULL) pIDTEntry = VirtAddr2Pointer(PIMAGE_THUNK_DATA64, sMemPE.pPEBase, pImportDescriptor->OriginalFirstThunk);
		else pIDTEntry = VirtAddr2Pointer(PIMAGE_THUNK_DATA64, sMemPE.pPEBase, pImportDescriptor->FirstThunk);
		PIMAGE_THUNK_DATA64 pIATEntry = VirtAddr2Pointer(PIMAGE_THUNK_DATA64, sMemPE.pPEBase, pImportDescriptor->FirstThunk);

		// Patch addresses in IAT 
		for (; pIDTEntry->u1.AddressOfData; pIDTEntry++, pIATEntry++)
		{
			LPVOID lpFunctionAddress = NULL;
			// Get address of function name
			DWORD lpFunctionNameRVA = pIDTEntry->u1.AddressOfData;

			PIMAGE_IMPORT_BY_NAME pImportNameStruct = NULL;

			if (IMAGE_SNAP_BY_ORDINAL64(pIDTEntry->u1.Ordinal) == 0)
			{
				pImportNameStruct = VirtAddr2Pointer(PIMAGE_IMPORT_BY_NAME, sMemPE.pPEBase, lpFunctionNameRVA);

				char* lpFunctionName = (char*)&(pImportNameStruct->Name);
				printf("\t\t[*] Loading Fucntion %s\n", lpFunctionName);

				lpFunctionAddress = GetProcAddress(hImportModule, lpFunctionName);
				if (lpFunctionAddress == NULL)
				{
					printf("\t\t[-] Failure Getting Function Address\n");
					exit(1);
				}


			}
			else
			{

				lpFunctionAddress = GetProcAddress(hImportModule, (LPSTR) & (pIDTEntry->u1.Ordinal));

				if (lpFunctionAddress == NULL)
				{
					printf("\t\t[-] Failure Getting Function Address\n");
					exit(1);
				}
				printf("\t\t[*] Loading By Ordinal: 0x%p", pIDTEntry->u1.Ordinal);
			}




			pIATEntry->u1.Function = (DWORDLONG)lpFunctionAddress;
		}





	}




	return sMemPE;
}




MemoryPE RelocManage()
{

	// Transfer pointers for PE in memory + NT Header
	MemoryPE sMemPE = ParseUnpackedPE();



	// Calculate how much we shift the Image base as compared to where it expects to be loaded
	DWORDLONG dDeltaShift = ((DWORDLONG)sMemPE.pPEBase - sMemPE.cpNTROOT->OptionalHeader.ImageBase);
	DWORD dOffset = sMemPE.cpNTROOT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

	printf("\n\n============ RELOCATIONS ============\n\n");
	printf("\t[*] Image Base: 0x%p\n", (DWORDLONG)sMemPE.pPEBase);
	printf("\t[*] Delta: 0x%p\n", (DWORDLONG)dDeltaShift);




	if (sMemPE.cpNTROOT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0 && dDeltaShift != 0)
	{


		// Init pointer for the Image base relocations array || const, make copy in iteration below, something something, immutable data, something something
		PIMAGE_BASE_RELOCATION pBaseReloc = VirtAddr2Pointer(PIMAGE_BASE_RELOCATION, sMemPE.pPEBase, dOffset);
		// Gather count of elements by : (SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD) = Relocation Element Count Array | from MSDN



		printf("\t[*] Relocations present...\n");

		int icount = 0;

		// while (pBaseReloc->VirtualAddress != 0) || this potentially works, but changing it for now. may change back later to see if it's a viable check
		while (pBaseReloc->VirtualAddress != 0)
		{

			DWORD dRelocElementCount = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			printf("\t[*] Number of Relocations in Block: %d\n", dRelocElementCount);
			// Iterate via copy's index in loop
			for (INT i = 0; i < dRelocElementCount; ++i)
			{
				// Add size of base relocations to the base of the relocation base in memory to get the start of relocation word arrays
				PWORD pwRelocDat = (PWORD)(pBaseReloc + 1);

				// wReloc is 16-bits (2-bytes), so get higher 4 bits by shifting 12 bits to the right
				UINT iType = pwRelocDat[i] >> 12;

				// Offset is in the last 12 bits - 0xFFF = 0000 0000 1111 1111 1111 | ---- ----
				DWORD iOffset = pwRelocDat[i] & 0x0FFF;
				// pointer to a x64 bit address in memory we must alter
				PDWORDLONG pAddrChange = (PDWORDLONG)((PBYTE)sMemPE.pPEBase + pBaseReloc->VirtualAddress + iOffset);

				switch (iType) {

				case IMAGE_REL_BASED_DIR64:
					*pAddrChange += dDeltaShift;
					break;

				case IMAGE_REL_BASED_HIGHLOW:
					*pAddrChange += (DWORD)dDeltaShift;
					break;
				case 0x0:
					continue;
				default:
					printf("[-] Unrecognized Reloc Type: 0x%x\n", iType);
					exit(1);

				}

			}
			// iterate by adding size of block to relocation base at end of while 
			pBaseReloc = VirtAddr2Pointer(PIMAGE_BASE_RELOCATION, pBaseReloc, pBaseReloc->SizeOfBlock);
			icount++;
		}
		printf("========Relocation Done - Blocks Processed: %d\n", icount);
	}

	return sMemPE;
}




MemoryPE Setup()
{
	MemoryPE sMemPE = RelocManage();
	PIMAGE_SECTION_HEADER pSecRef = IMAGE_FIRST_SECTION(sMemPE.cpNTROOT);

	printf("\n========VIRTUAL PERMISSIONS\n\n");
	
	DWORD dOldone;
	xx = VirtualProtect(sMemPE.pPEBase, sMemPE.cpNTROOT->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &dOldone);

	for (int i = 0; i < sMemPE.cpNTROOT->FileHeader.NumberOfSections; ++i)
	{
		PIMAGE_SECTION_HEADER pSecHead = (PIMAGE_SECTION_HEADER)((DWORDLONG)pSecRef + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
		BYTE* pTarget = (BYTE*)((DWORDLONG)sMemPE.pPEBase + pSecHead->VirtualAddress);
		DWORD dOld = NULL;
		char* cSecName = (char*)pSecHead->Name;
		DWORD dSPerms = pSecHead->Characteristics;
		int x = 0;

		CONST DWORD dImageCodeFlag = 0x60000020; // Read (0x40000000) + Execute (0x40000000) + Code Flag (0x20)
		CONST DWORD dImageInitDatFlag = 0x40000040; // Read (0x40000000) + Inited Data (0x40)


		switch (dSPerms) {
		case dImageCodeFlag:
			x = VirtualProtect(pTarget, pSecHead->Misc.VirtualSize, dImageCodeFlag, &dOld);
			if (x == 0) printf("[-] Virtual permission setting failed\n");
			printf("\t[*] %s Section Permissions: IMAGE_SCN_CNT_CODE\n", cSecName);
			break;
		default:
			x = VirtualProtect(pTarget, pSecHead->Misc.VirtualSize, PAGE_READWRITE, &dOld);
			if (x == 0) printf("[-] Virtual permission setting failed\n");
			printf("\t[*] %s Section Permissions: IMAGE_SCN_MEM_READ\n", cSecName);
			break;

		}
	}	
	return sMemPE;
}







int main()
{
	// setup will load a pe image from a section into memory, patch imports + relocations, then set virtual permissions
	MemoryPE sMemPE = Setup();


	// Derive entry point 
	LPVOID dEntry = VirtAddr2Pointer(LPVOID, sMemPE.pPEBase, sMemPE.cpNTROOT->OptionalHeader.AddressOfEntryPoint);

	printf("\n========== PACKED PROGRAMS OUTPUT:\n\n");

	void (*EnterNow)(void) = (void(*)())dEntry;
	EnterNow();



	return 0;

}
