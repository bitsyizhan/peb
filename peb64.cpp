// peb64.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>

extern "C" PVOID64 _cdecl GetPebX64();

int main(int argc, char* argv[])
{
	PVOID64 Peb = 0;
	Peb = GetPebX64();
	printf("Peb is 0x%p\n", Peb);

	void *pebAddr = *((void **)((BYTE*)NtCurrentTeb() + 0x60));  // TEB->ProcessEnvironmentBlockÒ²¾ÍÊÇPEB
	void *ldrAddr = *((void **)((BYTE*)pebAddr + 0x18)); // PEB->Ldr
	void *inLoadOrderLinks = *((void **)((BYTE*)ldrAddr + 0x10)); // PEB->Ldr->InLoadOrderLinks->FLink 
	void *fLink = inLoadOrderLinks; // PEB->Ldr->InLoadOrderLinks->FLink  
	void *p = fLink;
	void *dllBase = NULL;
	void *baseDllName = NULL;
	void *fullDllName = NULL;
	void *entryPoint = NULL;
	void *sizeOfImage = NULL;

	printf("PEB = 0x%p\n", Peb);
	printf("PEB ADDRESS = 0x%p\n", pebAddr);
	printf("LDR ADDRESS = 0x%p\n", ldrAddr);

	do
	{
		dllBase = *((void **)((BYTE*)p + 0x30));
		baseDllName = *((void **)((BYTE*)p + 0x58 + 0x8));
		fullDllName = *((void **)((BYTE*)p + 0x48 + 0x8));
		entryPoint = *((void **)((BYTE*)p + 0x38));
		sizeOfImage = *((void **)((BYTE*)p + 0x40));

		printf("\tModuleName:%S\n", (wchar_t*)baseDllName);
		printf("\t\tBase Address:0x%p\n", dllBase);
		printf("\t\tFull Module Name:%S\n", (wchar_t*)fullDllName);
		printf("\t\tentryPoint:0x%p\n", entryPoint);
		printf("\t\timageOfSize:0x%p\n", sizeOfImage);

		p = *(void **)p;  // p->InLoadOrderLinks->FLink

	} while (p!= fLink);

	
	return 0;
}
