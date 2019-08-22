// peb.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

//peb.cpp  
//compile:cl peb.cpp  
#include <windows.h>  

#define CONTAINING_RECORD(address, type, field) ((type *)((PCHAR)(address)-(ULONG_PTR)(&((type *)0)->field)))

typedef struct _UNICODE_STRING {
	USHORT  Length;
	USHORT  MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA
{
	DWORD Length;
	UCHAR Initialized;
	UINT8 _PADDING0_[0x3];
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
}PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	DWORD SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	DWORD Flags;
	WORD LoadCount;
	WORD TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	DWORD CheckSum;
	DWORD TimeDateStamp;
	PVOID LoadedImports;
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR SpareBool;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
}PEB, *PPEB;

/*
int main(int argc, char *argv[])
{
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = NULL;
	PLIST_ENTRY pListEntryStart = NULL, pListEntryEnd = NULL;
	PPEB_LDR_DATA pPebLdrData = NULL;
	PPEB pPeb = NULL;

	//1、获取PEB
	__asm
	{		
		mov eax, dword ptr fs : [30h];
		mov pPeb, eax
	}

	//2、通过_PEB的Ldr成员获取_PEB_LDR_DATA结构  
	pPebLdrData = pPeb->Ldr;

	printf("\nInMemoryOrderModuleList\n");
	//3、通过_PEB_LDR_DATA的InMemoryOrderModuleList成员获取_LIST_ENTRY结构  
	pListEntryStart = pListEntryEnd = pPebLdrData->InMemoryOrderModuleList.Flink;
	//查找所有已载入到内存中的模块  
	do
	{
		//4、通过_LIST_ENTRY的Flink成员获取_LDR_DATA_TABLE_ENTRY结构  
		pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(pListEntryStart, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		//5、输出_LDR_DATA_TABLE_ENTRY的BaseDllName或FullDllName成员信息  
		printf("%S\n", pLdrDataEntry->BaseDllName.Buffer);

		pListEntryStart = pListEntryStart->Flink;

	} while (pListEntryStart != pListEntryEnd);

	printf("\nInLoadOrderModuleList\n");
	pListEntryStart = pListEntryEnd = pPebLdrData->InLoadOrderModuleList.Flink;
	//查找所有已载入到内存中的模块  
	do
	{
		//4、通过_LIST_ENTRY的Flink成员获取_LDR_DATA_TABLE_ENTRY结构  
		pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(pListEntryStart, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		//5、输出_LDR_DATA_TABLE_ENTRY的BaseDllName或FullDllName成员信息  
		printf("%S\n", pLdrDataEntry->BaseDllName.Buffer);

		pListEntryStart = pListEntryStart->Flink;

	} while (pListEntryStart != pListEntryEnd);

	printf("\nInInitializationOrderModuleList\n");
	pListEntryStart = pListEntryEnd = pPebLdrData->InInitializationOrderModuleList.Flink;
	//查找所有已载入到内存中的模块  
	do
	{
		//4、通过_LIST_ENTRY的Flink成员获取_LDR_DATA_TABLE_ENTRY结构  
		pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(pListEntryStart, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);

		//5、输出_LDR_DATA_TABLE_ENTRY的BaseDllName或FullDllName成员信息  
		printf("%S\n", pLdrDataEntry->BaseDllName.Buffer);

		pListEntryStart = pListEntryStart->Flink;

	} while (pListEntryStart != pListEntryEnd);

	return 0;
}
*/


int main(int argc, char* argv[])
{
	PVOID Peb = 0;

	//1、获取PEB
	__asm
	{		
		mov eax, dword ptr fs : [30h];
		mov Peb, eax
	}
	
	printf("Peb 0x%p\n", Peb);

	void *pebAddr = *((void **)((BYTE*)NtCurrentTeb() + 0x30));  // TEB->ProcessEnvironmentBlock也就是PEB
	void *ldrAddr = *((void **)((BYTE*)pebAddr + 0x0c)); // PEB->Ldr
	void *inLoadOrderLinks = *((void **)((BYTE*)ldrAddr + 0x0c)); // PEB->Ldr->InLoadOrderLinks->FLink 
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
		dllBase = *((void **)((BYTE*)p + 0x18));
		baseDllName = *((void **)((BYTE*)p + 0x2c + 0x4));
		fullDllName = *((void **)((BYTE*)p + 0x24 + 0x4));
		entryPoint = *((void **)((BYTE*)p + 0x1c));
		sizeOfImage = *((void **)((BYTE*)p + 0x20));

		printf("ModuleName:%S\n", (wchar_t*)baseDllName);
		printf("Base Address:0x%p\n", dllBase);
		printf("Full Module Name:%S\n", (wchar_t*)fullDllName);
		printf("entryPoint:0x%p\n", entryPoint);
		printf("imageOfSize:0x%p\n", sizeOfImage);

		p = *(void **)p;  // p->InLoadOrderLinks->FLink

	} while (p != fLink);


	return 0;
}

/*
InMemoryOrderModuleList
peb.exe
ntdll.dll
KERNEL32.DLL
KERNELBASE.dll
(null)

InLoadOrderModuleList
peb.exe
ntdll.dll
KERNEL32.DLL
KERNELBASE.dll
(null)

InInitializationOrderModuleList
ntdll.dll
KERNELBASE.dll
KERNEL32.DLL
(null)
*/

/*
Peb 0x00CC1000
PEB = 0x00CC1000
PEB ADDRESS = 0x00CC1000
LDR ADDRESS = 0x775A7BA0
ModuleName:peb.exe
Base Address:0x00A30000
Full Module Name:C:\Users\surfacebook\Documents\Visual Studio 2015\Projects\peb\Debug\peb.exe
entryPoint:0x00A786D1
imageOfSize:0x0010D000
ModuleName:ntdll.dll
Base Address:0x77490000
Full Module Name:C:\WINDOWS\SYSTEM32\ntdll.dll
entryPoint:0x00000000
imageOfSize:0x00190000
ModuleName:KERNEL32.DLL
Base Address:0x755B0000
Full Module Name:C:\WINDOWS\System32\KERNEL32.DLL
entryPoint:0x755C06A0
imageOfSize:0x000E0000
ModuleName:KERNELBASE.dll
Base Address:0x74530000
Full Module Name:C:\WINDOWS\System32\KERNELBASE.dll
entryPoint:0x7461F3F0
imageOfSize:0x001E4000
ModuleName:(null)
Base Address:0x00000000
Full Module Name:entryPoint:0x00000000
imageOfSize:0x00000000
*/


