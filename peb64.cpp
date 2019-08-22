// peb64.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>

#define CONTAINING_RECORD(address, type, field) ((type *)((PCHAR)(address)-(ULONG_PTR)(&((type *)0)->field)))

typedef struct _UNICODE_STRING {
	USHORT  Length;
	USHORT  MaximumLength;
	UINT8  _PADDING0_[0x4];
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
	UINT8 _PADDING0_[0x4];
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
	UINT8 Padding0[4];
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
}PEB, *PPEB;

extern "C" PVOID64 _cdecl GetPebX64();

/*
int main(int argc, char *argv[])
{
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = NULL;
	PLIST_ENTRY pListEntryStart = NULL, pListEntryEnd = NULL;
	PPEB_LDR_DATA pPebLdrData = NULL;

	//1、获取PEB
	PPEB pPeb = (PPEB)GetPebX64();

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
	PVOID64 Peb = 0;
	Peb = GetPebX64();
	printf("Peb 0x%p\n", Peb);

	void *pebAddr = *((void **)((BYTE*)NtCurrentTeb() + 0x60));  // TEB->ProcessEnvironmentBlock也就是PEB
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

		printf("ModuleName:%S\n", (wchar_t*)baseDllName);
		printf("Base Address:0x%p\n", dllBase);
		printf("Full Module Name:%S\n", (wchar_t*)fullDllName);
		printf("entryPoint:0x%p\n", entryPoint);
		printf("imageOfSize:0x%p\n", sizeOfImage);

		p = *(void **)p;  // p->InLoadOrderLinks->FLink

	} while (p!= fLink);

	
	return 0;
}



/*
InMemoryOrderModuleList
peb64.exe
ntdll.dll
KERNEL32.DLL
KERNELBASE.dll
ucrtbased.dll
VCRUNTIME140D.dll
(null)

InLoadOrderModuleList
peb64.exe
ntdll.dll
KERNEL32.DLL
KERNELBASE.dll
ucrtbased.dll
VCRUNTIME140D.dll
(null)

InInitializationOrderModuleList
ntdll.dll
KERNELBASE.dll
KERNEL32.DLL
ucrtbased.dll
VCRUNTIME140D.dll
(null)
*/

/*
Peb 0x000000162A31D000
PEB = 0x000000162A31D000
PEB ADDRESS = 0x000000162A31D000
LDR ADDRESS = 0x00007FFE9CCDC360
ModuleName:peb64.exe
Base Address:0x00007FF7A9FB0000
Full Module Name:C:\Users\surfacebook\Documents\Visual Studio 2015\Projects\peb64\x64\Debug\peb64.exe
entryPoint:0x00007FF7A9FC1109
imageOfSize:0x0000000000025000
ModuleName:ntdll.dll
Base Address:0x00007FFE9CB80000
Full Module Name:C:\WINDOWS\SYSTEM32\ntdll.dll
entryPoint:0x0000000000000000
imageOfSize:0x00000000001E1000
ModuleName:KERNEL32.DLL
Base Address:0x00007FFE9A6C0000
Full Module Name:C:\WINDOWS\System32\KERNEL32.DLL
entryPoint:0x00007FFE9A6D3E50
imageOfSize:0x00000000000B2000
ModuleName:KERNELBASE.dll
Base Address:0x00007FFE99D90000
Full Module Name:C:\WINDOWS\System32\KERNELBASE.dll
entryPoint:0x00007FFE99D97FA0
imageOfSize:0x0000000000273000
ModuleName:VCRUNTIME140D.dll
Base Address:0x00007FFE8A890000
Full Module Name:C:\WINDOWS\SYSTEM32\VCRUNTIME140D.dll
entryPoint:0x00007FFE8A8A6770
imageOfSize:0x0000000000022000
ModuleName:ucrtbased.dll
Base Address:0x00007FFE5BCD0000
Full Module Name:C:\WINDOWS\SYSTEM32\ucrtbased.dll
entryPoint:0x00007FFE5BCFA130
imageOfSize:0x00000000001BD000
ModuleName:(null)
Base Address:0x0000000000000000
Full Module Name:(null)
entryPoint:0x0000000000000000
imageOfSize:0x0000000000000000
*/
