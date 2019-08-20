// peb.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

//peb.c  
//compile:cl peb.c  
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

int main(int argc, char *argv[])
{
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = NULL;
	PLIST_ENTRY pListEntryStart = NULL, pListEntryEnd = NULL;
	PPEB_LDR_DATA pPebLdrData = NULL;
	PPEB pPeb = NULL;

	//故意加载一些DLL，以便测试!  
	//LoadLibrary("ResLibDemo");
	__asm
	{
		//1、通过fs:[30h]获取当前进程的_PEB结构  
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
		pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(pListEntryStart, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

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
		pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(pListEntryStart, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		//5、输出_LDR_DATA_TABLE_ENTRY的BaseDllName或FullDllName成员信息  
		printf("%S\n", pLdrDataEntry->FullDllName.Buffer);

		pListEntryStart = pListEntryStart->Flink;

	} while (pListEntryStart != pListEntryEnd);

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
C : \Users\surfacebook\Documents\Visual Studio 2015\Projects\peb\Debug\peb.exe
C : \WINDOWS\SYSTEM32\ntdll.dll
C : \WINDOWS\System32\KERNEL32.DLL
C : \WINDOWS\System32\KERNELBASE.dll

InInitializationOrderModuleList
ntdll.dll
KERNELBASE.dll
KERNEL32.DLL
(null)
*/

