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

	//�������һЩDLL���Ա����!  
	//LoadLibrary("ResLibDemo");
	__asm
	{
		//1��ͨ��fs:[30h]��ȡ��ǰ���̵�_PEB�ṹ  
		mov eax, dword ptr fs : [30h];
		mov pPeb, eax
	}

	//2��ͨ��_PEB��Ldr��Ա��ȡ_PEB_LDR_DATA�ṹ  
	pPebLdrData = pPeb->Ldr;

	printf("\nInMemoryOrderModuleList\n");
	//3��ͨ��_PEB_LDR_DATA��InMemoryOrderModuleList��Ա��ȡ_LIST_ENTRY�ṹ  
	pListEntryStart = pListEntryEnd = pPebLdrData->InMemoryOrderModuleList.Flink;
	//�������������뵽�ڴ��е�ģ��  
	do
	{
		//4��ͨ��_LIST_ENTRY��Flink��Ա��ȡ_LDR_DATA_TABLE_ENTRY�ṹ  
		pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(pListEntryStart, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		//5�����_LDR_DATA_TABLE_ENTRY��BaseDllName��FullDllName��Ա��Ϣ  
		printf("%S\n", pLdrDataEntry->BaseDllName.Buffer);

		pListEntryStart = pListEntryStart->Flink;

	} while (pListEntryStart != pListEntryEnd);

	printf("\nInLoadOrderModuleList\n");
	pListEntryStart = pListEntryEnd = pPebLdrData->InLoadOrderModuleList.Flink;
	//�������������뵽�ڴ��е�ģ��  
	do
	{
		//4��ͨ��_LIST_ENTRY��Flink��Ա��ȡ_LDR_DATA_TABLE_ENTRY�ṹ  
		pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(pListEntryStart, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		//5�����_LDR_DATA_TABLE_ENTRY��BaseDllName��FullDllName��Ա��Ϣ  
		printf("%S\n", pLdrDataEntry->BaseDllName.Buffer);

		pListEntryStart = pListEntryStart->Flink;

	} while (pListEntryStart != pListEntryEnd);

	printf("\nInInitializationOrderModuleList\n");
	pListEntryStart = pListEntryEnd = pPebLdrData->InInitializationOrderModuleList.Flink;
	//�������������뵽�ڴ��е�ģ��  
	do
	{
		//4��ͨ��_LIST_ENTRY��Flink��Ա��ȡ_LDR_DATA_TABLE_ENTRY�ṹ  
		pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(pListEntryStart, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		//5�����_LDR_DATA_TABLE_ENTRY��BaseDllName��FullDllName��Ա��Ϣ  
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

