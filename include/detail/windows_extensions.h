#pragma once

#include <Windows.h>
#include <winternl.h>

#include <cstddef>

namespace pfw
{

	struct PEB_FREE_BLOCK
	{
		pfw::PEB_FREE_BLOCK* Next;
		unsigned long Size;
	};

	struct PEB_LDR_DATA
	{
		unsigned long Length;
		bool Initialized;
		void* SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
	};

	struct PEB
	{
		std::byte InheritedAddressSpace;
		std::byte ReadImageFileExecOptions;
		std::byte BeingDebugged;
		std::byte SpareBool;
		void* Mutant;
		void* ImageBaseAddress;
		pfw::PEB_LDR_DATA* Ldr;
		RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
		void* SubSystemData;
		void* ProcessHeap;
		RTL_CRITICAL_SECTION* FastPebLock;
		void* FastPebLockRoutine;
		void* FastPebUnlockRoutine;
		DWORD EnvironmentUpdateCount;
		void* KernelCallbackTable;
		DWORD SystemReserved[1];
		DWORD ExecuteOptions;
		pfw::PEB_FREE_BLOCK* FreeList;
		DWORD TlsExpansionCounter;
		void* TlsBitmap;
		DWORD TlsBitmapBits[2];
		void* ReadOnlySharedMemoryBase;
		void* ReadOnlySharedMemoryHeap;
		void** ReadOnlyStaticServerData;
		void* AnsiCodePageData;
		void* OemCodePageData;
		void* UnicodeCaseTableData;
		DWORD NumberOfProcessors;
		DWORD NtGlobalFlag;
		LARGE_INTEGER CriticalSectionTimeout;
		DWORD HeapSegmentReserve;
		DWORD HeapSegmentCommit;
		DWORD HeapDeCommitTotalFreeThreshold;
		DWORD HeapDeCommitFreeBlockThreshold;
		DWORD NumberOfHeaps;
		DWORD MaximumNumberOfHeaps;
		void** ProcessHeaps;
		void* GdiSharedHandleTable;
		void* ProcessStarterHelper;
		DWORD GdiDCAttributeList;
		void* LoaderLock;
		DWORD OSMajorVersion;
		DWORD OSMinorVersion;
		WORD OSBuildNumber;
		WORD OSCSDVersion;
		DWORD OSPlatformId;
		DWORD ImageSubsystem;
		DWORD ImageSubsystemMajorVersion;
		DWORD ImageSubsystemMinorVersion;
		DWORD ImageProcessAffinityMask;
		DWORD GdiHandleBuffer[34];
		void (*PostProcessInitRoutine)();
		void* TlsExpansionBitmap;
		DWORD TlsExpansionBitmapBits[32];
		DWORD SessionId;
		ULARGE_INTEGER AppCompatFlags;
		ULARGE_INTEGER AppCompatFlagsUser;
		void* pShimData;
		void* AppCompatInfo;
		UNICODE_STRING CSDVersion;
		void* ActivationContextData;
		void* ProcessAssemblyStorageMap;
		void* SystemDefaultActivationContextData;
		void* SystemAssemblyStorageMap;
		DWORD MinimumStackCommit;
	};

	struct LoaderDataTableEntry
	{
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		LIST_ENTRY InInitializationOrderLinks;
		void* DllBase;
		void* EntryPoint;
		unsigned long SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		unsigned long Flags;
		WORD LoadCount;
		WORD TlsIndex;
		union
		{
			LIST_ENTRY HashLinks;
			struct Selection
			{
				void* SectionPointer;
				unsigned long CheckSum;
			};
		};
		union
		{
			unsigned long TimeDateStamp;
			void* LoadedImports;
		};
		_ACTIVATION_CONTEXT* EntryPointActivationContext;
		void* PatchInformation;
		LIST_ENTRY ForwarderLinks;
		LIST_ENTRY ServiceTagLinks;
		LIST_ENTRY StaticLinks;
	};
}