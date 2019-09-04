#pragma once

#include <windows.h>
#include <SubAuth.h>

// typedef struct _LSA_UNICODE_STRING {
//  USHORT Length;
//  USHORT MaximumLength;
//  PWSTR Buffer;
//} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

namespace gwinmem {

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  BYTE Reserved1[ 16 ];
  PVOID Reserved2[ 10 ];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
  ULONG Length;
  BOOL Initialized;
  LPVOID SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
  ULONG Flags;
  WORD LoadCount;
  WORD TlsIndex;
  union {
    LIST_ENTRY HashLinks;
    struct {
      PVOID SectionPointer;
      ULONG CheckSum;
    };
  };
  union {
    ULONG TimeDateStamp;
    PVOID LoadedImports;
  };
  _ACTIVATION_CONTEXT* EntryPointActivationContext;
  PVOID PatchInformation;
  LIST_ENTRY ForwarderLinks;
  LIST_ENTRY ServiceTagLinks;
  LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

#define GDI_HANDLE_BUFFER_SIZE32 34
#define GDI_HANDLE_BUFFER_SIZE64 60

#ifndef _WIN64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#endif

typedef ULONG GDI_HANDLE_BUFFER[ GDI_HANDLE_BUFFER_SIZE ];

struct PEB {
  BOOLEAN InheritedAddressSpace;
  BOOLEAN ReadImageFileExecOptions;
  BOOLEAN BeingDebugged;
  union {
    BOOLEAN BitField;
    struct {
      BOOLEAN ImageUsesLargePages : 1;
      BOOLEAN IsProtectedProcess : 1;
      BOOLEAN IsLegacyProcess : 1;
      BOOLEAN IsImageDynamicallyRelocated : 1;
      BOOLEAN SkipPatchingUser32Forwarders : 1;
      BOOLEAN IsPackagedProcess : 1;
      BOOLEAN IsAppContainer : 1;
      BOOLEAN SpareBits : 1;
    };
  };
  HANDLE Mutant;
  PVOID ImageBaseAddress;
  PPEB_LDR_DATA Ldr;
  PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
  PVOID SubSystemData;
  PVOID ProcessHeap;
  PRTL_CRITICAL_SECTION FastPebLock;
  PVOID AtlThunkSListPtr;
  PVOID IFEOKey;
  union {
    ULONG CrossProcessFlags;
    struct {
      ULONG ProcessInJob : 1;
      ULONG ProcessInitializing : 1;
      ULONG ProcessUsingVEH : 1;
      ULONG ProcessUsingVCH : 1;
      ULONG ProcessUsingFTH : 1;
      ULONG ReservedBits0 : 27;
    };
    ULONG EnvironmentUpdateCount;
  };
  union {
    PVOID KernelCallbackTable;
    PVOID UserSharedInfoPtr;
  };
  ULONG SystemReserved[ 1 ];
  ULONG AtlThunkSListPtr32;
  PVOID ApiSetMap;
  ULONG TlsExpansionCounter;
  PVOID TlsBitmap;
  ULONG TlsBitmapBits[ 2 ];
  PVOID ReadOnlySharedMemoryBase;
  PVOID HotpatchInformation;
  PVOID* ReadOnlyStaticServerData;
  PVOID AnsiCodePageData;
  PVOID OemCodePageData;
  PVOID UnicodeCaseTableData;
  ULONG NumberOfProcessors;
  ULONG NtGlobalFlag;
  LARGE_INTEGER CriticalSectionTimeout;
  SIZE_T HeapSegmentReserve;
  SIZE_T HeapSegmentCommit;
  SIZE_T HeapDeCommitTotalFreeThreshold;
  SIZE_T HeapDeCommitFreeBlockThreshold;
  ULONG NumberOfHeaps;
  ULONG MaximumNumberOfHeaps;
  PVOID* ProcessHeaps;
  PVOID GdiSharedHandleTable;
  PVOID ProcessStarterHelper;
  ULONG GdiDCAttributeList;
  PRTL_CRITICAL_SECTION LoaderLock;
  ULONG OSMajorVersion;
  ULONG OSMinorVersion;
  USHORT OSBuildNumber;
  USHORT OSCSDVersion;
  ULONG OSPlatformId;
  ULONG ImageSubsystem;
  ULONG ImageSubsystemMajorVersion;
  ULONG ImageSubsystemMinorVersion;
  ULONG_PTR ImageProcessAffinityMask;
  GDI_HANDLE_BUFFER GdiHandleBuffer;
  PVOID PostProcessInitRoutine;
  PVOID TlsExpansionBitmap;
  ULONG TlsExpansionBitmapBits[ 32 ];
  ULONG SessionId;
  ULARGE_INTEGER AppCompatFlags;
  ULARGE_INTEGER AppCompatFlagsUser;
  PVOID pShimData;
  PVOID AppCompatInfo;
  UNICODE_STRING CSDVersion;
  PVOID ActivationContextData;
  PVOID ProcessAssemblyStorageMap;
  PVOID SystemDefaultActivationContextData;
  PVOID SystemAssemblyStorageMap;
  SIZE_T MinimumStackCommit;
  PVOID* FlsCallback;
  LIST_ENTRY FlsListHead;
  PVOID FlsBitmap;
  ULONG FlsBitmapBits[ FLS_MAXIMUM_AVAILABLE / ( sizeof( ULONG ) * 8 ) ];
  ULONG FlsHighIndex;
  PVOID WerRegistrationData;
  PVOID WerShipAssertPtr;
  PVOID pContextData;
  PVOID pImageHeaderHash;
  union {
    ULONG TracingFlags;
    struct {
      ULONG HeapTracingEnabled : 1;
      ULONG CritSecTracingEnabled : 1;
      ULONG LibLoaderTracingEnabled : 1;
      ULONG SpareTracingBits : 29;
    };
  };
  ULONGLONG CsrServerReadOnlySharedMemoryBase;
};

enum PROCESSINFOCLASS {
  ProcessBasicInformation =
      0,  // 0, q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
  ProcessQuotaLimits,  // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
  ProcessIoCounters,  // q: IO_COUNTERS
  ProcessVmCounters,  // q: VM_COUNTERS, VM_COUNTERS_EX
  ProcessTimes,  // q: KERNEL_USER_TIMES
  ProcessBasePriority,  // s: KPRIORITY
  ProcessRaisePriority,  // s: ULONG
  ProcessDebugPort,  // q: HANDLE
  ProcessExceptionPort,  // s: HANDLE
  ProcessAccessToken,  // s: PROCESS_ACCESS_TOKEN
  ProcessLdtInformation,  // 10
  ProcessLdtSize,
  ProcessDefaultHardErrorMode,  // qs: ULONG
  ProcessIoPortHandlers,  // (kernel-mode only)
  ProcessPooledUsageAndLimits,  // q: POOLED_USAGE_AND_LIMITS
  ProcessWorkingSetWatch,  // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
  ProcessUserModeIOPL,
  ProcessEnableAlignmentFaultFixup,  // s: BOOLEAN
  ProcessPriorityClass,  // qs: PROCESS_PRIORITY_CLASS
  ProcessWx86Information,
  ProcessHandleCount,  // 20, q: ULONG, PROCESS_HANDLE_INFORMATION
  ProcessAffinityMask,  // s: KAFFINITY
  ProcessPriorityBoost,  // qs: ULONG
  ProcessDeviceMap,  // qs: PROCESS_DEVICEMAP_INFORMATION,
                     // PROCESS_DEVICEMAP_INFORMATION_EX
  ProcessSessionInformation,  // q: PROCESS_SESSION_INFORMATION
  ProcessForegroundInformation,  // s: PROCESS_FOREGROUND_BACKGROUND
  ProcessWow64Information,  // q: ULONG_PTR
  ProcessImageFileName,  // q: UNICODE_STRING
  ProcessLUIDDeviceMapsEnabled,  // q: ULONG
  ProcessBreakOnTermination,  // qs: ULONG
  ProcessDebugObjectHandle,  // 30, q: HANDLE
  ProcessDebugFlags,  // qs: ULONG
  ProcessHandleTracing,  // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables,
                         // otherwise enables
  ProcessIoPriority,  // qs: ULONG
  ProcessExecuteFlags,  // qs: ULONG
  ProcessResourceManagement,
  ProcessCookie,  // q: ULONG
  ProcessImageInformation,  // q: SECTION_IMAGE_INFORMATION
  ProcessCycleTime,  // q: PROCESS_CYCLE_TIME_INFORMATION
  ProcessPagePriority,  // q: ULONG
  ProcessInstrumentationCallback,  // 40
  ProcessThreadStackAllocation,  // s: PROCESS_STACK_ALLOCATION_INFORMATION,
                                 // PROCESS_STACK_ALLOCATION_INFORMATION_EX
  ProcessWorkingSetWatchEx,  // q: PROCESS_WS_WATCH_INFORMATION_EX[]
  ProcessImageFileNameWin32,  // q: UNICODE_STRING
  ProcessImageFileMapping,  // q: HANDLE (input)
  ProcessAffinityUpdateMode,  // qs: PROCESS_AFFINITY_UPDATE_MODE
  ProcessMemoryAllocationMode,  // qs: PROCESS_MEMORY_ALLOCATION_MODE
  ProcessGroupInformation,  // q: USHORT[]
  ProcessTokenVirtualizationEnabled,  // s: ULONG
  ProcessConsoleHostProcess,  // q: ULONG_PTR
  ProcessWindowInformation,  // 50, q: PROCESS_WINDOW_INFORMATION
  ProcessHandleInformation,  // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since
                             // WIN8
  ProcessMitigationPolicy,  // s: PROCESS_MITIGATION_POLICY_INFORMATION
  ProcessDynamicFunctionTableInformation,
  ProcessHandleCheckingMode,
  ProcessKeepAliveCount,  // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
  ProcessRevokeFileHandles,  // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
  MaxProcessInfoClass
};

}  // namespace gwinmem