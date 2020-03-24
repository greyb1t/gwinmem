#include "pch.h"
#include "process_memory_internal.h"
#include "utils/string_utils.h"
#include "utils/pe_utils.h"

#include "detours.h"

// Define the global variable
namespace gwinmem {
ProcessMemoryInternal process_internal;
}

gwinmem::ProcessMemoryInternal& gwinmem::CurrentProcess() {
  return process_internal;
}

gwinmem::ProcessMemoryInternal::ProcessMemoryInternal()
    : ProcessMemory( GetCurrentProcessId() ),
      original_nt_query_info_process_( nullptr ) {
  Open();
}

bool gwinmem::ProcessMemoryInternal::Open() {
  process_handle_ = GetCurrentProcess();
  return true;
}

gwinmem::PEB* gwinmem::ProcessMemoryInternal::GetCurrentPeb() const {
#if defined( _WIN64 )
  uintptr_t peb_addr = __readgsqword( 0x60 );
#else
  uintptr_t peb_addr = __readfsdword( 0x30 );
#endif
  return reinterpret_cast<PEB*>( peb_addr );
}

void ThrowBadMemoryException( const uintptr_t address, const uint64_t size ) {
  throw gwinmem::BadMemoryException(
      "ReadBytes failed, it is most likely you who read invalid memory. "
      "Address: " +
      std::to_string( address ) + ", Size: " + std::to_string( size ) );
}

bool gwinmem::ProcessMemoryInternal::ReadBytes( const uintptr_t address,
                                                const uint64_t size,
                                                uint8_t* buf ) {
  __try {
    memcpy( buf, reinterpret_cast<const void*>( address ),
            static_cast<size_t>( size ) );
  } __except ( GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ) {
    // Assert here because we should not allow any reading to memory to fail.
    // That implies incorrect programming practices or bugs.
    ThrowBadMemoryException( address, size );
    return false;
  }

  return true;
}

bool gwinmem::ProcessMemoryInternal::WriteBytes( const uintptr_t address,
                                                 const uint64_t size,
                                                 const uint8_t* buf ) {
  __try {
    memcpy( reinterpret_cast<void*>( address ), buf,
            static_cast<size_t>( size ) );
  } __except ( GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ) {
    // Assert here because we should not allow any writing to memory to fail.
    // That implies incorrect programming practices or bugs.
    assert( false &&
            "WriteBytes failed, it is most likely you who wrote on a invalid "
            "memory location." );
    return false;
  }

  return true;
}

uintptr_t gwinmem::ProcessMemoryInternal::RemoteLoadLibrary(
    const std::wstring& dll_directory ) {
  return reinterpret_cast<uintptr_t>( LoadLibrary( dll_directory.c_str() ) );
}

std::vector<gwinmem::MemoryModule> gwinmem::ProcessMemoryInternal::GetModules()
    const {
  const auto peb = GetCurrentPeb();

  std::vector<gwinmem::MemoryModule> modules;

  // Loop through the module linked list until we've reached the end
  for ( auto entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(
            peb->Ldr->InLoadOrderModuleList.Flink );
        entry->DllBase != 0; entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(
                                 entry->InLoadOrderLinks.Flink ) ) {
    const auto base_dll_name = std::wstring( entry->BaseDllName.Buffer,
                                             entry->BaseDllName.Length / 2 );
    const auto base_dll_name_lower =
        stringutils::WideStringToLower( base_dll_name );

    const auto module = MemoryModule(
        base_dll_name_lower, reinterpret_cast<uintptr_t>( entry->DllBase ),
        entry->SizeOfImage );

    modules.push_back( module );
  }

  return modules;
}

bool gwinmem::ProcessMemoryInternal::ManualMapAddLoaderDll(
    const uintptr_t dll_base,
    const std::wstring& module_directory ) {
  if ( !dll_base )
    return false;

  HMODULE ntdll = GetModuleHandle( TEXT( "ntdll.dll" ) );

  using RtlInitUnicodeString_t = VOID( NTAPI* )(
      PUNICODE_STRING DestinationString, __drv_aliasesMem PCWSTR SourceString );

  const auto RtlInitUnicodeString = reinterpret_cast<RtlInitUnicodeString_t>(
      GetProcAddress( ntdll, "RtlInitUnicodeString" ) );

  const auto peb = GetCurrentPeb();

  auto module_list_head = &peb->Ldr->InLoadOrderModuleList;
  const auto module_list_head_data = CONTAINING_RECORD(
      module_list_head->Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );

  // TODO: Consider using new instead of HeapAlloc
  auto AllocateHeap = []( uint32_t allocation_size ) -> void* {
    return HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, allocation_size );
  };

  auto new_entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(
      AllocateHeap( sizeof( LDR_DATA_TABLE_ENTRY ) ) );

  assert( new_entry );

  *new_entry = *module_list_head_data;

  new_entry->DllBase = reinterpret_cast<LPVOID>( dll_base );

  const auto dos_headers =
      reinterpret_cast<const IMAGE_DOS_HEADER*>( dll_base );

  // Check if the dll_data is a dll, otherwise return false
  if ( dos_headers->e_magic != IMAGE_DOS_SIGNATURE )
    return false;

  const auto nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS*>(
      dll_base + dos_headers->e_lfanew );

  if ( nt_headers->Signature != IMAGE_NT_SIGNATURE )
    return false;

  new_entry->SizeOfImage = nt_headers->OptionalHeader.SizeOfImage;
  new_entry->EntryPoint = 0;

  const uint32_t kLdrpImageDll = 0x00000004;

  new_entry->Flags |= kLdrpImageDll;

  const auto full_dll_name_buf =
      reinterpret_cast<wchar_t*>( AllocateHeap( MAX_PATH ) );
  const auto base_dll_name_buf =
      reinterpret_cast<wchar_t*>( AllocateHeap( MAX_PATH ) );

  const auto base_dll_name_index = module_directory.find_last_of( '\\' );
  const auto base_dll_name_str =
      module_directory.substr( base_dll_name_index + 1 );

  std::wstring dll_dir_copy_filename = base_dll_name_str;

  wcscpy_s( full_dll_name_buf, module_directory.size() * 2,
            module_directory.c_str() );
  // wcscpy( full_dll_name_buf, module_directory.c_str() );

  wcscpy_s( base_dll_name_buf, dll_dir_copy_filename.size() * 2,
            dll_dir_copy_filename.c_str() );
  // wcscpy( base_dll_name_buf, dll_dir_copy_filename.c_str() );

  UNICODE_STRING full_dll_name;
  UNICODE_STRING base_dll_name;

  RtlInitUnicodeString( &full_dll_name, full_dll_name_buf );
  RtlInitUnicodeString( &base_dll_name, base_dll_name_buf );

  new_entry->FullDllName = full_dll_name;
  new_entry->BaseDllName = base_dll_name;

  auto InsertTailList = []( LIST_ENTRY* list_head, LIST_ENTRY* entry ) {
    LIST_ENTRY* temp = list_head->Blink;

    entry->Flink = list_head;
    entry->Blink = temp;

    temp->Flink = entry;
    list_head->Blink = entry;
  };

  InsertTailList( &peb->Ldr->InLoadOrderModuleList,
                  &new_entry->InLoadOrderLinks );
  InsertTailList( &peb->Ldr->InMemoryOrderModuleList,
                  &new_entry->InMemoryOrderLinks );

  // LIST_ENTRY *head = &peb->Ldr->InLoadOrderModuleList;

  //// Print all the modules
  // for (LIST_ENTRY *item = head->Flink; item != head; item = item->Flink) {
  // LDR_DATA_TABLE_ENTRY *entry = CONTAINING_RECORD(item, LDR_DATA_TABLE_ENTRY,
  // InLoadOrderLinks);

  // printf("Dll name: ");
  // wprintf(L"%ls", entry->FullDllName.Buffer);
  // printf("\nDll base: 0x%x\n\n", (int)entry->DllBase);
  //}

  return true;
}

// bool gwinmem::ProcessMemoryInternal::ManualMapAddLoaderModule(
//    const PVOID dll_base,
//    const std::wstring& module_directory ) {
//  if ( !dll_base ) {
//    // gWin::logger::DisplayError( TEXT( "The dll base is 0." ) );
//    return false;
//  }
//
//  HMODULE ntdll = GetModuleHandle( TEXT( "ntdll.dll" ) );
//
//  typedef void	(NTAPI *tRtlInitUnicodeString)(PUNICODE_STRING
//  DestinationString, PCWSTR SourceString);
//
//  tRtlInitUnicodeString RtlInitUnicodeString =
//      reinterpret_cast<tRtlInitUnicodeString>(
//          GetProcAddress( ntdll, "RtlInitUnicodeString" ) );
//
//  auto GetCurrentPeb = []() -> PEB* {
//#if defined( _WIN64 )
//    uint64_t peb_addr = __readgsqword( 0x60 );
//    return reinterpret_cast<PEB*>( peb_addr );
//#else
//    uint32_t peb_addr = __readfsdword( 0x30 );
//    return reinterpret_cast<PEB*>( peb_addr );
//#endif
//  };
//
//  const auto peb = GetCurrentPeb();
//
//  auto module_list_head = &peb->Ldr->InLoadOrderModuleList;
//  const auto module_list_head_data = CONTAINING_RECORD(
//      module_list_head->Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );
//
//  auto AllocateHeap = []( uint32_t allocation_size ) -> void* {
//    return HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, allocation_size );
//  };
//
//  auto new_entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(
//      AllocateHeap( sizeof( LDR_DATA_TABLE_ENTRY ) ) );
//
//  if ( !new_entry ) {
//    //gWin::logger::DisplayError( TEXT( "error so bad heap error" ) );
//  }
//
//  *new_entry = *module_list_head_data;
//
//  new_entry->DllBase = dll_base;
//
//  const auto dos_headers =
//      reinterpret_cast<const IMAGE_DOS_HEADER*>( dll_base );
//
//  // Check if the dll_data is a dll, otherwise return false
//  if ( dos_headers->e_magic != IMAGE_DOS_SIGNATURE )
//    return false;
//
//  const auto nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS*>(
//      reinterpret_cast<uint32_t>( dll_base ) + dos_headers->e_lfanew );
//
//  if ( nt_headers->Signature != IMAGE_NT_SIGNATURE )
//    return false;
//
//  new_entry->SizeOfImage = nt_headers->OptionalHeader.SizeOfImage;
//  new_entry->EntryPoint = 0;
//
//  const uint32_t kLdrpImageDll = 0x00000004;
//
//  new_entry->Flags |= kLdrpImageDll;
//
//  const auto full_dll_name_buf =
//      reinterpret_cast<wchar_t*>( AllocateHeap( MAX_PATH ) );
//  const auto base_dll_name_buf =
//      reinterpret_cast<wchar_t*>( AllocateHeap( MAX_PATH ) );
//
//  const auto base_dll_name_index = module_directory.find_last_of( '\\' );
//  const auto base_dll_name_str =
//      module_directory.substr( base_dll_name_index + 1 );
//
//  std::wstring dll_dir_copy_filename = base_dll_name_str;
//
//  wcscpy( full_dll_name_buf, module_directory.c_str() );
//  wcscpy( base_dll_name_buf, dll_dir_copy_filename.c_str() );
//
//  UNICODE_STRING full_dll_name;
//  UNICODE_STRING base_dll_name;
//
//  RtlInitUnicodeString( &full_dll_name, full_dll_name_buf );
//  RtlInitUnicodeString( &base_dll_name, base_dll_name_buf );
//
//  new_entry->FullDllName = full_dll_name;
//  new_entry->BaseDllName = base_dll_name;
//
//  auto InsertTailList = []( LIST_ENTRY* list_head, LIST_ENTRY* entry ) {
//    LIST_ENTRY* temp = list_head->Blink;
//
//    entry->Flink = list_head;
//    entry->Blink = temp;
//
//    temp->Flink = entry;
//    list_head->Blink = entry;
//  };
//
//  InsertTailList( &peb->Ldr->InLoadOrderModuleList,
//                  &new_entry->InLoadOrderLinks );
//  InsertTailList( &peb->Ldr->InMemoryOrderModuleList,
//                  &new_entry->InMemoryOrderLinks );
//
//  // LIST_ENTRY *head = &peb->Ldr->InLoadOrderModuleList;
//
//  //// Print all the modules
//  // for (LIST_ENTRY *item = head->Flink; item != head; item = item->Flink) {
//  // LDR_DATA_TABLE_ENTRY *entry = CONTAINING_RECORD(item,
//  LDR_DATA_TABLE_ENTRY,
//  // InLoadOrderLinks);
//
//  // printf("Dll name: ");
//  // wprintf(L"%ls", entry->FullDllName.Buffer);
//  // printf("\nDll base: 0x%x\n\n", (int)entry->DllBase);
//  //}
//
//  return true;
//}

NTSTATUS NTAPI gwinmem::ProcessMemoryInternal::NtQueryInformationProcessHooked(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength ) {
  // x86: Hook NtQueryInformationProcess and modify the ProcessExecuteFlags
  // makes the ntdll.RtlIsValidHandler return true.

  const auto MEM_EXECUTE_OPTION_IMAGE_DISPATCH_ENABLE = 0x20;

  auto status = gwinmem::process_internal.original_nt_query_info_process_(
      ProcessHandle, ProcessInformationClass, ProcessInformation,
      ProcessInformationLength, ReturnLength );

  if ( !status &&
       ProcessInformationClass == PROCESSINFOCLASS::ProcessExecuteFlags ) {
    *( DWORD* )ProcessInformation |= MEM_EXECUTE_OPTION_IMAGE_DISPATCH_ENABLE;
  }

  return status;
}

bool gwinmem::ProcessMemoryInternal::ManualMapFixExceptionHandling() {
  // 	works	with	exceptions:	for	x64	images	adds	exception	handlers (
  // RtlAddFunctionTable )
  DetourTransactionBegin();
  DetourUpdateThread( GetCurrentThread() );

  auto ntdll = GetModuleHandle( TEXT( "ntdll.dll" ) );

  if ( !ntdll )
    return false;

  auto nt_query_information_process =
      reinterpret_cast<NtQueryInformationProcess_t>(
          GetProcAddress( ntdll, "NtQueryInformationProcess" ) );

  if ( !nt_query_information_process )
    return false;

  DetourAttach( reinterpret_cast<PVOID*>( &nt_query_information_process ),
                ProcessMemoryInternal::NtQueryInformationProcessHooked );

  if ( DetourTransactionCommit() != NO_ERROR )
    return false;

  original_nt_query_info_process_ = nt_query_information_process;

  /*
  {
    const auto ntdll = GetModule( TEXT( "ntdll.dll" ) );

    if ( !ntdll.base )
      return false;

    const auto original_function =
        HookEat( ntdll, "NtQueryInformationProcess",
                 ProcessMemoryInternal::NtQueryInformationProcessHooked );

    if ( !original_function )
      return false;

    original_nt_query_info_process_ = original_function;
  }
  */

  return true;
}

// uintptr_t GetFunctionAddressFromPdb();

bool IsWindows8Point1OrGreaterBetter() {
  const auto ntdll = LoadLibrary( TEXT( "ntdll.dll" ) );

  using RtlGetVersion_t =
      NTSTATUS( NTAPI* )( PRTL_OSVERSIONINFOW lpVersionInformation );

  const auto RtlGetVersion = reinterpret_cast<RtlGetVersion_t>(
      GetProcAddress( ntdll, "RtlGetVersion" ) );

  OSVERSIONINFOW os_version_info;
  os_version_info.dwOSVersionInfoSize = sizeof( os_version_info );

  RtlGetVersion( &os_version_info );

  if ( os_version_info.dwBuildNumber >= 9200 ) {
    if ( os_version_info.dwMajorVersion == 6 ) {
      if ( os_version_info.dwMinorVersion >= 3 ) {
        return true;
      }
    }

    return true;
  }

  return false;
}

uintptr_t GetFunctionRvaFromPdb( const HMODULE module,
                                 const std::string& function_name ) {
  const auto pdb_info =
      peutils::GetPdbInfoFromModule( reinterpret_cast<uintptr_t>( module ) );

  if ( !pdb_info )
    return 0;

  std::string pdb_path = std::string( pdb_info->pdb_filename ) + "/" +
                         gwinmem::stringutils::GuidToString( pdb_info->guid ) +
                         std::to_string( pdb_info->age ) + "/" +
                         std::string( pdb_info->pdb_filename );

  const auto symbol_server_url = "http://msdl.microsoft.com/download/symbols/";

  std::string temp_directory_path( MAX_PATH, '\0' );

  const auto chars_count_copied =
      GetTempPathA( MAX_PATH, &temp_directory_path[ 0 ] );

  assert( chars_count_copied );

  temp_directory_path.resize( chars_count_copied );
  temp_directory_path.append( "yeet_gb_fb_v2.pdb" );

  const auto download_pdb_result =
      URLDownloadToFileA( 0, ( symbol_server_url + pdb_path ).c_str(),
                          temp_directory_path.c_str(), 0, NULL );

  if ( download_pdb_result != S_OK ) {
    return 0;
  }

  // Get better debugging error messages
  // SymSetOptions( SymGetOptions() | SYMOPT_DEBUG );

  if ( !SymInitialize( GetCurrentProcess(), NULL, FALSE ) ) {
    return 0;
  }

  const auto pdb_file_handle =
      CreateFileA( temp_directory_path.c_str(), GENERIC_READ, 0, NULL,
                   OPEN_EXISTING, 0, NULL );

  if ( !pdb_file_handle ) {
    return 0;
  }

  const auto pdb_file_size = GetFileSize( pdb_file_handle, NULL );

  // Close the handle before calling SymLoadModuleEx because it needs access to the file
  //
  CloseHandle( pdb_file_handle );

  const uintptr_t kDummyBaseAddress = 0x10000000;

  const auto mod_base_addr =
      SymLoadModuleEx( GetCurrentProcess(), NULL, temp_directory_path.c_str(),
                       NULL, kDummyBaseAddress, pdb_file_size, NULL, 0 );

  if ( !mod_base_addr )
    return 0;

  // Workaround instead of defining SYMBOL_INFO as a variable, because their API design is ABSOLUTE SHIT
  //
  char sym_memory[ sizeof( SYMBOL_INFO ) + MAX_SYM_NAME ];
  SYMBOL_INFO* sym_info = reinterpret_cast<SYMBOL_INFO*>( sym_memory );
  {
    sym_info->NameLen = MAX_SYM_NAME;
    sym_info->SizeOfStruct = sizeof( SYMBOL_INFO );
  }

  if ( !SymFromName( GetCurrentProcess(), function_name.c_str(), sym_info ) )
    return 0;

  const auto unload_module_result =
      SymUnloadModule64( GetCurrentProcess(), mod_base_addr );

  assert( unload_module_result );

  if ( !SymCleanup( GetCurrentProcess() ) )
    return 0;

  return static_cast<uintptr_t>( sym_info->Address - kDummyBaseAddress );
}

bool gwinmem::ProcessMemoryInternal::ManualMapHandleStaticTlsData(
    LDR_DATA_TABLE_ENTRY* entry ) {
  const auto ntdll = GetModuleHandle( TEXT( "ntdll.dll" ) );

  assert( ntdll );

  const auto ldrp_handle_tls_data_rva =
      GetFunctionRvaFromPdb( ntdll, "LdrpHandleTlsData" );

  if ( !ldrp_handle_tls_data_rva ) {
    return false;
  }

  using LdrpHandleTlsData_stdcall_t =
      NTSTATUS( __stdcall* )( PLDR_DATA_TABLE_ENTRY ModuleEntry );

  using LdrpHandleTlsData_thiscall_t =
      NTSTATUS( __thiscall* )( PLDR_DATA_TABLE_ENTRY ModuleEntry );

  const auto ntdll_base_addr = reinterpret_cast<uintptr_t>( ntdll );

  const auto ldrp_handle_tls_data_thiscall =
      reinterpret_cast<LdrpHandleTlsData_thiscall_t>(
          ntdll_base_addr + ldrp_handle_tls_data_rva );

  const auto ldrp_handle_tls_data_stdcall =
      reinterpret_cast<LdrpHandleTlsData_stdcall_t>( ntdll_base_addr +
                                                     ldrp_handle_tls_data_rva );

  NTSTATUS data_fix_result = 0;

  // Ever since the windows 8.1 version, LdrpHandleTlsData has changed to a __thiscall
  //
  if ( IsWindows8Point1OrGreaterBetter() ) {
    data_fix_result = ldrp_handle_tls_data_thiscall( entry );
  } else {
    data_fix_result = ldrp_handle_tls_data_stdcall( entry );
  }

  return NT_SUCCESS( data_fix_result );
}

bool gwinmem::ProcessMemoryInternal::ManualMapResetExceptionHandling() {
  DetourTransactionBegin();

  DetourUpdateThread( GetCurrentThread() );

  DetourDetach( reinterpret_cast<PVOID*>( &original_nt_query_info_process_ ),
                ProcessMemoryInternal::NtQueryInformationProcessHooked );

  if ( DetourTransactionCommit() != NO_ERROR )
    return false;

  // NOTE: Cannot use EAT or IAT for hooking because of their limitations.
  // Example: The target application has already called GetProcAddress and saved
  // it's address, then we eject dll and now it points to nothing.
  // If you unhook it manually, they still have saved our EAT hooked function.
  /*
  {
    const auto ntdll = GetModule( TEXT( "ntdll.dll" ) );

    if ( !ntdll.base )
      return false;

    return UnHookEat( ntdll, "NtQueryInformationProcess",
                      original_nt_query_info_process_ );
  }
  */

  return true;
}

bool gwinmem::ProcessMemoryInternal::ManualMapFreeStaticTlsData(
    LDR_DATA_TABLE_ENTRY* entry ) {
  const auto ntdll = GetModuleHandle( TEXT( "ntdll.dll" ) );

  assert( ntdll );

  const auto ldrp_release_tls_entry_rva =
      GetFunctionRvaFromPdb( ntdll, "LdrpReleaseTlsEntry" );

  if ( !ldrp_release_tls_entry_rva ) {
    return false;
  }

  using LdrpReleaseTlsEntry_stdcall =
      NTSTATUS( __stdcall* )( PLDR_DATA_TABLE_ENTRY ModuleEntry, DWORD * unk );

  using LdrpReleaseTlsEntry_fastcall =
      NTSTATUS( __fastcall* )( PLDR_DATA_TABLE_ENTRY ModuleEntry, DWORD * unk );

  const auto ntdll_base_addr = reinterpret_cast<uintptr_t>( ntdll );

  const auto ldrp_release_tls_entry_fastcall =
      reinterpret_cast<LdrpReleaseTlsEntry_fastcall>(
          ntdll_base_addr + ldrp_release_tls_entry_rva );

  const auto ldrp_release_tls_entry_stdcall =
      reinterpret_cast<LdrpReleaseTlsEntry_stdcall>(
          ntdll_base_addr + ldrp_release_tls_entry_rva );

  NTSTATUS tls_free_result = 0;

  // Ever since the windows 8.1 version, LdrpReleaseTlsEntry has changed to a __fastcall
  //
  if ( IsWindows8Point1OrGreaterBetter() ) {
    tls_free_result = ldrp_release_tls_entry_fastcall( entry, 0 );
  } else {
    tls_free_result = ldrp_release_tls_entry_stdcall( entry, 0 );
  }

  return NT_SUCCESS( tls_free_result );
}

#pragma optimize( "", off )

// Disable the runtime_checks to prevent the compiler from adding random calls
// to check esp inside of the code.
#pragma runtime_checks( "", off )

struct ManualMappedModuleFreeData {
  HANDLE main_bot_thread_handle;
  uintptr_t mapped_module_base_address;
  LPVOID unloader_thread_address;

  decltype( VirtualFree )* __VirtualFree;
  decltype( WaitForSingleObject )* __WaitForSingleObject;
  decltype( CloseHandle )* __CloseHandle;

  using tRtlExitUserThread = void( NTAPI* )( NTSTATUS Status );

  tRtlExitUserThread __RtlExitUserThread;
};

DWORD WINAPI ManualMapFreeModuleThread( ManualMappedModuleFreeData* mm_data ) {
  // Save the variables before we de-allocate them
  auto local_unloader_thread_address = mm_data->unloader_thread_address;
  auto local_main_bot_thread_handle = mm_data->main_bot_thread_handle;
  auto local_mapped_module_base_addr = mm_data->mapped_module_base_address;

  auto local_rtl_exit_user_thread = mm_data->__RtlExitUserThread;
  auto local_virtual_free = mm_data->__VirtualFree;
  auto local_wait_for_single_object = mm_data->__WaitForSingleObject;
  auto local_close_handle = mm_data->__CloseHandle;

  // Wait for the main bot thread to finish
  local_wait_for_single_object( local_main_bot_thread_handle, INFINITE );

  local_close_handle( local_main_bot_thread_handle );

  // After we free this, the win32 api calls get destroyed, therefore we pass
  // them by argument
  if ( !local_virtual_free(
           reinterpret_cast<LPVOID>( local_mapped_module_base_addr ), 0,
           MEM_RELEASE ) ) {
    return -1;
  }

  // Free the allocated arguments
  local_virtual_free( mm_data, 0, MEM_RELEASE );

  return 0;
}

void WINAPI ManualMapFreeModuleThreadEnd() {}

#pragma runtime_checks( "", restore )
#pragma optimize( "", on )

void gwinmem::ProcessMemoryInternal::ManualMapStartFreeDllThread(
    const uintptr_t mapped_module_base ) {
  ManualMappedModuleFreeData mm_data;
  {
    mm_data.main_bot_thread_handle =
        OpenThread( THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId() );

    assert( mm_data.main_bot_thread_handle );

    mm_data.mapped_module_base_address = mapped_module_base;

    mm_data.__VirtualFree = VirtualFree;
    mm_data.__WaitForSingleObject = WaitForSingleObject;
    mm_data.__CloseHandle = CloseHandle;

    const HMODULE ntdll = GetModuleHandle( TEXT( "ntdll.dll" ) );

    using tRtlExitUserThread = void( NTAPI* )( NTSTATUS Status );

    mm_data.__RtlExitUserThread = reinterpret_cast<tRtlExitUserThread>(
        GetProcAddress( ntdll, "RtlExitUserThread" ) );

    assert( mm_data.__RtlExitUserThread );
  }

  LPVOID mm_free_data_arguments_addr = VirtualAlloc(
      0, sizeof( mm_data ), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

  assert( mm_free_data_arguments_addr );

  //////////////////////////////////////////////////////////////////////////

  const auto free_module_thread_addr =
      peutils::GetFunctionAddress( ManualMapFreeModuleThread );
  const auto free_module_thread_end_addr =
      peutils::GetFunctionAddress( ManualMapFreeModuleThreadEnd );

  //////////////////////////////////////////////////////////////////////////

  const uint32_t kFreeModuleThreadAllocationSize =
      abs( ( int32_t )free_module_thread_end_addr -
           ( int32_t )free_module_thread_addr );

  LPVOID mm_free_module_thread_addr =
      VirtualAlloc( 0, kFreeModuleThreadAllocationSize,
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );

  assert( mm_free_module_thread_addr );

  mm_data.unloader_thread_address = mm_free_module_thread_addr;

  memcpy( mm_free_module_thread_addr,
          reinterpret_cast<const void*>( free_module_thread_addr ),
          kFreeModuleThreadAllocationSize );

  FlushInstructionCache( GetCurrentProcess(), mm_free_module_thread_addr,
                         kFreeModuleThreadAllocationSize );

  memcpy( mm_free_data_arguments_addr, &mm_data, sizeof( mm_data ) );

  // Crash happens after it starts the mm_free_module_thread_addr thread
  const HANDLE free_module_thread_handle = CreateThread(
      0, 0,
      reinterpret_cast<LPTHREAD_START_ROUTINE>( mm_free_module_thread_addr ),
      mm_free_data_arguments_addr, 0, 0 );
  assert( free_module_thread_handle );
}
