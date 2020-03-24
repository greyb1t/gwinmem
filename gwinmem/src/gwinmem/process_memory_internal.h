#pragma once

#include "process_memory.h"
#include "utils/string_utils.h"
#include "utils/pe_utils.h"
#include "utils/internal_win32_headers.h"

#include <assert.h>

namespace gwinmem {

enum PROCESSINFOCLASS;
struct PEB;

using NtQueryInformationProcess_t =
    NTSTATUS( NTAPI* )( IN HANDLE ProcessHandle,
                        IN PROCESSINFOCLASS ProcessInformationClass,
                        OUT PVOID ProcessInformation,
                        IN ULONG ProcessInformationLength,
                        OUT PULONG ReturnLength );

class ProcessMemoryInternal;

ProcessMemoryInternal& CurrentProcess();

class ProcessMemoryInternal : public ProcessMemory {
 public:
  ProcessMemoryInternal();

 private:
  bool Open() override;

  PEB* GetCurrentPeb() const;

 public:
  virtual bool ReadBytes( const uintptr_t address,
                          const uint64_t size,
                          uint8_t* buf ) override;

  virtual bool WriteBytes( const uintptr_t address,
                           const uint64_t size,
                           const uint8_t* buf ) override;

  virtual uintptr_t RemoteLoadLibrary(
      const std::wstring& dll_directory ) override;

  virtual std::vector<MemoryModule> GetModules() const override;

  // Add the manual mapped module to the peb loader tables to have a proper
  // crash dump with the module name included otherwise I can only view the
  // disassembly of where the error occured.
  bool ManualMapAddLoaderDll( const uintptr_t dll_base,
                              const std::wstring& module_directory );

  // bool ManualMapAddLoaderModule(
  //    const PVOID dll_base,
  //    const std::wstring& module_directory );

  // Hooks the specified function and returns the original function
  template <typename HookCallback_t>
  HookCallback_t HookIat( const std::string& dll_name,
                          const std::string& function_name,
                          const HookCallback_t hook_callback );

  template <typename HookCallback_t>
  bool UnHookIat( const std::string& dll_name,
                  const std::string& function_name,
                  const HookCallback_t original_function );

  // Hooks the specified function and returns the original function
  template <typename HookCallback_t>
  HookCallback_t HookEat( const MemoryModule& module,
                          const std::string& function_name,
                          const HookCallback_t hook_callback );

  template <typename HookCallback_t>
  bool UnHookEat( const MemoryModule& module,
                  const std::string& function_name,
                  const HookCallback_t original_function );

  static NTSTATUS NTAPI
  NtQueryInformationProcessHooked( HANDLE ProcessHandle,
                                   PROCESSINFOCLASS ProcessInformationClass,
                                   PVOID ProcessInformation,
                                   ULONG ProcessInformationLength,
                                   PULONG ReturnLength );

  // Hooks NtQueryInformationProcess and ensures that RtlIsValidHandler returns
  // true. The hook detours the code in ntdll.
  bool ManualMapFixExceptionHandling();

  // LDR_DATA_TABLE_ENTRY* entry, needs one member valid, it is DllBase
  bool ManualMapHandleStaticTlsData( LDR_DATA_TABLE_ENTRY* entry );

  // Unhooks NtQueryInformationProcess
  bool ManualMapResetExceptionHandling();

  // LDR_DATA_TABLE_ENTRY* entry, needs to be the same as the one passed
  // into the ManualMapHandleStaticTlsData function
  bool ManualMapFreeStaticTlsData( LDR_DATA_TABLE_ENTRY* entry );

  void ManualMapStartFreeDllThread( const uintptr_t mapped_module_base );

 private:
  NtQueryInformationProcess_t original_nt_query_info_process_;
};

template <typename HookCallback_t>
HookCallback_t ProcessMemoryInternal::HookIat(
    const std::string& hook_dll_name,
    const std::string& hook_function_name,
    const HookCallback_t hook_callback ) {
  const auto modules = GetModules();
  // TODO: I know, a fucking horrible piece of code. Should be divided up into
  // functions, but fuck it for now.

  // TODO: Idea, allocated a mem region in the target module in empty areas that
  // jumps to my hook instead. Bypasses some detection methods.

  // Since another module other than the main module can import functions, we go
  // though everyone.
  for ( const auto& module : modules ) {
    const auto nt_headers =
        peutils::GetNtHeaders( reinterpret_cast<uint8_t*>( module.base ) );

    // Is it a valid PE?
    if ( !nt_headers )
      continue;

    const auto import_directory =
        &nt_headers->OptionalHeader
             .DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];

    // Is there an import directory?
    if ( !import_directory->VirtualAddress )
      continue;

    // For each import desc
    for ( auto import_desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
              module.base + import_directory->VirtualAddress );
          import_desc->Name; ++import_desc ) {
      // Read the function associated dll name
      const std::string dll_name_lower = stringutils::StringToLower(
          reinterpret_cast<const char*>( module.base + import_desc->Name ) );

      // Since we are only looking for a function from a specific DLL, check if
      // the DLL name is the one we want that contains the function we want to
      // hook to avoid going though every import desc.
      if ( dll_name_lower == hook_dll_name ) {
        auto original_thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
            module.base + import_desc->OriginalFirstThunk );
        auto first_thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
            module.base + import_desc->FirstThunk );

        // For each import thunk
        for ( ; original_thunk->u1.AddressOfData;
              ++original_thunk, ++first_thunk ) {
          assert( original_thunk );

          if ( IMAGE_SNAP_BY_ORDINAL( original_thunk->u1.Ordinal ) ) {
            assert( false && "Handle ordinal" );
          } else {
            // Read the import info in that thunk
            const auto import = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                module.base + original_thunk->u1.AddressOfData );

            if ( strcmp( import->Name, hook_function_name.c_str() ) == 0 ) {
              // Use the first thunk that has been modified by the loader which
              // is containing the addresses
              DWORD old_protection;
              VirtualProtect(
                  reinterpret_cast<LPVOID>( &first_thunk->u1.Function ),
                  sizeof( uintptr_t ), PAGE_READWRITE, &old_protection );

              // Save the original function address
              const uintptr_t original_function_address =
                  first_thunk->u1.Function;

              // Replace the function address with a callback address
              first_thunk->u1.Function =
                  reinterpret_cast<uintptr_t>( hook_callback );

              // Reset the protection
              VirtualProtect(
                  reinterpret_cast<LPVOID>( &first_thunk->u1.Function ),
                  sizeof( uintptr_t ), old_protection, &old_protection );

              return reinterpret_cast<HookCallback_t>(
                  original_function_address );
            }
          }
        }
      }
    }
  }

  return 0;
}

template <typename HookCallback_t>
inline bool ProcessMemoryInternal::UnHookIat(
    const std::string& dll_name,
    const std::string& function_name,
    const HookCallback_t original_function ) {
  // Not the most performance'y kind of way, but it works. Can't bother making
  // it into its own class.
  return !!HookIat( dll_name, function_name, original_function );
}

template <typename HookCallback_t>
inline HookCallback_t ProcessMemoryInternal::HookEat(
    const MemoryModule& module,
    const std::string& function_name,
    const HookCallback_t hook_callback ) {
  const auto nt_headers =
      peutils::GetNtHeaders( reinterpret_cast<uint8_t*>( module.base ) );

  // Is it a valid PE?
  if ( !nt_headers )
    return 0;

  const auto export_directory =
      &nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

  // Is there an export directory?
  if ( !export_directory->VirtualAddress )
    return 0;

  const auto exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
      module.base + export_directory->VirtualAddress );
  const auto names =
      reinterpret_cast<uint32_t*>( module.base + exports->AddressOfNames );
  const auto ordinals = reinterpret_cast<uint16_t*>(
      module.base + exports->AddressOfNameOrdinals );
  const auto addresses =
      reinterpret_cast<uint32_t*>( module.base + exports->AddressOfFunctions );

  for ( uint32_t i = 0; i < exports->NumberOfNames; ++i ) {
    if ( strcmp( reinterpret_cast<const char*>( module.base + names[ i ] ),
                 function_name.c_str() ) == 0 ) {
      const auto current_func_ordinal = ordinals[ i ];
      const auto export_func_address = &addresses[ current_func_ordinal ];

      // Use the first thunk that has been modified by the loader which
      // is containing the addresses
      DWORD old_protection;
      VirtualProtect( reinterpret_cast<LPVOID>( export_func_address ),
                      sizeof( uintptr_t ), PAGE_READWRITE, &old_protection );

      // Save the original function address
      const uintptr_t original_function_address =
          module.base + *export_func_address;

      // Replace the function address with a callback rva address
      *export_func_address =
          reinterpret_cast<uintptr_t>( hook_callback ) - module.base;

      // Reset the protection
      VirtualProtect( reinterpret_cast<LPVOID>( export_func_address ),
                      sizeof( uintptr_t ), old_protection, &old_protection );

      return reinterpret_cast<HookCallback_t>( original_function_address );
    }
  }

  return HookCallback_t();
}

template <typename HookCallback_t>
inline bool ProcessMemoryInternal::UnHookEat(
    const MemoryModule& module,
    const std::string& function_name,
    const HookCallback_t hook_callback ) {
  // Not the most performance'y kind of way, but it works. Can't bother making
  // it into its own class.
  return !!HookEat( module, function_name, hook_callback );
}

}  // namespace gwinmem