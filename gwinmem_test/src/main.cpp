#include <iostream>
#include <Shlobj.h>

#pragma comment( lib, "gwinmem.lib" )

#include "gwinmem/processes.h"
#include "gwinmem/process_memory_external.h"
#include "gwinmem/process_memory_internal.h"
#include "gwinmem/utils/safe_handle.h"
#include "gwinmem/pattern_searcher.h"

#include <dbghelp.h>
#include <string>

#pragma comment( lib, "Dbghelp.lib" )

struct SomeData2 {
  int value1;
  int value2;
  std::wstring value3{ TEXT( "Some Random Value" ) };
  std::string value4{ "Some Random Value" };
  int value5;
};

struct SomeData1 {
  int value1;
  int value2;
  SomeData2* some_data2;
};

bool ReadFileData( const std::wstring& filename,
                   std::vector<uint8_t>* file_data ) {
  gwinmem::SafeHandle handle =
      CreateFile( filename.c_str(), GENERIC_READ, FILE_SHARE_READ, 0,
                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );

  if ( handle.GetValue() == INVALID_HANDLE_VALUE )
    return false;

  DWORD file_size = GetFileSize( handle.GetValue(), 0 );

  std::vector<uint8_t> buf;

  buf.resize( file_size );

  DWORD bytes_read = 0;

  if ( !ReadFile( handle.GetValue(), &buf[ 0 ], file_size, &bytes_read, 0 ) )
    return false;

  if ( bytes_read != file_size )
    return false;

  *file_data = buf;

  return true;
}

std::wstring GetSysWow64Directory() {
  PWSTR buf;

  SHGetKnownFolderPath( FOLDERID_SystemX86, KF_FLAG_DEFAULT, NULL, &buf );

  std::wstring s = buf;

  CoTaskMemFree( buf );

  return s;
}

void TestSomeShit() {
  int test_value1 = 1337;

  uint32_t test_value1_read = gwinmem::CurrentProcess().Read<uint32_t>(
      reinterpret_cast<uintptr_t>( &test_value1 ) );

  assert( test_value1_read == test_value1 );

  SomeData1 somedata;
  somedata.value1 = 1337;
  somedata.value2 = 1338;
  somedata.some_data2 = new SomeData2{ 666, 999 };

  SomeData1 somedata_read = gwinmem::CurrentProcess().Read<SomeData1>(
      reinterpret_cast<uintptr_t>( &somedata ) );

  int somedata2_offset2_2 = gwinmem::CurrentProcess().Read<int>(
      reinterpret_cast<uintptr_t>( &somedata ) + 0x8, { 0x4 } );

  assert( somedata2_offset2_2 == somedata.some_data2->value2 );

  gwinmem::CurrentProcess().Write( reinterpret_cast<uintptr_t>( &test_value1 ),
                                   1234 );

  assert( test_value1 == 1234 );

  gwinmem::CurrentProcess().Write<int>(
      reinterpret_cast<uintptr_t>( &somedata ) + 0x8, { 0x4 }, 123456 );

  assert( somedata.some_data2->value2 == 123456 );
}

int main() {
  using NtQueryInformationProcess_t = NTSTATUS( NTAPI* )(
      IN HANDLE ProcessHandle, IN ULONG ProcessInformationClass,
      OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength,
      OUT PULONG ReturnLength );

  auto ntdll_module =
      gwinmem::CurrentProcess().GetModule( TEXT( "ntdll.dll" ) );

  assert( ntdll_module.base != 0 );

  wchar_t ntdll_path[ MAX_PATH ] = { 0 };
  GetModuleFileName( LoadLibrary( TEXT( "ntdll" ) ), ntdll_path, MAX_PATH );

  //const auto syswow64_path = GetSysWow64Directory();
  //const auto ntdll_path = syswow64_path + TEXT( "\\ntdll.dll" );

  std::vector<uint8_t> ntdll_data;

  if ( !ReadFileData( ntdll_path, &ntdll_data ) ) {
    return -1;
  }

  const auto ntdll_headers = peutils::GetNtHeaders( ntdll_data.data() );

  const auto my_headers = peutils::GetNtHeaders(
      reinterpret_cast<uint8_t*>( GetModuleHandle( 0 ) ) );

  // We must load the ntdll with the same bitness
  assert( my_headers->FileHeader.Machine == ntdll_headers->FileHeader.Machine );

  const auto ntdll_manual_mapped_base =
      gwinmem::CurrentProcess().ManualMapDll( TEXT( "bullshit" ), ntdll_data );

  assert( ntdll_manual_mapped_base != 0 );

  const auto Wow64TransitionAddress =
      peutils::GetExport<void*>( ntdll_manual_mapped_base, "Wow64Transition" );

  const auto wow64_transition_original = GetProcAddress(
      reinterpret_cast<HMODULE>( ntdll_module.base ), "Wow64Transition" );

  DWORD old_protection;
  VirtualProtect( Wow64TransitionAddress, sizeof( Wow64TransitionAddress ),
                  PAGE_EXECUTE_READWRITE, &old_protection );

  memcpy( Wow64TransitionAddress, wow64_transition_original,
          sizeof( Wow64TransitionAddress ) );

  VirtualProtect( Wow64TransitionAddress, sizeof( Wow64TransitionAddress ),
                  old_protection, &old_protection );

  const auto nt_query_information_process_mapped =
      peutils::GetExport<NtQueryInformationProcess_t>(
          ntdll_manual_mapped_base, "NtQueryInformationProcess" );

  /*
    Tested against scylla hide
    
    Does not work. Why? 
    
    Because scyllahide hooks Wow64Transition, that is the only I fixup my mapped ntdll with.
  */

  while ( true ) {
    nt_query_information_process_mapped( ( HANDLE )-1, 0x20, 0, 0, 0 );

    PVOID mapped_retval;
    nt_query_information_process_mapped( ( HANDLE )-1, 0x07, &mapped_retval, 4,
                                         NULL );

    if ( mapped_retval != 0 ) {
      std::cout << "[MAPPED NTDLL] detected debugger" << std::endl;
    } else {
      std::cout << "[MAPPED NTDLL] not debugging" << std::endl;
    }

    const auto nt_query_information_process_original =
        reinterpret_cast<NtQueryInformationProcess_t>(
            GetProcAddress( reinterpret_cast<HMODULE>( ntdll_module.base ),
                            "NtQueryInformationProcess" ) );

    nt_query_information_process_original( ( HANDLE )-1, 0x20, 0, 0, 0 );

    PVOID original_retval;
    nt_query_information_process_original( ( HANDLE )-1, 0x07, &original_retval,
                                           4, NULL );

    if ( original_retval != 0 ) {
      std::cout << "[ORIGINAL NTDLL] detected debugger" << std::endl;
    } else {
      std::cout << "[ORIGINAL NTDLL] not debugging" << std::endl;
    }

    Sleep( 500 );
  }

  TestSomeShit();

  std::cin.get();

  return 0;
}