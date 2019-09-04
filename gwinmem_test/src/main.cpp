#include <iostream>

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
    return {};

  *file_data = buf;

  return true;
}

using MessageBoxW_t = int( WINAPI* )( HWND hWnd,
                                      LPCWSTR lpText,
                                      LPCWSTR lpCaption,
                                      UINT uType );
MessageBoxW_t g_original_message_box_w = 0;

int WINAPI MessageBoxWHook( HWND hWnd,
                            LPCWSTR lpText,
                            LPCWSTR lpCaption,
                            UINT uType ) {
  std::wcout << TEXT( "in hook" ) << std::endl;
  return g_original_message_box_w( hWnd, lpText, lpCaption, uType );
}

int main() {
  const auto window =
      gwinmem::CurrentProcess().FindWindowsCreatedByProcess( {} );

  auto ntdll_module =
      gwinmem::CurrentProcess().GetModule( TEXT( "ntdll.dll" ) );

  int some_value1 = 1337;

  uint32_t some_value1_read = gwinmem::CurrentProcess().Read<uint32_t>(
      reinterpret_cast<uintptr_t>( &some_value1 ) );

  // int some_value1_read2 = process_memory_external.Read<int>(
  //    reinterpret_cast<uintptr_t>( &some_value1 ) );

  SomeData1 somedata1;
  somedata1.value1 = 1337;
  somedata1.value2 = 1338;
  somedata1.some_data2 = new SomeData2{ 666, 999 };

  // SomeData1 data = process_memory_external.Read<SomeData1>(
  //    reinterpret_cast<uintptr_t>( &somedata1 ) );

  SomeData1 data2 = gwinmem::CurrentProcess().Read<SomeData1>(
      reinterpret_cast<uintptr_t>( &somedata1 ) );

  // int some_data_2_offset2 = process_memory_external.Read<int>(
  //    reinterpret_cast<uintptr_t>( &somedata1 ) + 0x8, { 0x4 } );
  int some_data_2_offset2_2 = gwinmem::CurrentProcess().Read<int>(
      reinterpret_cast<uintptr_t>( &somedata1 ) + 0x8, { 0x4 } );

  std::wcout << ( uintptr_t )somedata1.some_data2->value3.data() << std::endl;
  std::cout << ( uintptr_t )somedata1.some_data2->value4.data() << std::endl;

  // uintptr_t string_addr = 0;
  // std::string string_from_memory =
  //    process_memory_external.ReadString( string_addr, 255 );
  // std::string string_from_memory2 =
  //    gwinmem::InternalProcess().ReadString( string_addr, 255 );

  // process_memory_external.Write( reinterpret_cast<uintptr_t>( &some_value1 ),
  //                               123 );
  gwinmem::CurrentProcess().Write( reinterpret_cast<uintptr_t>( &some_value1 ),
                                   1234 );

  // process_memory_external.Write<int>(
  //    reinterpret_cast<uintptr_t>( &somedata1 ) + 0x8, { 0x4 }, 12345 );
  gwinmem::CurrentProcess().Write<int>(
      reinterpret_cast<uintptr_t>( &somedata1 ) + 0x8, { 0x4 }, 123456 );

  // uintptr_t string_addr = 0;
  // process_memory_external.WriteString( string_addr, "A Radom test222" );
  // gwinmem::InternalProcess().WriteString( string_addr, "A random test 1" );

  // process_memory_external.RemoteLoadLibrary(TEXT("D:\\development\\projects\\C++\\gWin
  // Framework\\RIMJOB.module.dll"));

  ////std::vector<uint8_t> data;
  ////ReadFileData(
  ////    // TEXT( "D:\\development\\projects\\C++\\Flyff Bot "
  ////    //      "V2\\bin\\Win32\\Release\\RIMJOB.module.dll" ),
  ////    TEXT(
  ////        "D:\\development\\projects\\C++\\gWin
  /// Framework\\RIMJOB.module.dll" ), /    &data );

  ////// TODO: Continue by figuring out what should be in what.

  ////const uintptr_t mm_addr =
  ////    gwinmem::ProcessInternal().ManualMapDll( TEXT( "dicky" ), data );

  ////std::vector<uint8_t> data2;
  ////ReadFileData(
  ////    // TEXT( "D:\\development\\projects\\C++\\Flyff Bot "
  ////    //      "V2\\bin\\Win32\\Release\\RIMJOB.module.dll" ),
  ////    TEXT( "D:\\development\\projects\\C++\\Example "
  ////          "Dll\\bin\\Win32\\Release\\Example Dll.dll" ),
  ////    &data2 );

  ////const uintptr_t mm_addr2 =
  ////    gwinmem::ProcessInternal().ManualMapDll( TEXT( "cocky" ), data2 );

  const auto user32 =
      gwinmem::CurrentProcess().GetModule( TEXT( "user32.dll" ) );

  g_original_message_box_w = gwinmem::CurrentProcess().HookIat(
      ( "user32.dll" ), ( "MessageBoxW" ), MessageBoxWHook );

  MessageBoxW( 0, TEXT( "dicks" ), TEXT( "dicks 2" ), 0 );

  bool unhook = gwinmem::CurrentProcess().UnHookIat(
      "user32.dll", "MessageBoxW", g_original_message_box_w );

  MessageBoxW( 0, TEXT( "dicks" ), TEXT( "dicks 2" ), 0 );

  // gwinmem::InternalProcess().ManualMapAddDllLoaderTable(mm_addr,
  // TEXT("D:\\development\\projects\\C++\\gWin Framework\\RIMJOB.module.dll"));
  //
  // const auto lol =
  //     gwinmem::InternalProcess().GetModule( TEXT( "kernel32.dll" ) );

  const auto valuie = gwinmem::CurrentProcess().ManualMapFixExceptionHandling();

  using NtQueryInformationProcess_t = NTSTATUS( NTAPI* )(
      IN HANDLE ProcessHandle, IN ULONG ProcessInformationClass,
      OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength,
      OUT PULONG ReturnLength );

  const auto ntdlll = GetModuleHandle( TEXT( "ntdll.dll" ) );
  const auto nt_q = reinterpret_cast<NtQueryInformationProcess_t>(
      GetProcAddress( ntdlll, "NtQueryInformationProcess" ) );

  nt_q( ( HANDLE )-1, 0x20, 0, 0, 0 );

  const auto valu2ie =
      gwinmem::CurrentProcess().ManualMapResetExceptionHandling();

  nt_q( ( HANDLE )-1, 0x20, 0, 0, 0 );

  gwinmem::CurrentProcess().ManualMapStartFreeDllThread( 0 );

  std::cin.get();

  return 0;
}