#include "pch.h"
#include "process_memory_external.h"
#include "processes.h"
#include "utils/string_utils.h"

gwinmem::ProcessMemoryExternal
gwinmem::processmemoryexternal::OpenExternalProcess(
    const std::wstring& process_name ) {
  const auto processes = processes::GetProcesses();
  for ( const auto& process : processes ) {
    if ( wcscmp( process.szExeFile, process_name.c_str() ) == 0 ) {
      return OpenExternalProcess( process.th32ProcessID );
    }
  }

  return {};
}

gwinmem::ProcessMemoryExternal
gwinmem::processmemoryexternal::OpenExternalProcess(
    const uint32_t process_id ) {
  auto process_memory = gwinmem::ProcessMemoryExternal( process_id );

  if ( !process_memory.Open() )
    return {};

  return process_memory;
}

gwinmem::ProcessMemoryExternal::ProcessMemoryExternal(
    const uint32_t process_id )
    : ProcessMemory( process_id ),
      open_process_( OpenProcess ),
      read_process_memory_( ReadProcessMemory ),
      write_process_memory_( WriteProcessMemory ) {}

bool gwinmem::ProcessMemoryExternal::Open() {
  process_handle_ = open_process_( PROCESS_ALL_ACCESS, FALSE, process_id_ );

  if ( !process_handle_.GetValue() )
    return false;

  return true;
}

bool gwinmem::ProcessMemoryExternal::IsOpen() const {
  return !!process_handle_.GetValue();
}

bool gwinmem::ProcessMemoryExternal::ReadBytes( const uintptr_t address,
                                                const uint64_t size,
                                                uint8_t* buf ) {
  const bool ret = !!read_process_memory_(
      process_handle_.GetValue(), reinterpret_cast<LPCVOID>( address ), buf,
      static_cast<SIZE_T>( size ), nullptr );

  // Assert here because we should not allow any reading to memory to fail. That
  // implies incorrect programming practices or bugs.
  assert( ret &&
          "ReadBytes failed, it is most likely you who read invalid memory." );

  return ret;
}

bool gwinmem::ProcessMemoryExternal::WriteBytes( const uintptr_t address,
                                                 const uint64_t size,
                                                 const uint8_t* buf ) {
  const bool ret = !!write_process_memory_(
      process_handle_.GetValue(), reinterpret_cast<LPVOID>( address ), buf,
      static_cast<SIZE_T>( size ), nullptr );

  // Assert here because we should not allow any writing to memory to fail. That
  // implies incorrect programming practices or bugs.
  assert( ret &&
          "WriteBytes failed, it is most likely you who wrote on a invalid "
          "memory location." );

  return ret;
}

uintptr_t gwinmem::ProcessMemoryExternal::RemoteLoadLibrary(
    const std::wstring& dll_directory ) {
  const auto dll_dir_mem_size = dll_directory.size() * sizeof( wchar_t );

  // Allocate the memory for the dll directory in the target process
  const uintptr_t dll_directory_addr =
      Allocate( 0, dll_dir_mem_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );

  // Write the dll directory into the target process
  WriteBytes( dll_directory_addr, dll_dir_mem_size,
              reinterpret_cast<const uint8_t*>( &dll_directory[ 0 ] ) );

  // Using this method, we assume that kernel32.dll is loaded into the target
  const SafeHandle thread_handle = CreateRemoteThread(
      process_handle_.GetValue(), nullptr, 0,
      ( LPTHREAD_START_ROUTINE )LoadLibraryW,
      reinterpret_cast<LPVOID>( dll_directory_addr ), 0, 0 );

  if ( !thread_handle.GetValue() )
    return 0;

  // Wait for the thread to finish loading the dll
  WaitForSingleObject( thread_handle.GetValue(), INFINITE );

  // NOTE: When going to support 64 bit, the DWORD retval might be an issue if
  // it is bigger than a DWORD. Take note in future. Fuck it now tho.
  DWORD loadlibrary_retval = 0;
  GetExitCodeThread( thread_handle.GetValue(), &loadlibrary_retval );

  if ( !loadlibrary_retval )
    return 0;

  return loadlibrary_retval;
}

std::vector<gwinmem::MemoryModule> gwinmem::ProcessMemoryExternal::GetModules()
    const {
  const SafeHandle snapshot_handle =
      CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, process_id_ );

  MODULEENTRY32 me32;
  me32.dwSize = sizeof( me32 );

  if ( !Module32First( snapshot_handle.GetValue(), &me32 ) )
    return {};

  std::vector<gwinmem::MemoryModule> modules;

  do {
    const auto found_module_name_lower =
        stringutils::WideStringToLower( me32.szModule );

    const auto module = MemoryModule(
        found_module_name_lower,
        reinterpret_cast<uintptr_t>( me32.modBaseAddr ), me32.modBaseSize );

    modules.push_back( module );
  } while ( Module32Next( snapshot_handle.GetValue(), &me32 ) );

  return modules;
}

void gwinmem::ProcessMemoryExternal::OverrideDefaultOpenProcess(
    const OpenProcess_t openprocess ) {
  open_process_ = openprocess;
}

void gwinmem::ProcessMemoryExternal::OverrideDefaultReadProcessMemory(
    const ReadProcessMemory_t readprocessmemory ) {
  read_process_memory_ = readprocessmemory;
}

void gwinmem::ProcessMemoryExternal::OverrideDefaultWriteProcessMemory(
    const WriteProcessMemory_t writeprocessmemory ) {
  write_process_memory_ = writeprocessmemory;
}