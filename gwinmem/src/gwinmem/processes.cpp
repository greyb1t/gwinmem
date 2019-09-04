#include "pch.h"
#include "processes.h"

#include "utils/safe_handle.h"

std::vector<PROCESSENTRY32> gwinmem::processes::GetProcesses() {
  const SafeHandle snapshot_handle =
      CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

  if ( snapshot_handle.GetValue() == INVALID_HANDLE_VALUE )
    return {};

  PROCESSENTRY32 pe32;
  pe32.dwSize = sizeof( pe32 );

  if ( !Process32First( snapshot_handle.GetValue(), &pe32 ) )
    return {};

  std::vector<PROCESSENTRY32> processes;

  do {
    processes.push_back( pe32 );
  } while ( Process32Next( snapshot_handle.GetValue(), &pe32 ) );

  return processes;
}

std::vector<THREADENTRY32> gwinmem::processes::GetThreads(
    const uint32_t process_id ) {
  const SafeHandle snapshot_handle =
      CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );

  if ( snapshot_handle.GetValue() == INVALID_HANDLE_VALUE )
    return {};

  THREADENTRY32 te32;
  te32.dwSize = sizeof( te32 );

  if ( !Thread32First( snapshot_handle.GetValue(), &te32 ) )
    return {};

  std::vector<THREADENTRY32> threads;

  do {
    if ( te32.th32OwnerProcessID == process_id )
      threads.push_back( te32 );
  } while ( Thread32Next( snapshot_handle.GetValue(), &te32 ) );

  return threads;
}
