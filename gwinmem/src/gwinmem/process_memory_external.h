#pragma once

#include "process_memory.h"

namespace gwinmem {

using OpenProcess_t = HANDLE( WINAPI* )( DWORD dwDesiredAccess,
                                         BOOL bInheritHandle,
                                         DWORD dwProcessId );

using ReadProcessMemory_t = BOOL( WINAPI* )( HANDLE hProcess,
                                             LPCVOID lpBaseAddress,
                                             LPVOID lpBuffer,
                                             SIZE_T nSize,
                                             SIZE_T* lpNumberOfBytesRead );

using WriteProcessMemory_t = BOOL( WINAPI* )( HANDLE hProcess,
                                              LPVOID lpBaseAddress,
                                              LPCVOID lpBuffer,
                                              SIZE_T nSize,
                                              SIZE_T* lpNumberOfBytesWritten );

class ProcessMemoryExternal;

namespace processmemoryexternal {

ProcessMemoryExternal OpenExternalProcess( const std::wstring& process_name );
ProcessMemoryExternal OpenExternalProcess( const uint32_t process_id );
}  // namespace processmemoryexternal

class ProcessMemoryExternal : public ProcessMemory {
 private:
  ProcessMemoryExternal() : ProcessMemory( 0 ) {}
  ProcessMemoryExternal( const uint32_t process_id );

  bool Open() override;

 public:
  bool IsOpen() const;

  virtual bool ReadBytes( const uintptr_t address,
                          const uint64_t size,
                          uint8_t* buf ) override;

  virtual bool WriteBytes( const uintptr_t address,
                           const uint64_t size,
                           const uint8_t* buf ) override;

  virtual uintptr_t RemoteLoadLibrary(
      const std::wstring& dll_directory ) override;

  virtual std::vector<MemoryModule> GetModules() const override;

  void OverrideDefaultOpenProcess( const OpenProcess_t openprocess );
  void OverrideDefaultReadProcessMemory(
      const ReadProcessMemory_t readprocessmemory );
  void OverrideDefaultWriteProcessMemory(
      const WriteProcessMemory_t writeprocessmemory );

  friend ProcessMemoryExternal processmemoryexternal::OpenExternalProcess(
      const uint32_t process_id );

  friend ProcessMemoryExternal processmemoryexternal::OpenExternalProcess(
      const std::wstring& process_name );

 private:
  OpenProcess_t open_process_;
  ReadProcessMemory_t read_process_memory_;
  WriteProcessMemory_t write_process_memory_;
};

}  // namespace gwinmem