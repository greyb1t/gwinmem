#pragma once

#include <Windows.h>
#include <vector>
#include <string>
#include <stdint.h>
#include <stdexcept>

#include "utils/safe_handle.h"

namespace gwinmem {

class BadMemoryException : public std::runtime_error {
public:
  BadMemoryException( const std::string& message )
      : std::runtime_error( message ) {}
};

using VirtualAllocEx_t = LPVOID( WINAPI* )( HANDLE hProcess,
                                            LPVOID lpAddress,
                                            SIZE_T dwSize,
                                            DWORD flAllocationType,
                                            DWORD flProtect );

using Read_t = bool ( * )( const uintptr_t address,
                           const uint64_t size,
                           uint8_t* buf );

using Write_t = bool ( * )( const uintptr_t address,
                            const uint64_t size,
                            uint8_t* buf );

using SearchConditionCallback_t = bool ( * )( const HWND window_handle );

struct MemoryModule {
  MemoryModule() = default;

  MemoryModule( const std::wstring& name_, uintptr_t base_, uint32_t size_ )
      : name( name_ ), base( base_ ), size( size_ ) {}

  std::wstring name{ 0 };
  uintptr_t base{ 0 };
  uint32_t size{ 0 };
};

class ProcessMemory {
 private:
  // Make protected to prevent any user from making an instance of the class
  // themeselves, force the wrapper methods to create them.
 protected:
  ProcessMemory( const uint32_t process_id );
  ~ProcessMemory();
  ProcessMemory( const ProcessMemory& process_memory );

  virtual bool Open() = 0;

  virtual std::vector<MemoryModule> GetModules() const = 0;

 public:
  virtual bool ReadBytes( const uintptr_t address,
                          const uint64_t size,
                          uint8_t* buf ) = 0;

  virtual bool WriteBytes( const uintptr_t address,
                           const uint64_t size,
                           const uint8_t* buf ) = 0;

  virtual MemoryModule GetModule( const std::wstring& name );

  template <typename T>
  T Read( const uintptr_t address );

  template <typename T>
  T Read( const uintptr_t address, const std::vector<uint32_t>& offsets );

  std::string ReadString( const uintptr_t address, const uint32_t size );
  std::string ReadString( const uintptr_t address,
                          const uint32_t size,
                          const std::vector<uint32_t>& offsets );

  template <typename T>
  void Write( const uintptr_t address, const T& value );

  template <typename T>
  void Write( const uintptr_t address,
              const std::vector<uint32_t>& offsets,
              const T& value );

  void WriteString( const uintptr_t address, const std::string& value );
  void WriteString( const uintptr_t address,
                    const std::vector<uint32_t>& offsets,
                    const std::string& value );

  uintptr_t Allocate( const uintptr_t address,
                      const uint32_t size,
                      const uint32_t allocation_type,
                      const uint32_t protection );

  uintptr_t Allocate( const uint32_t size );

  std::vector<HWND> FindWindowsCreatedByProcess(
      const std::vector<SearchConditionCallback_t>& search_conditions = {} );

  virtual uintptr_t RemoteLoadLibrary( const std::wstring& dll_directory ) = 0;

  uintptr_t ManualMapDll( const std::wstring& name,
                          const std::vector<uint8_t>& dll_data );

  void OverrideDefaultVirtualAllocEx( const VirtualAllocEx_t virtual_alloc_ex );

 private:
  uintptr_t ReadPointersUntilLastOffset( const uintptr_t address,
                                         const std::vector<uint32_t>& offsets );

 protected:
  uint32_t process_id_;
  SafeHandle process_handle_;

  class ManualMapper;
  ManualMapper* manual_mapper_;

  VirtualAllocEx_t virtual_alloc_ex_;
};

template <typename T>
inline T ProcessMemory::Read( const uintptr_t address ) {
  T value;

  ReadBytes( address, sizeof( T ), reinterpret_cast<uint8_t*>( &value ) );

  return value;
}

template <typename T>
inline T ProcessMemory::Read( const uintptr_t address,
                              const std::vector<uint32_t>& offsets ) {
  const auto last_address = ReadPointersUntilLastOffset( address, offsets );
  return Read<T>( last_address );
}

template <typename T>
inline void ProcessMemory::Write( const uintptr_t address, const T& value ) {
  WriteBytes( address, sizeof( T ),
              reinterpret_cast<const uint8_t*>( &value ) );
}

template <typename T>
inline void ProcessMemory::Write( const uintptr_t address,
                                  const std::vector<uint32_t>& offsets,
                                  const T& value ) {
  const auto last_address = ReadPointersUntilLastOffset( address, offsets );
  Write<T>( last_address, value );
}

}  // namespace gwinmem