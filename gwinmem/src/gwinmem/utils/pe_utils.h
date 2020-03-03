#pragma once

#include <Windows.h>
#include <stdint.h>
#include <string>

namespace peutils {

const IMAGE_NT_HEADERS* GetNtHeaders( const uint8_t* data );

template <typename T>
const T GetExport( const uintptr_t module_base,
                   const std::string& function_name );

template <typename T>
uintptr_t GetFunctionAddress( const T function ) {
  // TODO: Support x64

  const auto function_addr = reinterpret_cast<uintptr_t>( function );

  // If the function is a redirection function (usually in Debug Mode with VS),
  // get the relative jump address
  if ( *reinterpret_cast<uint8_t*>( function_addr ) == 0xE9 ) {
    const auto relative_addr =
        *reinterpret_cast<uintptr_t*>( function_addr + 1 );

    return function_addr + relative_addr + 5;
  }

  return function_addr;
}

template <typename T>
const T GetExport( const uintptr_t module_base,
                   const std::string& function_name ) {
  const auto nt_headers =
      peutils::GetNtHeaders( reinterpret_cast<uint8_t*>( module_base ) );

  // Is it a valid PE?
  if ( !nt_headers )
    return 0;

  const auto export_directory =
      &nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

  // Is there an export directory?
  if ( !export_directory->VirtualAddress )
    return 0;

  const auto exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
      module_base + export_directory->VirtualAddress );
  const auto names =
      reinterpret_cast<uint32_t*>( module_base + exports->AddressOfNames );
  const auto ordinals = reinterpret_cast<uint16_t*>(
      module_base + exports->AddressOfNameOrdinals );
  const auto addresses =
      reinterpret_cast<uint32_t*>( module_base + exports->AddressOfFunctions );

  for ( uint32_t i = 0; i < exports->NumberOfNames; ++i ) {
    if ( strcmp( reinterpret_cast<const char*>( module_base + names[ i ] ),
                 function_name.c_str() ) == 0 ) {
      const auto current_func_ordinal = ordinals[ i ];
      const auto export_func_address = &addresses[ current_func_ordinal ];

      // Save the original function address
      const uintptr_t original_function_address =
          module_base + *export_func_address;

      return reinterpret_cast<T>( original_function_address );
    }
  }

  return T();
}

}  // namespace peutils