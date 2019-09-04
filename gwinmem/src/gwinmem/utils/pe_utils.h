#pragma once

#include <Windows.h>
#include <stdint.h>

namespace peutils {

const IMAGE_NT_HEADERS* GetNtHeaders( const uint8_t* data );

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

}  // namespace peutils