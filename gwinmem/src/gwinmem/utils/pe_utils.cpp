#include "pch.h"
#include "pe_utils.h"

const IMAGE_NT_HEADERS* peutils::GetNtHeaders( const uint8_t* data ) {
  const auto dos_headers = reinterpret_cast<const IMAGE_DOS_HEADER*>( data );

  // Check if the dll_data is a dll, otherwise return false
  if ( dos_headers->e_magic != IMAGE_DOS_SIGNATURE )
    return 0;

  auto nt_headers =
      reinterpret_cast<const IMAGE_NT_HEADERS*>( data + dos_headers->e_lfanew );

  if ( nt_headers->Signature != IMAGE_NT_SIGNATURE )
    return 0;

  return nt_headers;
}
