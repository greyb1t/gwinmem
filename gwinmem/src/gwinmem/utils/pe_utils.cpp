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

PdbInfo* peutils::GetPdbInfoFromModule( const uintptr_t module_base ) {
  const auto nt_header =
      GetNtHeaders( reinterpret_cast<uint8_t*>( module_base ) );

  if ( !nt_header )
    return 0;

  const auto debug_data_directory =
      &nt_header->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_DEBUG ];

  // Does the directory exist?
  //
  if ( !debug_data_directory->Size )
    return 0;

  const auto debug_directory = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(
      module_base + debug_data_directory->VirtualAddress );

  if ( !debug_directory )
    return 0;

  if ( debug_directory->Type == IMAGE_DEBUG_TYPE_CODEVIEW ) {
    const auto pdb_info = reinterpret_cast<PdbInfo*>(
        module_base + debug_directory->AddressOfRawData );

    return pdb_info;
  }

  return 0;
}