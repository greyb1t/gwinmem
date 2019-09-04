#include "pch.h"
#include "pattern_searcher.h"

bool gwinmem::PatternSearcher::LoadProcess( ProcessMemory& process_memory,
                                            const MemoryModule& module ) {
  module_ = module;

  module_data_.resize( module.size );

  return process_memory.ReadBytes( module.base, module_data_.size(),
                                   &module_data_[ 0 ] );
}

uintptr_t gwinmem::PatternSearcher::FindHexPattern( const char* pattern,
                                                    const char* mask ) {
  const uint8_t* beg_ptr = &module_data_[ 0 ];
  auto pattern_ptr = reinterpret_cast<const uint8_t*>( pattern );

  const auto pattern_length = strlen( mask );

  for ( size_t i = 0, data_size = module_data_.size(); i < data_size; ++i ) {
    if ( ComparePattern( pattern_ptr, mask, beg_ptr + i, pattern_length ) ) {
      return module_.base + i;
    }
  }

  return 0;
}

uintptr_t gwinmem::PatternSearcher::FindIdaSignature( const char* signature ) {
  const auto ida_sig_length = strlen( signature );

  char signature_copy[ 1024 ] = { 0 };
  strcpy_s( signature_copy, signature );

  uint8_t pattern[ 1024 ] = { 0 };
  char mask[ 512 ] = { 0 };

  for ( size_t i = 0, j = 0; j < ida_sig_length; ++i ) {
    if ( signature_copy[ j ] == '?' ) {
      mask[ i ] = '?';
      pattern[ i ] = '\x00';

      j += 2;
    } else {
      char* sign_ptr = signature_copy + j + 1;
      const auto value =
          std::strtoul( signature_copy + j, ( char** )&sign_ptr, 16 );
      pattern[ i ] = static_cast<uint8_t>( value );
      mask[ i ] = 'x';

      j += 3;
    }
  }

  return FindHexPattern( reinterpret_cast<const char*>( pattern ), mask );
}

bool gwinmem::PatternSearcher::ComparePattern( const uint8_t* pattern,
                                               const char* mask,
                                               const uint8_t* data,
                                               const uint32_t pattern_length ) {
  for ( size_t i = 0; i < pattern_length; ++i ) {
    if ( *( mask + i ) == '?' )
      continue;

    if ( *( pattern + i ) != *( data + i ) )
      return false;
  }

  /*
  for ( size_t i = 0; i < pattern_length; ++i ) {
    // If it does not matter what the value on this offset is, skip comparing it
    if ( mask[ i ] == '?' )
      continue;

    if ( pattern[ i ] != data[ i ] )
      return false;
  }
  */

  return true;
}