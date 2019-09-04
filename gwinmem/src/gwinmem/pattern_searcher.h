#pragma once

#include <vector>
#include <stdint.h>

#include "process_memory.h"

namespace gwinmem {

class PatternSearcher {
 public:
  PatternSearcher() = default;

  bool LoadProcess( ProcessMemory& process_memory, const MemoryModule& module );

  uintptr_t FindHexPattern( const char* pattern, const char* mask );
  uintptr_t FindIdaSignature( const char* signature );

 private:
  bool ComparePattern( const uint8_t* pattern,
                       const char* mask,
                       const uint8_t* data,
                       const uint32_t pattern_length );

  MemoryModule module_;
  std::vector<uint8_t> module_data_;
};

}  // namespace gwinmem