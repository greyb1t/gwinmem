#pragma once

#include <windows.h>
#include <vector>
#include <TlHelp32.h>
#include <stdint.h>

namespace gwinmem {

namespace processes {

std::vector<PROCESSENTRY32> GetProcesses();
std::vector<THREADENTRY32> GetThreads(const uint32_t process_id);

}

}  // namespace gwinmem