#include "pch.h"
#include "process_memory.h"
#include "utils/internal_win32_headers.h"
#include "utils/pe_utils.h"
#include "utils/string_utils.h"

#include <map>
#include <assert.h>

// Private implementation of the class
class gwinmem::ProcessMemory::ManualMapper {
 public:
  ManualMapper() = default;
  ManualMapper( const ManualMapper& manual_mapper ) = default;

  uintptr_t ManualMapDll( const std::wstring& name,
                          const std::vector<uint8_t>& dll_data,
                          ProcessMemory& process_memory );

 private:
  // TODO: Consider removing these functions and only defining and declaring
  // them in the CPP file.
  void RelocateImage( const IMAGE_NT_HEADERS* nt_headers,
                      const uintptr_t delta,
                      uint8_t* data );

  void FixImportTable( const IMAGE_NT_HEADERS* nt_headers,
                       uint8_t* data,
                       ProcessMemory& process_memory );

  IMAGE_SECTION_HEADER* GetSectionFromRva( const IMAGE_NT_HEADERS* nt_headers,
                                           const uintptr_t rva );
  uintptr_t RvaToFileOffset( const IMAGE_NT_HEADERS* nt_headers,
                             const uintptr_t rva );

  std::wstring GetSystemDllPath( const std::wstring& dll_name );

 private:
  std::map<std::wstring, uintptr_t> mapped_dlls_;
};

gwinmem::ProcessMemory::ProcessMemory( const uint32_t process_id )
    : process_id_( process_id ), virtual_alloc_ex_( VirtualAllocEx ) {
  manual_mapper_ = new ManualMapper;
  OutputDebugString(
      ( std::wstring( TEXT( "ProcessMemory::ProcessMemory: " ) ) +
        std::to_wstring( process_id ) + TEXT( "\n" ) )
          .c_str() );
}

gwinmem::ProcessMemory::~ProcessMemory() {
  if ( manual_mapper_ )
    delete manual_mapper_;
}

gwinmem::ProcessMemory::ProcessMemory( const ProcessMemory& process_memory ) {
  *this = process_memory;
  manual_mapper_ = new ManualMapper( *process_memory.manual_mapper_ );
}

gwinmem::MemoryModule gwinmem::ProcessMemory::GetModule(
    const std::wstring& name ) {
  const auto modules = GetModules();

  for ( const auto& module : modules ) {
    if ( module.name == stringutils::WideStringToLower( name ) ) {
      return module;
    }
  }

  return MemoryModule();
}

std::string gwinmem::ProcessMemory::ReadString( const uintptr_t address,
                                                const uint32_t size ) {
  std::string s( size, '\0' );

  ReadBytes( address, size, reinterpret_cast<uint8_t*>( &s[ 0 ] ) );

  s.resize( strlen( s.c_str() ) );

  return s;
}

std::string gwinmem::ProcessMemory::ReadString(
    const uintptr_t address,
    const uint32_t size,
    const std::vector<uint32_t>& offsets ) {
  const auto last_address = ReadPointersUntilLastOffset( address, offsets );
  return ReadString( last_address, size );
}

void gwinmem::ProcessMemory::WriteString( const uintptr_t address,
                                          const std::string& value ) {
  WriteBytes( address, value.size(),
              reinterpret_cast<const uint8_t*>( value.data() ) );
}

void gwinmem::ProcessMemory::WriteString( const uintptr_t address,
                                          const std::vector<uint32_t>& offsets,
                                          const std::string& value ) {
  const auto last_address = ReadPointersUntilLastOffset( address, offsets );
  return WriteString( last_address, value );
}

uintptr_t gwinmem::ProcessMemory::Allocate( const uintptr_t address,
                                            const uint32_t size,
                                            const uint32_t allocation_type,
                                            const uint32_t protection ) {
  return reinterpret_cast<uintptr_t>( virtual_alloc_ex_(
      process_handle_.GetValue(), reinterpret_cast<LPVOID>( address ), size,
      allocation_type, protection ) );
}

uintptr_t gwinmem::ProcessMemory::Allocate( const uint32_t size ) {
  return Allocate( 0, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
}

std::vector<HWND> gwinmem::ProcessMemory::FindWindowsCreatedByProcess(
    const std::vector<SearchConditionCallback_t>& search_conditions ) {
  struct WindowEnumCallbackData {
    ProcessMemory* process_memory;
    const std::vector<SearchConditionCallback_t>* search_conditions;
    std::vector<HWND> found_window_handles;
  };

  const auto enum_wnd_callback = []( HWND window_handle,
                                     LPARAM lparam ) -> BOOL CALLBACK {
    DWORD id;
    GetWindowThreadProcessId( window_handle, &id );

    const auto window_enum_callback_data =
        reinterpret_cast<WindowEnumCallbackData*>( lparam );
    auto process_memory = window_enum_callback_data->process_memory;
    const auto& search_conditions =
        *window_enum_callback_data->search_conditions;

    // WCHAR buffer[ MAX_PATH ] = { 0 };
    // GetWindowText( window_handle, buffer, MAX_PATH );

    if ( process_memory->process_id_ == id ) {
      // If there are no conditions, then it is valid, otherwise, it is invalid
      // from the start
      bool meets_conditions = search_conditions.empty();

      for ( const auto& condition : search_conditions ) {
        if ( condition( window_handle ) ) {
          meets_conditions = true;
          break;
        }
      }

      if ( meets_conditions ) {
        window_enum_callback_data->found_window_handles.push_back(
            window_handle );

        // Stop enumerating windows
        // return FALSE;
      }
    }

    return TRUE;
  };

  WindowEnumCallbackData data;
  data.process_memory = this;
  data.search_conditions = &search_conditions;

  EnumWindows( enum_wnd_callback, reinterpret_cast<LPARAM>( &data ) );

  return std::move( data.found_window_handles );
}

uintptr_t gwinmem::ProcessMemory::ManualMapDll(
    const std::wstring& name,
    const std::vector<uint8_t>& dll_data ) {
  return manual_mapper_->ManualMapDll( name, dll_data, *this );
}

void gwinmem::ProcessMemory::OverrideDefaultVirtualAllocEx(
    const VirtualAllocEx_t virtual_alloc_ex ) {
  virtual_alloc_ex_ = virtual_alloc_ex;
}

uintptr_t gwinmem::ProcessMemory::ReadPointersUntilLastOffset(
    const uintptr_t address,
    const std::vector<uint32_t>& offsets ) {
  auto pointer = Read<uintptr_t>( address );

  if ( pointer == 0 ) {
    throw gwinmem::BadMemoryException(
        "ReadBytes read a null value, it is most likely you who read invalid "
        "memory. Address: " +
        std::to_string( address ) );
  }

  const uint32_t last_offset_index = offsets.empty() ? 0 : offsets.size() - 1;

  for ( uint32_t i = 0; i < last_offset_index; ++i ) {
    pointer = Read<uintptr_t>( pointer + offsets[ i ] );

    if ( pointer == 0 ) {
      throw gwinmem::BadMemoryException(
          "ReadBytes read a null value, it is most likely you who read invalid "
          "memory. Address: " +
          std::to_string( address ) );
    }
  }

  return pointer + offsets.back();
}

using tLoadLibraryA = HINSTANCE( WINAPI* )( const char* lpLibFilename );
using tGetProcAddress = FARPROC( WINAPI* )( HINSTANCE hModule,
                                            LPCSTR lpProcName );
using tVirtualAlloc = LPVOID( WINAPI* )( LPVOID lpAddress,
                                         SIZE_T dwSize,
                                         DWORD flAllocationType,
                                         DWORD flProtect );
using tDllMain = BOOL( WINAPI* )( void* hDll, DWORD dwReason, void* pReserved );

struct MANUAL_MAPPING_DATA {
  tLoadLibraryA load_library;
  tGetProcAddress get_proc_address;
  uintptr_t dll_base_address;
};

// Required: Disable /JMC (JustMyCode)
// Disable the runtime_checks to prevent the compiler from adding random calls
// to check esp inside of the code.
#pragma optimize( "", off )
#pragma runtime_checks( "", off )

void LoadManualMappedDll( const MANUAL_MAPPING_DATA* mm_data ) {
  if ( !mm_data )
    return;

  const auto data = reinterpret_cast<uint8_t*>( mm_data->dll_base_address );

  const auto dos_headers = reinterpret_cast<const IMAGE_DOS_HEADER*>( data );

  const auto nt_headers =
      reinterpret_cast<const IMAGE_NT_HEADERS*>( data + dos_headers->e_lfanew );

  const auto& optional_header = nt_headers->OptionalHeader;

  const auto import_directory =
      nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];

  if ( import_directory.Size ) {
    const IMAGE_IMPORT_DESCRIPTOR* import_desc =
        reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            data + import_directory.VirtualAddress );

    // For each import descriptor
    for ( auto import_desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
              data + import_directory.VirtualAddress );
          import_desc->Name; ++import_desc ) {
      const auto dll_name =
          reinterpret_cast<const char*>( data + import_desc->Name );

      const HINSTANCE dll_instance = mm_data->load_library( dll_name );

      auto original_thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
          data + import_desc->OriginalFirstThunk );
      auto first_thunk =
          reinterpret_cast<IMAGE_THUNK_DATA*>( data + import_desc->FirstThunk );

      // For each import thunk
      for ( ; original_thunk->u1.AddressOfData;
            ++original_thunk, ++first_thunk ) {
        if ( IMAGE_SNAP_BY_ORDINAL( original_thunk->u1.Ordinal ) ) {
          *reinterpret_cast<uintptr_t*>( first_thunk ) =
              reinterpret_cast<uintptr_t>( mm_data->get_proc_address(
                  dll_instance, reinterpret_cast<char*>(
                                    original_thunk->u1.Ordinal & 0xFFFF ) ) );
        } else {
          const auto import = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
              data + original_thunk->u1.AddressOfData );
          *reinterpret_cast<uintptr_t*>( first_thunk ) =
              reinterpret_cast<uintptr_t>(
                  mm_data->get_proc_address( dll_instance, import->Name ) );
        }
      }
    }
  }

  const auto& tls_data_directory =
      optional_header.DataDirectory[ IMAGE_DIRECTORY_ENTRY_TLS ];

  if ( tls_data_directory.Size ) {
    const auto tls_directory = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(
        data + tls_data_directory.VirtualAddress );

    // Call the TLS callbacks
    for ( auto tls_callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(
              tls_directory->AddressOfCallBacks );
          tls_callbacks && *tls_callbacks; ++tls_callbacks )
      ( *tls_callbacks )( reinterpret_cast<PVOID>( mm_data->dll_base_address ),
                          DLL_PROCESS_ATTACH, nullptr );
  }

  using DllMain_t =
      BOOL( WINAPI* )( HINSTANCE instance, DWORD reason, LPVOID reserved );

  const auto dll_main =
      reinterpret_cast<DllMain_t>( data + optional_header.AddressOfEntryPoint );

  if ( optional_header.AddressOfEntryPoint )
    dll_main( reinterpret_cast<HINSTANCE>( mm_data->dll_base_address ),
              DLL_PROCESS_ATTACH, reinterpret_cast<LPVOID>( 1 ) );
}

#pragma runtime_checks( "", restore )
#pragma optimize( "", on )

uintptr_t gwinmem::ProcessMemory::ManualMapper::ManualMapDll(
    const std::wstring& name,
    const std::vector<uint8_t>& dll_data,
    ProcessMemory& process_memory ) {
  if ( dll_data.empty() )
    return 0;

  uint8_t* data = const_cast<uint8_t*>( &dll_data[ 0 ] );

  const auto nt_headers = peutils::GetNtHeaders( data );

  // Is it a valid PE?
  if ( !nt_headers )
    return 0;

  // TODO: Read the ntheaders of the target process and compare them to the dll we are about to manual map
  // We need to make sure they are of the same bitness

  const uintptr_t alloc_address = process_memory.Allocate(
      0, nt_headers->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE,
      PAGE_EXECUTE_READWRITE );

  if ( !alloc_address )
    return 0;

  // Add the dll to the locally mapped dll's
  mapped_dlls_[ name ] = alloc_address;

  // Relocate the image
  RelocateImage( nt_headers, alloc_address, data );

  // Fixing the imports directly on the binary causes some DLL to crash
  // without any explanation. I have do not know the reason either and I have
  // tried to fix it. After some debugging, it seemed as if there were more
  // imports when doing it from the memory itself.
  // TODO: Fix sometime in the future.
  // FixImportTable( nt_headers, data, process_memory );

  // Write the header to the allocated address
  process_memory.WriteBytes( alloc_address,
                             nt_headers->OptionalHeader.SizeOfHeaders, data );

  // Write each section to their location
  for ( uint16_t i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i ) {
    const auto section = &IMAGE_FIRST_SECTION( nt_headers )[ i ];
    process_memory.WriteBytes( alloc_address + section->VirtualAddress,
                               section->SizeOfRawData,
                               data + section->PointerToRawData );
  }

  // Flush the whole allocated memory
  FlushInstructionCache( process_memory.process_handle_.GetValue(),
                         reinterpret_cast<LPCVOID>( alloc_address ),
                         nt_headers->OptionalHeader.SizeOfImage );

  MANUAL_MAPPING_DATA mm_data;
  mm_data.dll_base_address = alloc_address;
  mm_data.get_proc_address = GetProcAddress;
  mm_data.load_library = LoadLibraryA;

  // Allocate memory that is big enough for the dll base address
  const auto dll_base_address_addr =
      process_memory.Allocate( sizeof( mm_data ) );

  // Write the dll base address to allocated memory region
  process_memory.Write( dll_base_address_addr, mm_data );

  constexpr uint32_t kPageSize = 0x1000;

  // Allocate memory for the shellcode that will call the mapped DLL's dllmain
  const auto mapped_dll_loader_address = process_memory.Allocate( kPageSize );

  // Get the address of the mapped dll loader function
  // LoadManualMappedDll

  uintptr_t dll_loader_function_address =
      reinterpret_cast<uintptr_t>( LoadManualMappedDll );

  // If the function is a redirection function (usually in Debug Mode with
  // VS), get the relative jump address
  if ( *reinterpret_cast<uint8_t*>( LoadManualMappedDll ) == 0xE9 ) {
    // TODO: Support x64...
    const auto relative_addr =
        *reinterpret_cast<uintptr_t*>( dll_loader_function_address + 1 );

    dll_loader_function_address =
        dll_loader_function_address + relative_addr + 5;
  }

  // Write the loader shellcode to the allocated location
  process_memory.WriteBytes(
      mapped_dll_loader_address, kPageSize,
      reinterpret_cast<const uint8_t*>( dll_loader_function_address ) );

  // Flush the whole allocated loader shellcode memory
  FlushInstructionCache( process_memory.process_handle_.GetValue(),
                         reinterpret_cast<LPCVOID>( mapped_dll_loader_address ),
                         kPageSize );

  // Call the loader shellcode
  const SafeHandle loader_thread_handle = CreateRemoteThread(
      process_memory.process_handle_.GetValue(), 0, 0,
      reinterpret_cast<LPTHREAD_START_ROUTINE>( mapped_dll_loader_address ),
      reinterpret_cast<LPVOID>( dll_base_address_addr ), 0, 0 );

  if ( !loader_thread_handle.GetValue() )
    return 0;

  WaitForSingleObject( loader_thread_handle.GetValue(), INFINITE );

  // Free all the memory
  VirtualFreeEx( process_memory.process_handle_.GetValue(),
                 reinterpret_cast<LPVOID>( mapped_dll_loader_address ), 0,
                 MEM_RELEASE );

  VirtualFreeEx( process_memory.process_handle_.GetValue(),
                 reinterpret_cast<LPVOID>( dll_base_address_addr ), 0,
                 MEM_RELEASE );

  return alloc_address;
}

void gwinmem::ProcessMemory::ManualMapper::RelocateImage(
    const IMAGE_NT_HEADERS* nt_headers,
    const uintptr_t delta,
    uint8_t* data ) {
  const IMAGE_DATA_DIRECTORY& reloc_directory =
      nt_headers->OptionalHeader
          .DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];

  IMAGE_BASE_RELOCATION* reloc_block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
      data + RvaToFileOffset( nt_headers, reloc_directory.VirtualAddress ) );

  DWORD relocation_size_read = 0;

  // TODO: Consider converting this to a for loop due to the reloc_block_offset
  // usage
  while ( relocation_size_read < reloc_directory.Size ) {
    DWORD reloc_list_count =
        ( reloc_block->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) /
        sizeof( WORD );

    WORD* reloc_list =
        reinterpret_cast<WORD*>( reinterpret_cast<size_t>( reloc_block ) +
                                 sizeof( IMAGE_BASE_RELOCATION ) );

    for ( size_t i = 0; i < reloc_list_count; ++i ) {
      // Mask out the type and assign
      const WORD type = reloc_list[ i ] >> 12;

      // Mask out the offset and assign
      const WORD offset = reloc_list[ i ] & 0xfff;

      const uintptr_t rva = offset + reloc_block->VirtualAddress;

      const uintptr_t file_offset = RvaToFileOffset( nt_headers, rva );

      if ( type == IMAGE_REL_BASED_ABSOLUTE ) {
        continue;
      } else if ( type == IMAGE_REL_BASED_HIGHLOW ) {
        *( DWORD* )( data + file_offset ) +=
            ( DWORD )delta - nt_headers->OptionalHeader.ImageBase;
      }
    }

    relocation_size_read += reloc_block->SizeOfBlock;

    reloc_block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
        reinterpret_cast<size_t>( reloc_block ) + reloc_block->SizeOfBlock );
  }
}

void gwinmem::ProcessMemory::ManualMapper::FixImportTable(
    const IMAGE_NT_HEADERS* nt_headers,
    uint8_t* data,
    ProcessMemory& process_memory ) {
  const auto string_to_wide = []( const std::string s ) -> std::wstring {
    return std::wstring( s.begin(), s.end() );
  };

  const auto import_directory =
      nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];

  const IMAGE_IMPORT_DESCRIPTOR* import_desc =
      reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
          data +
          RvaToFileOffset( nt_headers, import_directory.VirtualAddress ) );

  // For each import descriptor
  for ( auto import_desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            data +
            RvaToFileOffset( nt_headers, import_directory.VirtualAddress ) );
        import_desc->Name; ++import_desc ) {
    const std::string dll_name_lower =
        stringutils::StringToLower( reinterpret_cast<const char*>(
            data + RvaToFileOffset( nt_headers, import_desc->Name ) ) );

    auto original_thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
        data + RvaToFileOffset( nt_headers, import_desc->OriginalFirstThunk ) );
    auto first_thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
        data + RvaToFileOffset( nt_headers, import_desc->FirstThunk ) );

    // For each import thunk
    for ( ; original_thunk->u1.AddressOfData;
          ++original_thunk, ++first_thunk ) {
      assert( original_thunk );

      if ( IMAGE_SNAP_BY_ORDINAL( original_thunk->u1.Ordinal ) ) {
        assert( false && "Handle ordinal" );
      } else {
        // Read the import info in that thunk
        const auto import = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
            data +
            RvaToFileOffset( nt_headers, original_thunk->u1.AddressOfData ) );

        // TODO: When supporting the idea to manual map all the dependant dll's,
        // try out the api set schema method with ApiSetResolveToHost TypeDef:
        // https://github.com/DarthTon/Blackbone/blob/master/src/BlackBoneDrv/apiset.h#L237
        // Get ApiSetResolveToHost dynamically with pdbparse:
        // https://www.unknowncheats.me/forum/c-and-c-/248123-pdbparse.html

        const auto dll_name_lower_wide =
            std::wstring( dll_name_lower.begin(), dll_name_lower.end() );

        const auto mapped_dependency = mapped_dlls_.find( dll_name_lower_wide );
        const auto module = process_memory.GetModule( dll_name_lower_wide );

        uintptr_t module_addr = 0;

        // If the dependency has not been mapped earlier
        // and if the dependency is not already loaded in the pe
        if ( mapped_dependency == mapped_dlls_.end() && !module.base ) {
          std::wstring dll_path = GetSystemDllPath( dll_name_lower_wide );
          module_addr = process_memory.RemoteLoadLibrary( dll_path );
        } else if ( mapped_dependency != mapped_dlls_.end() ) {
          module_addr = mapped_dependency->second;
        } else if ( module.base ) {
          module_addr = module.base;
        }

        assert( module_addr );

        // Issue: The dependency DLL might be loaded on different addresses in
        // this and the target process. Therefore we cannot use normal
        // getprocaddress.
        // Solution: Get the offset of the function and add it to the base
        // address of the targets dependency base address.

        uintptr_t local_module = reinterpret_cast<uintptr_t>(
            GetModuleHandle( dll_name_lower_wide.c_str() ) );

        if ( !local_module )
          local_module = reinterpret_cast<uintptr_t>(
              LoadLibrary( dll_name_lower_wide.c_str() ) );

        const uintptr_t local_func_addr =
            reinterpret_cast<uintptr_t>( GetProcAddress(
                reinterpret_cast<HMODULE>( local_module ), import->Name ) );

        const uintptr_t target_function_address =
            ( local_func_addr - local_module ) + module_addr;

        assert( target_function_address );

        std::string info = std::string( "DLL: " ) + dll_name_lower +
                           std::string( "Name: " ) +
                           std::string( import->Name );

        /*
        std::wstring ansi = stringutils::StringToWide(
            std::string( "dick: " ) + info + " " +
            std::to_string( target_function_address ) + "\n" );

        OutputDebugString( ansi.c_str() );
        */

        // The loader has the responsibility to modify the first thunk with the
        // correct addresses, that is what we do here.
        *reinterpret_cast<uintptr_t*>( first_thunk ) = target_function_address;
      }
    }
  }
}

IMAGE_SECTION_HEADER* gwinmem::ProcessMemory::ManualMapper::GetSectionFromRva(
    const IMAGE_NT_HEADERS* nt_headers,
    const uintptr_t rva ) {
  for ( uint16_t i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i ) {
    const auto section = &IMAGE_FIRST_SECTION( nt_headers )[ i ];
    if ( rva >= section->VirtualAddress &&
         rva < section->VirtualAddress + section->Misc.VirtualSize ) {
      return section;
    }
  }

  return nullptr;
}

uintptr_t gwinmem::ProcessMemory::ManualMapper::RvaToFileOffset(
    const IMAGE_NT_HEADERS* nt_headers,
    const uintptr_t rva ) {
  const auto section = GetSectionFromRva( nt_headers, rva );

  if ( !section )
    return 0;

  return section->PointerToRawData + ( rva - section->VirtualAddress );
}

std::wstring gwinmem::ProcessMemory::ManualMapper::GetSystemDllPath(
    const std::wstring& dll_name ) {
  auto wide_to_lower = []( const std::wstring& s ) -> std::wstring {
    std::wstring new_s;

    // Make the dll name lower case
    for ( auto c : s )
      new_s += towlower( c );

    return new_s;
  };

  const std::wstring dll_name_lower = wide_to_lower( dll_name );

  // TODO: Consider using std::string_view to avoid all these unnessecary
  // allocations

  std::wstring system_dir( MAX_PATH, '\0' );
  GetSystemDirectory( &system_dir[ 0 ], MAX_PATH );
  system_dir.resize( wcslen( system_dir.c_str() ) );

  WIN32_FIND_DATA find_data;
  const SafeFindHandle file_handle =
      FindFirstFile( ( system_dir + TEXT( "\\*" ) ).c_str(), &find_data );

  std::wstring dll_path{ 0 };
  dll_path.reserve( MAX_PATH );

  do {
    std::wstring file_lower;
    file_lower = wide_to_lower( find_data.cFileName );

    if ( file_lower == dll_name_lower ) {
      dll_path = system_dir;
      dll_path += TEXT( "\\" ) + dll_name_lower;
      break;
    }

  } while ( FindNextFile( file_handle.GetValue(), &find_data ) );

  return dll_path;
}
