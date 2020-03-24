#pragma once

#include <algorithm>
#include <string>

namespace gwinmem {

namespace stringutils {

// make wide to lower, and use int GetModule

inline std::wstring WideStringToLower( const std::wstring& str ) {
  std::wstring strcopy;
  strcopy.resize( str.size() );
  std::transform( str.begin(), str.end(), strcopy.begin(),
                  []( wchar_t c ) { return towlower( c ); } );
  return strcopy;
}

inline std::string StringToLower( const std::string& str ) {
  std::string strcopy;
  strcopy.resize( str.size() );
  std::transform( str.begin(), str.end(), strcopy.begin(),
                  []( char c ) { return tolower( c ); } );
  return strcopy;
}

inline std::string GuidToString( const GUID& guid ) {
  char guid_string[ 37 ] = { 0 };

  snprintf( guid_string, sizeof( guid_string ),
            "%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x", guid.Data1,
            guid.Data2, guid.Data3, guid.Data4[ 0 ], guid.Data4[ 1 ],
            guid.Data4[ 2 ], guid.Data4[ 3 ], guid.Data4[ 4 ], guid.Data4[ 5 ],
            guid.Data4[ 6 ], guid.Data4[ 7 ] );

  return guid_string;
}

}  // namespace stringutils

}  // namespace gwinmem