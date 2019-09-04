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

}  // namespace stringutils

}  // namespace gwinmem