#pragma once

#include <Windows.h>
#include <functional>
#include <memory>

namespace gwinmem {

template <typename T, typename freeType>
using SafeObjectPtr =
    std::shared_ptr<typename std::remove_pointer<T>::type>;  // Shared Pointer

template <typename HandleType>
using SafeObject = SafeObjectPtr<HandleType, std::function<void( HandleType )>>;

template <typename T>
class __SafeHandleImplementation {
 public:
  using HandleType = typename T::HandleType;

  __SafeHandleImplementation() {}

  __SafeHandleImplementation( HandleType object ) {
    std::function<void( HandleType )> m_deleter = []( HandleType object ) {
      T::CleanUp( object );
    };

    // TODO: Consider opitmizing this to simply: object_( object, m_deleter );
    SafeObject<HandleType> pObject( object, m_deleter );
    object_ = std::move( pObject );
  }

  inline HandleType GetValue() const {
    return object_.get();
  }

 private:
  SafeObject<HandleType> object_;
};

template <typename T>
class __SafeCloseHandle {
 public:
  using HandleType = T;

  static void CleanUp( HandleType object ) {
    CloseHandle( object );
  }
};

template <typename T>
class __SafeFindClose {
 public:
  using HandleType = T;

  static void CleanUp( HandleType object ) {
    FindClose( object );
  }
};

using SafeHandle = __SafeHandleImplementation<__SafeCloseHandle<HANDLE>>;
using SafeFindHandle = __SafeHandleImplementation<__SafeFindClose<HANDLE>>;

}  // namespace gwinmem