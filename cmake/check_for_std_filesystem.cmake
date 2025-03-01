add_library(filesystem INTERFACE)

set(filesystem_code [[
#include <filesystem>

int main() {
  auto cwd = std::filesystem::current_path();
  return !cwd.string().empty();
}
]])

if (CMAKE_CXX_COMPILER STREQUAL "AppleClang" AND CMAKE_OSX_DEPLOYMENT_TARGET)
  set(CMAKE_REQUIRED_FLAGS -mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET})
endif()

include(CheckCXXSourceCompiles)
check_cxx_source_compiles("${filesystem_code}" filesystem_compiled)
if (filesystem_compiled)
  message(STATUS "No extra link flag needed for std::filesystem")
  set(filesystem_is_good ON)
else()
  foreach(fslib stdc++fs c++fs)
    set(CMAKE_REQUIRED_LIBRARIES -l${fslib})
    check_cxx_source_compiles("${filesystem_code}" filesystem_compiled_${fslib})
    if (filesystem_compiled_${fslib})
      message(STATUS "Using -l${fslib} for std::filesystem support")
      target_link_libraries(filesystem INTERFACE ${fslib})
      set(filesyetem_is_good ON)
      break()
    endif()
  endforeach()
endif()
unset(CMAKE_REQUIRED_LIBRARIES)
if (NOT filesystem_is_good)
  message(FATAL_ERROR "std::filesystem is not available, apparently this compiler isn't C++17 compliant")
endif()