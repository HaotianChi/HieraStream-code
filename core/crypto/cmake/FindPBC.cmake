# Homebrew PBC often ships without pbc.pc — provide a CMake finder.
# Portable across macOS (Homebrew) and Ubuntu (/usr, /usr/local).

set(_PBC_HINTS
  ${PBC_ROOT}
  $ENV{PBC_ROOT}
  /opt/homebrew/opt/pbc
  /usr/local
  /usr
)

find_path(PBC_INCLUDE_DIR
  NAMES pbc/pbc.h pbc.h
  HINTS ${_PBC_HINTS}
  PATH_SUFFIXES include
)

find_library(PBC_LIBRARY
  NAMES pbc
  HINTS ${_PBC_HINTS}
  PATH_SUFFIXES lib lib64
)

find_path(GMP_INCLUDE_DIR
  NAMES gmp.h
  HINTS /opt/homebrew/opt/gmp /usr/local /usr
  PATH_SUFFIXES include
)

find_library(GMP_LIBRARY
  NAMES gmp
  HINTS /opt/homebrew/opt/gmp /usr/local /usr
  PATH_SUFFIXES lib lib64
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PBC DEFAULT_MSG PBC_LIBRARY PBC_INCLUDE_DIR GMP_LIBRARY GMP_INCLUDE_DIR)

if(PBC_FOUND AND NOT TARGET PBC::PBC)
  add_library(PBC::PBC UNKNOWN IMPORTED)
  set_target_properties(PBC::PBC PROPERTIES
    IMPORTED_LOCATION "${PBC_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${PBC_INCLUDE_DIR};${GMP_INCLUDE_DIR}"
    INTERFACE_LINK_LIBRARIES "${GMP_LIBRARY}"
  )
endif()

mark_as_advanced(PBC_INCLUDE_DIR PBC_LIBRARY GMP_INCLUDE_DIR GMP_LIBRARY)
