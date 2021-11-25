cmake_minimum_required (VERSION 3.15)
project (test_libssh2)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)


set(Boost_USE_STATIC_LIBS   ON)
set(BOOST_LIBS system filesystem unit_test_framework log)
find_package(Boost COMPONENTS ${BOOST_LIBS} REQUIRED)
find_package(Threads)
CHECK_INCLUDE_FILE(unistd.h HAVE_UNISTD)
include(CheckSymbolExists)
check_symbol_exists(mkstemp stdlib.h HAVE_MKSTEMP)

add_executable(Tests main.cpp ssh.cpp utils.cpp test.hpp)
target_include_directories(Tests PUBLIC src "${Boost_INCLUDE_DIRS}")
target_include_directories(Tests PRIVATE src "${PROJECT_BINARY_DIR}")
target_link_libraries(Tests PUBLIC
  ${Boost_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
  )

find_package(PkgConfig REQUIRED)
pkg_check_modules(Libssh2 libssh2 REQUIRED)
target_link_libraries(Tests PRIVATE ${Libssh2_LIBRARIES})
configure_file(test.hpp.in test.hpp)
