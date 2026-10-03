cmake_minimum_required(VERSION 3.24)
project(wsrv VERSION 1.0.0 LANGUAGES C CXX RC)

if(NOT MSVC)
  message(FATAL_ERROR "wsrv builds with MSVC for Windows x64.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Static CRT: wsrv.exe depends on Windows system DLLs only.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# ---- SQLite (vendored amalgamation, compiled as C) ----
add_library(sqlite3 STATIC third_party/sqlite/sqlite3.c)
target_compile_definitions(sqlite3 PRIVATE
  SQLITE_THREADSAFE=1
  SQLITE_DQS=0
  SQLITE_DEFAULT_MEMSTATUS=0
  SQLITE_OMIT_LOAD_EXTENSION
  SQLITE_OMIT_DEPRECATED
  SQLITE_OMIT_SHARED_CACHE
  SQLITE_OMIT_PROGRESS_CALLBACK
  SQLITE_DEFAULT_FOREIGN_KEYS=1
  SQLITE_WIN32_MALLOC)
target_compile_options(sqlite3 PRIVATE /W0 /O2)

# ---- Event Log message table ----
find_program(MC_EXE mc HINTS "${CMAKE_RC_COMPILER}/..")
if(NOT MC_EXE)
  get_filename_component(RC_DIR "${CMAKE_RC_COMPILER}" DIRECTORY)
  find_program(MC_EXE mc HINTS "${RC_DIR}" REQUIRED)
endif()
set(GEN_DIR "${CMAKE_CURRENT_BINARY_DIR}/gen")
add_custom_command(
  OUTPUT "${GEN_DIR}/messages.h" "${GEN_DIR}/messages.rc"
  COMMAND ${CMAKE_COMMAND} -E make_directory "${GEN_DIR}"
  COMMAND "${MC_EXE}" -h "${GEN_DIR}" -r "${GEN_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/src/messages.mc"
  DEPENDS src/messages.mc
  COMMENT "Compiling Event Log message table")

# ---- Core library (shared by the server and the tests) ----
set(CORE_SOURCES
  src/util.cpp src/log.cpp src/json.cpp src/http_util.cpp src/path_guard.cpp
  src/config_store.cpp src/certs.cpp src/hosts_file.cpp src/httpsys.cpp
  src/reconciler.cpp src/handlers.cpp src/admin.cpp src/pipe.cpp src/server.cpp src/service.cpp
  "${GEN_DIR}/messages.h")
add_library(wsrvcore STATIC ${CORE_SOURCES})
target_include_directories(wsrvcore PUBLIC src "${GEN_DIR}")
target_compile_definitions(wsrvcore PUBLIC UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
target_compile_options(wsrvcore PUBLIC /W4 /permissive- /utf-8 /guard:cf /Qspectre /sdl /GS /EHsc /Zc:__cplusplus
  $<$<CONFIG:Release>:/O1 /Gy /Gw /GL>)
target_link_libraries(wsrvcore PUBLIC sqlite3 httpapi crypt32 ncrypt bcrypt advapi32 shell32 ole32 user32)

set(HARDENED_LINK /guard:cf /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /CETCOMPAT
  $<$<CONFIG:Release>:/LTCG /OPT:REF /OPT:ICF /INCREMENTAL:NO>)

# ---- wsrv.exe ----
add_executable(wsrv src/main.cpp src/wsrv.rc)
set_source_files_properties(src/wsrv.rc PROPERTIES OBJECT_DEPENDS
  "${GEN_DIR}/messages.rc;${CMAKE_CURRENT_SOURCE_DIR}/admin-ui/index.html;${CMAKE_CURRENT_SOURCE_DIR}/admin-ui/app.js;${CMAKE_CURRENT_SOURCE_DIR}/admin-ui/app.css;${CMAKE_CURRENT_SOURCE_DIR}/admin-ui/favicon.svg;${CMAKE_CURRENT_SOURCE_DIR}/src/wsrv.manifest")
target_link_libraries(wsrv PRIVATE wsrvcore)
target_link_options(wsrv PRIVATE ${HARDENED_LINK} /MANIFEST:NO)

# ---- Tests ----
add_executable(wsrv_tests tests/tests.cpp src/wsrv.rc)  # same embedded admin UI as wsrv.exe
set_source_files_properties(src/wsrv.rc TARGET_DIRECTORY wsrv_tests PROPERTIES OBJECT_DEPENDS "${GEN_DIR}/messages.rc")
target_link_libraries(wsrv_tests PRIVATE wsrvcore ws2_32)  # raw-socket client, tests only
target_link_options(wsrv_tests PRIVATE ${HARDENED_LINK} /MANIFEST:NO)
enable_testing()
add_test(NAME unit COMMAND wsrv_tests)
