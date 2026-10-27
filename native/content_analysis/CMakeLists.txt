cmake_minimum_required(VERSION 3.22)

project(transpect_content_analysis_agent LANGUAGES CXX)

option(TTRACE_BUILD_SDK_TEST_CLIENT
  "Build the controlled upstream-SDK protocol client" OFF)

if(NOT WIN32)
  message(FATAL_ERROR "The Content Analysis Agent is Windows-only")
endif()

set(CONTENT_ANALYSIS_SDK_ROOT "" CACHE PATH
    "Path to chromium/content_analysis_sdk at the pinned commit")
if(NOT CONTENT_ANALYSIS_SDK_ROOT)
  message(FATAL_ERROR "CONTENT_ANALYSIS_SDK_ROOT is required")
endif()
get_filename_component(CONTENT_ANALYSIS_SDK_ROOT
  "${CONTENT_ANALYSIS_SDK_ROOT}" ABSOLUTE)

set(SDK_PROTO
  "${CONTENT_ANALYSIS_SDK_ROOT}/proto/content_analysis/sdk/analysis.proto")
set(SDK_AGENT_HEADER
  "${CONTENT_ANALYSIS_SDK_ROOT}/agent/include/content_analysis/sdk/analysis_agent.h")
if(NOT EXISTS "${SDK_PROTO}" OR NOT EXISTS "${SDK_AGENT_HEADER}")
  message(FATAL_ERROR "CONTENT_ANALYSIS_SDK_ROOT is not a compatible SDK checkout")
endif()

find_package(Protobuf CONFIG REQUIRED)

set(GENERATED_ROOT "${CMAKE_CURRENT_BINARY_DIR}/gen")
set(GENERATED_CC "${GENERATED_ROOT}/content_analysis/sdk/analysis.pb.cc")
set(GENERATED_H "${GENERATED_ROOT}/content_analysis/sdk/analysis.pb.h")
add_custom_command(
  OUTPUT "${GENERATED_CC}" "${GENERATED_H}"
  COMMAND ${CMAKE_COMMAND} -E make_directory
          "${GENERATED_ROOT}/content_analysis/sdk"
  COMMAND protobuf::protoc
          --cpp_out=${GENERATED_ROOT}
          --proto_path=${CONTENT_ANALYSIS_SDK_ROOT}/proto
          "${SDK_PROTO}"
  DEPENDS "${SDK_PROTO}"
  VERBATIM)

add_library(transpect_cac_agent STATIC
  "${CONTENT_ANALYSIS_SDK_ROOT}/agent/src/agent_base.cc"
  "${CONTENT_ANALYSIS_SDK_ROOT}/agent/src/event_base.cc"
  "${CONTENT_ANALYSIS_SDK_ROOT}/agent/src/scoped_print_handle_base.cc"
  "${CONTENT_ANALYSIS_SDK_ROOT}/agent/src/agent_utils_win.cc"
  "${CONTENT_ANALYSIS_SDK_ROOT}/agent/src/agent_win.cc"
  "${CONTENT_ANALYSIS_SDK_ROOT}/agent/src/event_win.cc"
  "${CONTENT_ANALYSIS_SDK_ROOT}/agent/src/scoped_print_handle_win.cc"
  "${CONTENT_ANALYSIS_SDK_ROOT}/common/utils_win.cc"
  "${GENERATED_CC}")
target_compile_features(transpect_cac_agent PUBLIC cxx_std_17)
target_include_directories(transpect_cac_agent
  SYSTEM PUBLIC
    "${CONTENT_ANALYSIS_SDK_ROOT}/agent/include"
    "${GENERATED_ROOT}"
)
target_include_directories(transpect_cac_agent
  PRIVATE
    "${CONTENT_ANALYSIS_SDK_ROOT}")
target_link_libraries(transpect_cac_agent
  PUBLIC protobuf::libprotobuf
  PRIVATE Advapi32)

add_executable(ttrace-content-agent agent.cc)
target_compile_features(ttrace-content-agent PRIVATE cxx_std_17)
target_compile_definitions(ttrace-content-agent PRIVATE
  UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_include_directories(ttrace-content-agent SYSTEM PRIVATE
  "${CMAKE_CURRENT_LIST_DIR}/../guard/third_party/jsmn")
target_link_libraries(ttrace-content-agent PRIVATE
  transpect_cac_agent Bcrypt Winhttp)

if(MSVC)
  target_compile_options(ttrace-content-agent PRIVATE /W4 /WX /permissive-)
  target_compile_options(transpect_cac_agent PRIVATE /W3)
endif()

if(TTRACE_BUILD_SDK_TEST_CLIENT)
  add_library(transpect_cac_browser STATIC
    "${CONTENT_ANALYSIS_SDK_ROOT}/browser/src/client_base.cc"
    "${CONTENT_ANALYSIS_SDK_ROOT}/browser/src/client_win.cc"
    "${CONTENT_ANALYSIS_SDK_ROOT}/common/utils_win.cc"
    "${GENERATED_CC}")
  target_compile_features(transpect_cac_browser PUBLIC cxx_std_17)
  target_include_directories(transpect_cac_browser
    SYSTEM PUBLIC
      "${CONTENT_ANALYSIS_SDK_ROOT}/browser/include"
      "${GENERATED_ROOT}")
  target_include_directories(transpect_cac_browser PRIVATE
    "${CONTENT_ANALYSIS_SDK_ROOT}")
  target_link_libraries(transpect_cac_browser
    PUBLIC protobuf::libprotobuf
    PRIVATE Advapi32)

  add_executable(ttrace-content-sdk-client sdk_test_client.cc)
  target_compile_features(ttrace-content-sdk-client PRIVATE cxx_std_17)
  target_compile_definitions(ttrace-content-sdk-client PRIVATE
    WIN32_LEAN_AND_MEAN NOMINMAX)
  target_link_libraries(ttrace-content-sdk-client PRIVATE
    transpect_cac_browser)
  if(MSVC)
    target_compile_options(transpect_cac_browser PRIVATE /W3)
    target_compile_options(ttrace-content-sdk-client PRIVATE /W4 /WX /permissive-)
  endif()
endif()
