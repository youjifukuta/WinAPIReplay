cmake_minimum_required(VERSION 3.20)
project(WinAPIReplay CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_definitions(UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)

if(MSVC)
    add_compile_options(/utf-8 /W3)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# ── ① WinAPISample (動作検証サンプル) ─────────────────────────────────────
add_executable(WinAPISample
    src/sample/main.cpp
    src/sample/scenarios/file_ops.cpp
    src/sample/scenarios/registry_ops.cpp
    src/sample/scenarios/network_ops.cpp
    src/sample/scenarios/process_ops.cpp
)
target_include_directories(WinAPISample PRIVATE include)
target_link_libraries(WinAPISample PRIVATE Ws2_32 Advapi32)

# ── ⑤ WinAPIReplay (動作再現ツール) ───────────────────────────────────────
set(REPLAY_SOURCES
    # core
    src/replay/nt_native.cpp
    src/replay/log_parser.cpp
    src/replay/handle_map.cpp
    src/replay/pointer_map.cpp
    src/replay/pid_map.cpp
    src/replay/path_sandbox.cpp
    src/replay/registry_sandbox.cpp
    src/replay/net_simulator.cpp
    src/replay/arg_preparer.cpp
    src/replay/api_executor.cpp
    src/replay/generic_dispatcher.cpp
    src/replay/thread_manager.cpp
    src/replay/result_writer.cpp
    # executors
    src/replay/executors/file_executor.cpp
    src/replay/executors/nt_file_executor.cpp
    src/replay/executors/registry_executor.cpp
    src/replay/executors/network_executor.cpp
    src/replay/executors/process_executor.cpp
    src/replay/executors/dll_executor.cpp
    src/replay/executors/sync_executor.cpp
    src/replay/executors/crypto_executor.cpp
    src/replay/executors/service_executor.cpp
    src/replay/executors/shell_executor.cpp
    src/replay/executors/hook_executor.cpp
    src/replay/executors/token_executor.cpp
    src/replay/executors/system_executor.cpp
    src/replay/executors/nt_registry_executor.cpp
    src/replay/executors/nt_memory_executor.cpp
    src/replay/executors/nt_sync_executor.cpp
    src/replay/executors/nt_misc_executor.cpp
    src/replay/executors/ldr_executor.cpp
)

add_executable(WinAPIReplay
    src/replay/main.cpp
    ${REPLAY_SOURCES}
)
target_include_directories(WinAPIReplay PRIVATE include external)
target_link_libraries(WinAPIReplay PRIVATE
    Ws2_32       # Winsock
    Wininet      # WinINet
    Advapi32     # registry, crypto, services, token, LSA
    Shell32      # ShellExecuteW/A, ShellExecuteExW/A
    Shlwapi      # PathCombineW, PathCanonicalizeW etc.
    Pathcch      # PathCchCombineEx
    Ole32        # CoCreateInstance, CoInitializeEx
    Psapi        # EnumProcessModules (GenericDispatcher)
    # Ntdll: NOT linked — NtUnmapViewOfSection is loaded via GetProcAddress at runtime
)

# ── Google Test unit tests ─────────────────────────────────────────────────
set(gtest_force_shared_crt OFF CACHE BOOL "" FORCE)
set(BUILD_GMOCK   OFF CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
add_subdirectory(external/googletest)

enable_testing()

add_executable(WinAPIReplayTests
    tests/test_log_parser.cpp
    tests/test_arg_preparer.cpp
    tests/test_path_sandbox.cpp
    tests/test_registry_sandbox.cpp
    tests/test_nt_api_load.cpp
    # Nt* executors
    tests/test_nt_file_executor.cpp
    tests/test_nt_registry_executor.cpp
    tests/test_nt_sync_executor.cpp
    tests/test_nt_memory_executor.cpp
    tests/test_nt_misc_executor.cpp
    tests/test_ldr_executor.cpp
    # Win32 executors
    tests/test_file_executor.cpp
    tests/test_registry_executor.cpp
    tests/test_sync_executor.cpp
    tests/test_dll_executor.cpp
    tests/test_network_executor.cpp
    tests/test_process_executor.cpp
    tests/test_crypto_executor.cpp
    tests/test_service_executor.cpp
    tests/test_system_executor.cpp
    tests/test_shell_executor.cpp
    tests/test_token_executor.cpp
    tests/test_hook_executor.cpp
    # Handle chain integration tests (chain correctness across API categories)
    tests/test_handle_chains.cpp
    # Layer 1/2 routing (handles APIs outside the 104 Layer-1 types)
    tests/test_api_executor_routing.cpp
    # SandboxTransform serialization
    tests/test_result_writer.cpp
    ${REPLAY_SOURCES}
)
target_include_directories(WinAPIReplayTests PRIVATE include external)
target_link_libraries(WinAPIReplayTests PRIVATE
    GTest::gtest_main
    Ws2_32 Wininet Advapi32 Shell32 Psapi Shlwapi Pathcch Ole32
)
include(GoogleTest)
gtest_discover_tests(WinAPIReplayTests WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

# ビルド: cmake -B build -A x64 && cmake --build build --config Release
# テスト: cmake --build build --config Release --target WinAPIReplayTests && ctest -C Release
