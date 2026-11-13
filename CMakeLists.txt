cmake_minimum_required(VERSION 3.16)
project(flipper_persistent_security VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(ps_security STATIC
    src/ps_crypto.c
    src/ps_security.c
)
target_include_directories(ps_security PUBLIC include PRIVATE src)

if(MSVC)
    target_compile_options(ps_security PRIVATE /W4 /WX)
else()
    target_compile_options(ps_security PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

add_executable(ps_security_tests
    tests/test_security.c
    tests/pc_store.c
)
target_include_directories(ps_security_tests PRIVATE tests src)
target_link_libraries(ps_security_tests PRIVATE ps_security)

if(MSVC)
    target_compile_options(ps_security_tests PRIVATE /W4 /WX)
else()
    target_compile_options(ps_security_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

enable_testing()
add_test(NAME ps_security_tests COMMAND ps_security_tests)
