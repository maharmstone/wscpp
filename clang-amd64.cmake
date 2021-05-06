set(CMAKE_SYSTEM_NAME Linux)

set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_RC_COMPILER llvm-rc)

set(CLANG_TARGET_TRIPLE x86_64-pc-linux-gnu)
set(CMAKE_C_COMPILER_TARGET x86_64-pc-linux-gnu)
set(CMAKE_CXX_COMPILER_TARGET x86_64-pc-linux-gnu)
set(CMAKE_ASM_COMPILER_TARGET x86_64-pc-linux-gnu)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

set(CMAKE_SYSTEM_PROCESSOR x86_64)