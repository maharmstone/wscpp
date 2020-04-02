cmake_minimum_required(VERSION 3.14.0)

include(GNUInstallDirs)

project(wscpp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_definitions(WSCPP_EXPORT)

set(SRC_FILES wsclient.cpp
	wsserver.cpp
	b64.cpp
	sha1.cpp)

add_library(wscpp SHARED ${SRC_FILES})

if(WIN32)
target_link_libraries(wscpp wsock32 ws2_32)
else()
target_link_libraries(wscpp pthread)
endif()

target_compile_options(wscpp PRIVATE
	$<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:
		-Wall>
	$<$<CXX_COMPILER_ID:MSVC>:
		/W4>)

install(TARGETS wscpp DESTINATION "${CMAKE_INSTALL_FULL_LIBDIR}")
install(FILES wscpp.h DESTINATION "${CMAKE_INSTALL_FULL_INCLUDEDIR}")

