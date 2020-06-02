cmake_minimum_required(VERSION 3.10)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

project(wscpp)

option(BUILD_SAMPLE "Build sample program" ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

add_definitions(-DWSCPP_EXPORT)

set(SRC_FILES wsclient.cpp
	wsserver.cpp
	b64.cpp
	sha1.cpp
	wsexcept.cpp)

add_library(wscpp SHARED ${SRC_FILES})
add_library(wscppstatic STATIC ${SRC_FILES})

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

set_target_properties(wscpp PROPERTIES PUBLIC_HEADER wscpp.h)

install(TARGETS wscpp
	EXPORT wscpp-targets
	RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
	ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
	PRIVATE_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

if(BUILD_SAMPLE)
	add_executable(wsserver-test wsserver-test.cpp)
	target_include_directories(wsserver-test PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
	target_link_libraries(wsserver-test wscpp)
	install(TARGETS wsserver-test DESTINATION "${CMAKE_INSTALL_FULL_BINDIR}")
endif()

install(TARGETS wscppstatic DESTINATION "${CMAKE_INSTALL_FULL_LIBDIR}")

install(EXPORT wscpp-targets DESTINATION lib/cmake/wscpp)

configure_package_config_file(
	"wscppConfig.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/wscppConfig.cmake"
	INSTALL_DESTINATION "lib/cmake/wscpp"
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/wscppConfig.cmake" DESTINATION "lib/cmake/wscpp")
