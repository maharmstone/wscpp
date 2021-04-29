cmake_minimum_required(VERSION 3.10)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

project(wscpp)

option(BUILD_SAMPLE "Build sample programs" ON)

find_package(fmt REQUIRED)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

add_definitions(-DWSCPP_EXPORT)

set(SRC_FILES src/wsclient.cpp
	src/wsserver.cpp
	src/b64.cpp
	src/sha1.cpp
	src/wsexcept.cpp)

add_library(wscpp SHARED ${SRC_FILES})
add_library(wscppstatic STATIC ${SRC_FILES})

if(WIN32)
	target_link_libraries(wscpp wsock32 ws2_32 secur32 ntdsapi)
else()
	target_link_libraries(wscpp pthread gssapi_krb5)
endif()

target_link_libraries(wscpp fmt::fmt-header-only)
target_link_libraries(wscppstatic fmt::fmt-header-only)

target_compile_options(wscpp PRIVATE
	$<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:
		-Wall>
	$<$<CXX_COMPILER_ID:MSVC>:
		/W4>)

set_target_properties(wscpp PROPERTIES PUBLIC_HEADER src/wscpp.h)

if(WIN32 AND NOT MSVC)
	target_link_options(wscpp PUBLIC -static -static-libgcc)
endif()

install(TARGETS wscpp
	EXPORT wscpp-targets
	RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
	ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
	PRIVATE_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libwscpp.pdb" DESTINATION "${CMAKE_INSTALL_BINDIR}" OPTIONAL)

if(BUILD_SAMPLE)
	add_executable(wsserver-test src/wsserver-test.cpp)
	target_include_directories(wsserver-test PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
	target_link_libraries(wsserver-test wscpp)
	install(TARGETS wsserver-test DESTINATION "${CMAKE_INSTALL_FULL_BINDIR}")
	install(FILES "${CMAKE_CURRENT_BINARY_DIR}/wsserver-test.pdb" DESTINATION "${CMAKE_INSTALL_BINDIR}" OPTIONAL)

	add_executable(wsclient-test src/wsclient-test.cpp)
	target_include_directories(wsclient-test PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
	target_link_libraries(wsclient-test wscpp)
	install(TARGETS wsclient-test DESTINATION "${CMAKE_INSTALL_FULL_BINDIR}")
	install(FILES "${CMAKE_CURRENT_BINARY_DIR}/wsclient-test.pdb" DESTINATION "${CMAKE_INSTALL_BINDIR}" OPTIONAL)
endif()

install(TARGETS wscppstatic DESTINATION "${CMAKE_INSTALL_FULL_LIBDIR}")

install(EXPORT wscpp-targets DESTINATION lib/cmake/wscpp)

configure_package_config_file(
	"wscppConfig.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/wscppConfig.cmake"
	INSTALL_DESTINATION "lib/cmake/wscpp"
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/wscppConfig.cmake" DESTINATION "lib/cmake/wscpp")
