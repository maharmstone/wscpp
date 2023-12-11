cmake_minimum_required(VERSION 3.10)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

project(wscpp)

option(BUILD_SAMPLE "Build sample programs" ON)
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(BUILD_MODULE "Build module" OFF)
option(WITH_OPENSSL "Use OpenSSL for encryption" ON)
option(WITH_ZLIB "Use zlib for compression" ON)

if(WITH_ZLIB)
	find_package(ZLIB REQUIRED)
endif()

if(WITH_OPENSSL)
	find_package(OpenSSL REQUIRED)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

add_definitions(-DWSCPP_EXPORT)
add_definitions(-D_WIN32_WINNT=0x0602)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(SRC_FILES src/wsclient.cpp
	src/wsserver.cpp
	src/b64.cpp
	src/sha1.cpp
	src/wsexcept.cpp
	src/ssl.cpp)

add_library(wscpp ${SRC_FILES})

if(WIN32)
	target_link_libraries(wscpp PUBLIC wsock32 ws2_32 secur32 ntdsapi crypt32)
else()
	target_link_libraries(wscpp PUBLIC pthread gssapi_krb5)
endif()

if(WITH_ZLIB)
	target_link_libraries(wscpp PUBLIC ZLIB::ZLIB)
endif()

if(WITH_OPENSSL)
	target_link_libraries(wscpp PUBLIC OpenSSL::Crypto OpenSSL::SSL)
endif()

target_compile_options(wscpp PRIVATE
	$<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:
		-Wall -Wextra>
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

export(TARGETS wscpp FILE ${PROJECT_BINARY_DIR}/wscpp-targets.cmake)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libwscpp.pdb" DESTINATION "${CMAKE_INSTALL_BINDIR}" OPTIONAL)

if(BUILD_SAMPLE)
	find_package(PkgConfig REQUIRED)
	pkg_check_modules(READLINE REQUIRED readline)

	add_executable(wsserver-test src/wsserver-test.cpp)
	target_include_directories(wsserver-test PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
	target_link_libraries(wsserver-test wscpp)
	install(TARGETS wsserver-test DESTINATION "${CMAKE_INSTALL_FULL_BINDIR}")
	install(FILES "${CMAKE_CURRENT_BINARY_DIR}/wsserver-test.pdb" DESTINATION "${CMAKE_INSTALL_BINDIR}" OPTIONAL)

	add_executable(wsclient-test src/wsclient-test.cpp)
	target_include_directories(wsclient-test PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
	target_include_directories(wsclient-test PUBLIC ${READLINE_INCLUDE_DIRS})
	target_link_libraries(wsclient-test wscpp)
	target_link_libraries(wsclient-test ${READLINE_LINK_LIBRARIES})
	install(TARGETS wsclient-test DESTINATION "${CMAKE_INSTALL_FULL_BINDIR}")
	install(FILES "${CMAKE_CURRENT_BINARY_DIR}/wsclient-test.pdb" DESTINATION "${CMAKE_INSTALL_BINDIR}" OPTIONAL)

	add_executable(wsclient-test2 src/wsclient-test2.cpp)
	target_include_directories(wsclient-test2 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
	target_link_libraries(wsclient-test2 wscpp)
	install(TARGETS wsclient-test2 DESTINATION "${CMAKE_INSTALL_FULL_BINDIR}")
	install(FILES "${CMAKE_CURRENT_BINARY_DIR}/wsclient-test2.pdb" DESTINATION "${CMAKE_INSTALL_BINDIR}" OPTIONAL)
endif()

install(EXPORT wscpp-targets DESTINATION lib/cmake/wscpp)

configure_package_config_file(
	"wscppConfig.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/wscppConfig.cmake"
	INSTALL_DESTINATION "lib/cmake/wscpp"
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/wscppConfig.cmake" DESTINATION "lib/cmake/wscpp")

if(BUILD_MODULE)
	cmake_minimum_required(VERSION 3.28)

	add_library(wscpp-mod SHARED)
	target_sources(wscpp-mod PUBLIC FILE_SET CXX_MODULES FILES src/mod.cpp)
	target_compile_features(wscpp-mod PUBLIC cxx_std_20)

	install(TARGETS wscpp-mod
		EXPORT wscpp-mod-targets
		RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
		ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
		LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
		PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
		PRIVATE_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
		FILE_SET CXX_MODULES DESTINATION "lib/cmake/wscpp"
	)

	export(TARGETS wscpp-mod
		FILE ${PROJECT_BINARY_DIR}/wscpp-mod-targets.cmake)

	install(EXPORT wscpp-mod-targets DESTINATION lib/cmake/wscpp)
endif()
