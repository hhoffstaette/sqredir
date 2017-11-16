
cmake_minimum_required(VERSION 2.8)

project(sqredir)

set (SQREDIR_VERSION "1.3.2")

# custom distclean target
if (UNIX)
	add_custom_target (distclean @echo cleaning for source distribution)
	set (DISTCLEAN_FILES CMakeCache.txt cmake_install.cmake install_manifest.txt
		Makefile core gmon.out version.h *~)
	set (DISTCLEAN_DIRS CMakeFiles)

	add_custom_command (
		TARGET  distclean
		COMMENT "distribution clean"
		COMMAND ${CMAKE_MAKE_PROGRAM} ARGS clean
		COMMAND ${CMAKE_COMMAND} ARGS -E remove ${DISTCLEAN_FILES}
		COMMAND ${CMAKE_COMMAND} ARGS -E remove_directory ${DISTCLEAN_DIRS}
	)
endif ()

# obey CXXFLAGS or use defaults
if (NOT CMAKE_CXX_FLAGS)
	# generic defaults
	set (CMAKE_CXX_FLAGS "-pipe -std=c++11 -march=native -O2 -Wall")
else ()
	# add C++11 support
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
endif ()

# don't let clang complain about unsupported GCC flags
if (CMAKE_CXX_COMPILER MATCHES "clang")
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Qunused-arguments")
endif ()

message ("-- Using CXXFLAGS: ${CMAKE_CXX_FLAGS}")
message ("-- Version: ${SQREDIR_VERSION}")

configure_file ("${PROJECT_SOURCE_DIR}/version.h.in" "${PROJECT_BINARY_DIR}/version.h")

set (SRC blocklist.cpp sqredir.cpp)
set (EXEC sqredir)

add_executable (${EXEC} ${SRC})

find_library(PCREPOSIX_LIBRARY pcreposix)

target_link_libraries(${EXEC} ${PCREPOSIX_LIBRARY})

# configure via -DCMAKE_INSTALL_PREFIX=/usr
install (TARGETS ${EXEC} DESTINATION bin)

# TODO: we should really observe CMAKE_INSTALL_PREFIX,
# but the config file location is currently hardcoded
install (FILES sqredir.conf DESTINATION /etc)

