
cmake_minimum_required(VERSION 2.8)

project(sqredir)

# custom distclean target
if (UNIX)
	add_custom_target (distclean @echo cleaning for source distribution)
	set (DISTCLEAN_FILES CMakeCache.txt cmake_install.cmake install_manifest.txt
		Makefile core gmon.out *~)
	set (DISTCLEAN_DIRS CMakeFiles)

	add_custom_command (
		TARGET  distclean
		COMMENT "distribution clean"
		COMMAND ${CMAKE_MAKE_PROGRAM} ARGS clean
		COMMAND ${CMAKE_COMMAND} ARGS -E remove ${DISTCLEAN_FILES}
		COMMAND ${CMAKE_COMMAND} ARGS -E remove_directory ${DISTCLEAN_DIRS}
	)
endif ()

# obey CXXFLAGS
if (CMAKE_CXX_FLAGS)
	# use supplied CXXFLAGS, but also enforce POSIX
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_XOPEN_SOURCE")
	message ("-- Using CXXFLAGS: ${CMAKE_CXX_FLAGS}")
else ()
	# generic defaults
	set (CMAKE_CXX_FLAGS "-pipe -Wall -march=native -O2 -D_XOPEN_SOURCE")
endif ()

# don't let clang complain about unsupported GCC flags
if (CMAKE_CXX_COMPILER MATCHES "clang")
	set (CMAKE_CXX_FLAGS "-Qunused-arguments ${CMAKE_CXX_FLAGS}")
endif ()

set (src blocklist.cpp sqredir.cpp)
add_executable (sqredir ${src})

# configure via -DCMAKE_INSTALL_PREFIX=/usr
install (TARGETS sqredir DESTINATION bin)

# TODO: we should really observe CMAKE_INSTALL_PREFIX,
# but the config file location is currently hardcoded
install (FILES sqredir.conf DESTINATION /etc)

