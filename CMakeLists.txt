
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

# obey CFLAGS
if (CMAKE_C_FLAGS)
	# enforce C99 and use supplied CFLAGS
	set (CMAKE_C_FLAGS "-std=c99 ${CMAKE_C_FLAGS}")
	message ("-- Using CFLAGS: ${CMAKE_C_FLAGS}")
else ()
	# generic defaults
	set (CMAKE_C_FLAGS "-pipe -std=c99 -Wall -O2")
endif ()

# don't let clang complain about unsupported GCC flags
if (CMAKE_C_COMPILER MATCHES "clang")
	set (CMAKE_C_FLAGS "-Qunused-arguments ${CMAKE_C_FLAGS}")
endif ()

set (src blocklist.c match.c sqredir.c)
add_executable (sqredir ${src})

# configure via -DCMAKE_INSTALL_PREFIX=/usr
install (TARGETS sqredir DESTINATION bin)

# TODO: we should really observe CMAKE_INSTALL_PREFIX,
# but the config file location is currently hardcoded
install (FILES sqredir.conf DESTINATION /etc)

