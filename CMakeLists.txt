cmake_minimum_required(VERSION 3.8 FATAL_ERROR)

set(CMAKE_C_COMPILER_WORKS TRUE)
set(CMAKE_CXX_COMPILER_WORKS TRUE)

project(EFTR C)

set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_LIST_DIR}/modules")

set(BUILD_DIR ${CMAKE_BINARY_DIR})
set(CMAKE_CURRENT_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/bin")

set(CMAKE_C_FLAGS "-std=gnu2x -fms-extensions -m64")

add_subdirectory(deps/TinyCThread)

add_executable(EFTR
	"${CMAKE_CURRENT_LIST_DIR}/deps/glad/src/glad.c"
	"${CMAKE_CURRENT_LIST_DIR}/src/ini.h"
	"${CMAKE_CURRENT_LIST_DIR}/src/ini.c"
	"${CMAKE_CURRENT_LIST_DIR}/src/nuklear.h"
	"${CMAKE_CURRENT_LIST_DIR}/src/nuklear_glfw_gl3.h"
	"${CMAKE_CURRENT_LIST_DIR}/src/main.c"
	"${CMAKE_CURRENT_LIST_DIR}/src/unet.h"
	"${CMAKE_CURRENT_LIST_DIR}/src/hashrecord.h"
	"${CMAKE_CURRENT_LIST_DIR}/src/hashrecord.c"
	"${CMAKE_CURRENT_LIST_DIR}/src/world.h"
	"${CMAKE_CURRENT_LIST_DIR}/src/world.c"
	"${CMAKE_CURRENT_LIST_DIR}/src/bytestream.h"
	"${CMAKE_CURRENT_LIST_DIR}/src/stretchyarray.h"
	"${CMAKE_CURRENT_LIST_DIR}/src/network.h"
	"${CMAKE_CURRENT_LIST_DIR}/src/network.c"
	"${CMAKE_CURRENT_LIST_DIR}/src/math.h"
	"${CMAKE_CURRENT_LIST_DIR}/src/common.h"
	)

target_link_options(EFTR  PRIVATE "-L${CMAKE_CURRENT_LIST_DIR}/deps/npcap/Lib/x64"
	"-L${CMAKE_CURRENT_LIST_DIR}/deps/glfw-3.3.2.bin.WIN64/lib-vc2019")


#include_directories("${CMAKE_CURRENT_LIST_DIR}/deps/glfw-3.3.2.bin.WIN32/include")

target_link_libraries(EFTR PRIVATE OpenGL32 glfw3 packet wpcap WSock32 tinycthread)
target_include_directories(EFTR PRIVATE
	"${CMAKE_CURRENT_LIST_DIR}/deps/npcap/Include"
	"${CMAKE_CURRENT_LIST_DIR}/deps/glm-c"
	"${CMAKE_CURRENT_LIST_DIR}/deps/glad/include"
	"${CMAKE_CURRENT_LIST_DIR}/deps/glfw-3.3.2.bin.WIN64/include"
	)

set_target_properties(EFTR
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

file(COPY "${CMAKE_CURRENT_LIST_DIR}\\data" DESTINATION "${BUILD_DIR}")