cmake_minimum_required(VERSION 3.8 FATAL_ERROR)
project(EFTR LANGUAGES C)


set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_LIST_DIR}/modules")

set(CMAKE_C_FLAGS "-Ofast -std=c2x")

add_executable(EFTR "${CMAKE_CURRENT_LIST_DIR}/deps/glad/src/glad.c"
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
	)

target_link_options(EFTR  PRIVATE "-L${CMAKE_CURRENT_LIST_DIR}/deps/npcap/Lib/x64"
	"-L${CMAKE_CURRENT_LIST_DIR}/deps/glfw-3.3.2.bin.WIN64/lib-mingw-w64")

#include_directories("${CMAKE_CURRENT_LIST_DIR}/deps/glfw-3.3.2.bin.WIN32/include")

target_link_libraries(EFTR PRIVATE OpenGL32 glfw3 packet wpcap WSock32 pthread)
target_include_directories(EFTR PRIVATE
	"${CMAKE_CURRENT_LIST_DIR}/deps/npcap/Include"
	"${CMAKE_CURRENT_LIST_DIR}/deps/glm-c"
	"${CMAKE_CURRENT_LIST_DIR}/deps/glad/include"
	"${CMAKE_CURRENT_LIST_DIR}/deps/glfw-3.3.2.bin.WIN64/include"
	)