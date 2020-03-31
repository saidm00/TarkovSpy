cmake_minimum_required(VERSION 3.8 FATAL_ERROR)
project(EFTS LANGUAGES C)

add_executable(EFTR "src/main.c" "src/unet.h")

target_link_libraries(EFTR PRIVATE "-L\"${CMAKE_CURRENT_LIST_DIR}/dep/npcap/Lib/x64\" -lpacket -lwpcap -lWSock32 -lpthread")
target_include_directories(EFTR PRIVATE "${CMAKE_CURRENT_LIST_DIR}/dep/npcap/Include")