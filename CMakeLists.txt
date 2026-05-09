cmake_minimum_required(VERSION 3.16)
project(NFSHPWindowedMode LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 32-bit (x86) is mandatory for HP2010
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR "You must use -A Win32 to compile for the game's 32-bit architecture.")
endif()

add_definitions(-D_CRT_SECURE_NO_WARNINGS)

# Include Directories
include_directories(
    "."
    "external/hooking"
    "external/injector/include"
    "external/injector/safetyhook/include"
    "external/injector/minhook/include"
    "external/injector/zydis"
)

# Automatically find all implementation files in the submodules
file(GLOB_RECURSE SAFETYHOOK_SOURCES "external/injector/safetyhook/src/*.cpp")
file(GLOB_RECURSE ZYDIS_SOURCES "external/injector/zydis/*.c" "external/injector/zydis/*.cpp")

set(SRC_FILES
    "dllmain.cpp"
    "external/hooking/Hooking.Patterns.cpp"
    ${SAFETYHOOK_SOURCES}
    ${ZYDIS_SOURCES}
)

# Create the ASI
add_library(${PROJECT_NAME} SHARED ${SRC_FILES})

# Output Formatting
set_target_properties(${PROJECT_NAME} PROPERTIES 
    PREFIX ""
    SUFFIX ".asi"
)