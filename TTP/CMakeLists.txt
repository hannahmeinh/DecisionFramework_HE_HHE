# TTP/CMakeLists.txt

cmake_minimum_required(VERSION 3.10)
project(KeyGeneration)

# Set C++17 Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Debug Build
#set(CMAKE_BUILD_TYPE Debug)
#set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_FLAGS_Release "-O3 -march=native -DNDEBUG")

# Force portable AES implementation
add_definitions(-DOC_ENABLE_PORTABLE_AES)

# Disable AVX2 for Keccak on ARM architecture
set(USE_AVX2 OFF CACHE BOOL "USE AVX2 version.")

# Find Packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(ZMQ REQUIRED libzmq)
find_package(nlohmann_json REQUIRED)

# Path to Libraries 
set(HYBRID_HE_FRAMEWORK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../hybrid-HE-framework")
set(HYBRID_HE_FRAMEWORK_BUILD_DIR "${HYBRID_HE_FRAMEWORK_DIR}/build")

# TFHE paths
set(TFHE_PREFIX "${CMAKE_CURRENT_SOURCE_DIR}/../hybrid-HE-framework/thirdparty/tfhe/build")
set(TFHE_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../hybrid-HE-framework/thirdparty/tfhe/src")
#set(TFHE_LIB "${TFHE_PREFIX}/libtfhe/libtfhe-nayuki-portable.so")
set(TFHE_LIB "${TFHE_PREFIX}/libtfhe/libtfhe-spqlios-fma.so")

# M4RI paths
set(M4RI_PREFIX "${CMAKE_CURRENT_SOURCE_DIR}/../hybrid-HE-framework/thirdparty/m4ri/installed")
set(M4RI_INCLUDE_DIR "${M4RI_PREFIX}/include")
set(M4RI_LIB "${M4RI_PREFIX}/lib/libm4ri.so")

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${HYBRID_HE_FRAMEWORK_DIR}
    ${TFHE_INCLUDE_DIR}
    ${M4RI_INCLUDE_DIR}
    ${ZMQ_INCLUDE_DIRS}
)

# Add link directories for ZMQ
link_directories(${ZMQ_LIBRARY_DIRS})

# Find Libraries
find_library(PERF_LIB perf PATHS ${HYBRID_HE_FRAMEWORK_BUILD_DIR}/util NO_DEFAULT_PATH REQUIRED)
find_library(KECCAK_LIB keccak PATHS ${HYBRID_HE_FRAMEWORK_BUILD_DIR}/util/keccak NO_DEFAULT_PATH REQUIRED)
find_library(AES_LIB aes PATHS ${HYBRID_HE_FRAMEWORK_BUILD_DIR}/util/aes NO_DEFAULT_PATH REQUIRED)
find_library(TFHECIPHERS_LIB tfheciphers PATHS ${HYBRID_HE_FRAMEWORK_BUILD_DIR}/ciphers NO_DEFAULT_PATH REQUIRED)

# Create executable
add_executable(mainTTP
    "mainTTP.cpp" 
    "../Key_Manager/key_storage.cpp"
    "../Data_Manager/data_manager.cpp"
    "../Parameters/parameters.cpp"
    "../Performance_Measurement/timewriter.cpp"
    "../hybrid-HE-framework/ciphers/he_only_z2/tfhe/he_only_z2_tfhe.cpp"
)

# Link Libraries
target_link_libraries(mainTTP
    ${TFHECIPHERS_LIB}
    ${PERF_LIB}
    ${KECCAK_LIB}
    ${AES_LIB}
    ${TFHE_LIB}
    ${M4RI_LIB}
    ${ZMQ_LIBRARIES}
    nlohmann_json::nlohmann_json
    pthread
)

# Compiler-Flags
#target_compile_options(mainTTP PRIVATE -Wall -Wextra ${ZMQ_CFLAGS})
target_compile_options(mainTTP PRIVATE ${ZMQ_CFLAGS_OTHER} -O3 -march=native)
