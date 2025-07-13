cmake_minimum_required(VERSION 3.15)
project(DSE)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${PROJECT_SOURCE_DIR}/pbcwrapper)
include_directories(${PROJECT_SOURCE_DIR})

# 获取 wrapper 源代码，但排除 Testing.cc
file(GLOB WRAPPER_SOURCES ${PROJECT_SOURCE_DIR}/pbcwrapper/*.cc)
list(REMOVE_ITEM WRAPPER_SOURCES ${PROJECT_SOURCE_DIR}/pbcwrapper/Testing.cc)

# 你的主程序
add_executable(pbc_test pbc_test.cpp ${WRAPPER_SOURCES})
add_executable(main main.cpp ShiftableEncryption.cpp BF_IBE.cpp ${WRAPPER_SOURCES})
add_executable(dse DSE.cpp ShiftableEncryption.cpp BF_IBE.cpp ${WRAPPER_SOURCES})
# add_executable(ibe BF_IBE.cpp ${WRAPPER_SOURCES})
target_link_libraries(pbc_test pbc gmp)
target_link_libraries(main pbc gmp)
target_link_libraries(dse pbc gmp crypto)
