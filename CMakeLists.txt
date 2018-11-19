cmake_minimum_required(VERSION 3.12)
project(openssl_demos)

set(CMAKE_CXX_STANDARD 14)

add_subdirectory(demo1)
add_subdirectory(sandbox/xml-test)

# add_executable(openssl_demos main.cpp)