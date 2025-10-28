cmake_minimum_required(VERSION 3.10)
project(rjson)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-Duuid_system_generator)

# External dependencies
find_package(ZLIB REQUIRED)

# Include directories for header-only libraries
include_directories(include)

# Add source files
file(GLOB SOURCES "src/*.cpp")

# Create the executable
add_executable(rjson ${SOURCES})
target_link_libraries(rjson PRIVATE ZLIB::ZLIB)
