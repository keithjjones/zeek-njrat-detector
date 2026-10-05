cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(NJRAT LANGUAGES C)

list(PREPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
find_package(SpicyPlugin REQUIRED)

# Set mininum versions that this plugin needs. Make sure to use "x.y.z" format.
# spicy_require_version("1.2.0")
# spicy_plugin_require_version("0.99.0")
#
# The parser skips the tail of long messages with "skip bytes &size=..." so that
# it never has to buffer them. Older Spicy versions either reject that syntax or
# buffer the data anyway, so the memory bound only holds from Zeek 7.0 on.
zeek_require_version("7.0.0")

if (NOT CMAKE_BUILD_TYPE)
    # Default to release build.
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "")
endif ()

add_subdirectory(analyzer)
