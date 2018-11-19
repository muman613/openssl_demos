project(xml-test)

# Search OpenSSL
find_package(PkgConfig REQUIRED)
pkg_search_module(LIBXML REQUIRED libxml-2.0)

if ( LIBXML_FOUND )
    include_directories(${LIBXML_INCLUDE_DIRS})
    message(STATUS "Using libxml-2.0 ${LIBXML_VERSION} ${LIBXML_INCLUDE_DIRS}")
else()
    # error
endif()

add_executable(${PROJECT_NAME} main.cpp)

target_link_libraries(${PROJECT_NAME} ${LIBXML_LIBRARIES})

