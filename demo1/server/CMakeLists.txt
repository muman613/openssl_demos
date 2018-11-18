project(demo1_server)

# Search OpenSSL
find_package(PkgConfig REQUIRED)
pkg_search_module(OPENSSL REQUIRED openssl)
pkg_search_module(LIBXML REQUIRED libxml-2.0)

if( OPENSSL_FOUND )
    include_directories(${OPENSSL_INCLUDE_DIRS})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
else()
    # Error; with REQUIRED, pkg_search_module() will throw an error by it's own
endif()

if ( LIBXML_FOUND )
    include_directories(${LIBXML_INCLUDE_DIRS})
    message(STATUS "Using libxml-2.0 ${LIBXML_VERSION} ${LIBXML_INCLUDE_DIRS}")
else()
    # error
endif()

add_executable(${PROJECT_NAME} main.cpp)

target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES} ${LIBXML_LIBRARIES})

