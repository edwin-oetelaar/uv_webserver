cmake_minimum_required(VERSION 3.2)
project(uv_webserver)
# find_package (Threads)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99  -pthread -Wall -Wextra")

set(SOURCE_FILES
    webserver.c
    http-parser/http_parser.c
    )


add_executable(uv_webserver ${SOURCE_FILES})

include_directories(. http-parser libuv libuv/include )
# link the libraries to the executable
link_directories(libuv )
target_link_libraries(uv_webserver ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_SOURCE_DIR}/libuv/libuv.a )

