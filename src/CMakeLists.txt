cmake_minimum_required(VERSION 3.10)
set(CMAKE_C_STANDARD 11)

project(httpclient)

add_executable(httpclient main.c)
target_link_libraries(httpclient uring)
