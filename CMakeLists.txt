cmake_minimum_required(VERSION 3.13)
project(http C)

set(CMAKE_C_STANDARD 99)

add_executable(http http/http.h http/http.c main.c http/http_parser.c http/http_parser.h http/krypton.c http/krypton.h main.c http/cJSON.c http/cJSON.h http/api.c http/api.h)