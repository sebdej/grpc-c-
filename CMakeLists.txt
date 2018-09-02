#  Copyright 2021 Sébastian Dejonghe
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

cmake_minimum_required(VERSION 3.16)

project(grpc VERSION 1.0)

set(CMAKE_CXX_STANDARD 20)

find_package(spdlog CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

include_directories(${PROTOBUF_INCLUDE_DIR})

function(grpc_compile SOURCES_NAME HEADERS_NAME NAME)
    set(SOURCE "${CMAKE_CURRENT_BINARY_DIR}/${NAME}.grpc.pb.cc")
	set(HEADER "${CMAKE_CURRENT_BINARY_DIR}/${NAME}.grpc.pb.h")

	set(SOURCES ${${SOURCES_NAME}})
	set(HEADERS ${${HEADERS_NAME}})

	list(APPEND SOURCES ${SOURCE})
	list(APPEND HEADERS ${HEADER})

	set(${SOURCES_NAME} ${SOURCES} PARENT_SCOPE)
	set(${HEADERS_NAME} ${HEADERS} PARENT_SCOPE)

	add_custom_command(
	  OUTPUT ${SOURCE} ${HEADER}
	  COMMAND protobuf::protoc -I=${PROJECT_SOURCE_DIR}/proto --grpc_out=${CMAKE_CURRENT_BINARY_DIR} --plugin=protoc-gen-grpc=$<TARGET_FILE:gRPC::grpc_cpp_plugin> ${NAME}.proto
	  DEPENDS protobuf::protoc  ${PROJECT_SOURCE_DIR}/proto/${NAME}.proto
	  COMMENT "Running protoc for gRPC C++ on ${NAME}.proto"
	  VERBATIM)
endfunction()

add_subdirectory("client")
add_subdirectory("server-synchronous")
add_subdirectory("server-asynchronous")
add_subdirectory("server-callback")