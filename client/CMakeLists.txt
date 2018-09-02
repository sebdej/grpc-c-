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

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_SOURCE_DIR})

protobuf_generate_cpp(PROTO_SOURCES PROTO_HEADERS ${CMAKE_SOURCE_DIR}/proto/hello_world.proto)

grpc_compile(GRPC_SOURCES GRPC_HEADERS "hello_world")

add_executable(grpc-client
	${CMAKE_SOURCE_DIR}/proto/hello_world.proto
	src/main.cpp
	${PROTO_SOURCES} ${PROTO_HEADERS} ${GRPC_SOURCES} ${GRPC_HEADERS})

source_group("Protocol Buffers Files" REGULAR_EXPRESSION ".*\\.proto$")

target_link_libraries(grpc-client PRIVATE spdlog::spdlog spdlog::spdlog_header_only)
target_link_libraries(grpc-client PRIVATE gRPC::gpr gRPC::grpc gRPC::grpc++)
target_link_libraries(grpc-client PRIVATE OpenSSL::SSL OpenSSL::Crypto)