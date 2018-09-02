//  Copyright 2021 Sébastian Dejonghe
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

#include "hello_world_service.h"
#include <utilities/auth_token.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <sstream>
#include <thread>

HelloWorldService::HelloWorldService(std::shared_ptr<AsymmetricKey> signingKey)
    : signingKey_(signingKey) {
}

grpc::Status HelloWorldService::Login(grpc::ServerContext* context, hello_world::LoginRequest const* request, hello_world::LoginResponse* response) {
  if (request->username() == "admin" && request->password() == "abcde") {
    response->set_auth_token(CreateAuthenticationToken("admin", {"user", "admin"}, signingKey_.get()));

    return Success();
  } else {
    return Unauthenticated();
  }
}

grpc::Status HelloWorldService::HelloWorld(grpc::ServerContext* context, hello_world::HelloWorldRequest const* request,
                                           hello_world::HelloWorldResponse* response) {
  if (auto authToken = GetAuthenticationToken(context, signingKey_.get())) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    std::stringstream stream;
    stream << "[username: " << authToken->username() << "] Hello " << request->name() << " from thread #" << std::this_thread::get_id() << "!";

    response->set_message(stream.str());

    return Success();
  } else {
    return Unauthenticated();
  }
}
