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

#include <chrono>
#include <thread>
#include <sstream>
#include <spdlog/spdlog.h>

#include "server_reactor.h"
#include "hello_world_service.h"
#include <utilities/auth_token.h>

HelloWorldService::HelloWorldService(std::shared_ptr<AsymmetricKey> signingKey)
    : signingKey_(signingKey) {
}

class LoginReactor: public AuthenticatedServerUnaryReactorT<hello_world::LoginRequest, hello_world::LoginResponse> {
 public:
  LoginReactor(std::shared_ptr<AsymmetricKey> signingKey, hello_world::LoginRequest const* request, hello_world::LoginResponse* response)
      : AuthenticatedServerUnaryReactorT(signingKey, request, response) {
    if (request->username() == "admin" && request->password() == "abcde") {
      response_->set_auth_token(CreateAuthenticationToken("admin", {"user", "admin"}, signingKey.get()));

      Finish(Success());
    } else {
      Finish(Unauthenticated());
    }
  }
};

grpc::ServerUnaryReactor* HelloWorldService::Login(grpc::CallbackServerContext* context, hello_world::LoginRequest const* request,
                                                   hello_world::LoginResponse* response) {
  return new LoginReactor(signingKey_, request, response);
}

class HelloWorldReactor: public AuthenticatedServerUnaryReactorT<hello_world::HelloWorldRequest, hello_world::HelloWorldResponse> {
 public:
  HelloWorldReactor(std::shared_ptr<AsymmetricKey> signingKey, grpc::CallbackServerContext* context, hello_world::HelloWorldRequest const* request,
                    hello_world::HelloWorldResponse* response)
      : AuthenticatedServerUnaryReactorT(signingKey, request, response) {
    if (auto authToken = GetAuthorizationTokenOrFinish(context)) {
      std::stringstream stream;
      stream << "[username: " << authToken->username() << "] Hello " << request->name() << " from thread #" << std::this_thread::get_id() << "!";

      response->set_message(stream.str());

      Finish(Success());
    }
  }
};

grpc::ServerUnaryReactor* HelloWorldService::HelloWorld(grpc::CallbackServerContext* context, hello_world::HelloWorldRequest const* request,
                                                        hello_world::HelloWorldResponse* response) {
  return new HelloWorldReactor(signingKey_, context, request, response);
}