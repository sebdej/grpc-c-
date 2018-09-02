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

#ifndef _HELLO_WORLD_SERVICE_H_
#define _HELLO_WORLD_SERVICE_H_

#include <grpcpp/grpcpp.h>

#include <hello_world.grpc.pb.h>
#include <utilities/crypto.h>

class HelloWorldService: public hello_world::GrpcServer::Service {
 public:
  HelloWorldService(std::shared_ptr<AsymmetricKey> signingKey);

  grpc::Status Login(grpc::ServerContext* context, hello_world::LoginRequest const* request, hello_world::LoginResponse* response) override;

  grpc::Status HelloWorld(grpc::ServerContext* context, hello_world::HelloWorldRequest const* request, hello_world::HelloWorldResponse* response) override;

 private:
  std::shared_ptr<AsymmetricKey> const signingKey_;
};

#endif