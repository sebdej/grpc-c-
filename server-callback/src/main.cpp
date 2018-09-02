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

#include <grpcpp/grpcpp.h>
#include <spdlog/spdlog.h>

#include <certificates/trusted_chain.h>
#include <certificates/server.h>
#include <certificates/server_key.h>

#include "hello_world_service.h"

int main() {
  std::string address("0.0.0.0:50051");

  grpc::EnableDefaultHealthCheckService(true);

  grpc::SslServerCredentialsOptions::PemKeyCertPair pkcp;

  pkcp.cert_chain = std::string_view(reinterpret_cast<char*>(server_crt), server_crt_len);
  pkcp.private_key = std::string_view(reinterpret_cast<char*>(server_key), server_key_len);
 
  grpc::SslServerCredentialsOptions sco;
  sco.pem_key_cert_pairs.push_back(pkcp);
  sco.pem_root_certs = std::string_view(reinterpret_cast<char*>(trusted_chain_crt), trusted_chain_crt_len);

  auto sslCredentials = grpc::SslServerCredentials(sco);

  grpc::ServerBuilder builder;
  builder.SetDefaultCompressionAlgorithm(GRPC_COMPRESS_GZIP);
  builder.AddListeningPort(address, sslCredentials);

  HelloWorldService helloWorldService(createEllipticCurve());

  builder.RegisterService(&helloWorldService);

  auto completionQueue = builder.AddCompletionQueue();

  std::unique_ptr<grpc::Server> server(builder.BuildAndStart());

  if (server) {
    spdlog::info("Server listening on {}", address);

    server->Wait();
  } else {
    spdlog::critical("Server creation failed");

    return 1;
  }

  return 0;
}
