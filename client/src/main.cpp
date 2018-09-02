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

#include <certificates/client.h>
#include <certificates/client_key.h>
#include <certificates/trusted_chain.h>
#include <grpcpp/grpcpp.h>
#include <hello_world.grpc.pb.h>
#include <spdlog/spdlog.h>

class MyCustomAuthenticator: public grpc::MetadataCredentialsPlugin {
 public:
  MyCustomAuthenticator() {
  }

  grpc::Status GetMetadata(grpc::string_ref service_url, grpc::string_ref methodName, const grpc::AuthContext& channelAuthContext,
                           std::multimap<grpc::string, grpc::string>* metadata) override {
    if (!m_ticket.empty()) {
      metadata->insert(std::make_pair("authorization", m_ticket));
    }

    return grpc::Status::OK;
  }

  void SetToken(std::string_view value) {
    m_ticket = fmt::format("Bearer {}", grpc::string(value.data(), value.size()));
  }

 private:
  grpc::string m_ticket;
};

void client(int id, std::shared_ptr<grpc::Channel> channel) {
  auto stub = hello_world::GrpcServer::NewStub(channel);

  for (int i = 0; i < 10; i++) {
    grpc::ClientContext context;
    hello_world::HelloWorldRequest helloWorldRequest;
    hello_world::HelloWorldResponse helloWorldResponse;

    helloWorldRequest.set_name("World");

    auto status = stub->HelloWorld(&context, helloWorldRequest, &helloWorldResponse);

    if (status.ok()) {
      spdlog::info("[{0}] HelloWorld successfull: message={1}", id, helloWorldResponse.message());
    } else {
      spdlog::error("[{0}] HelloWorld failed: {1}", id, status.error_message());
    }
  }

  stub.release();
}

int main() {
  auto authenticator = std::make_unique<MyCustomAuthenticator>();

  auto callCredentials = grpc::MetadataCredentialsFromPlugin(std::unique_ptr<grpc::MetadataCredentialsPlugin>(authenticator.get()));

  grpc::SslCredentialsOptions sslOpts;
  sslOpts.pem_root_certs = std::string_view(reinterpret_cast<char*>(trusted_chain_crt), trusted_chain_crt_len);
  sslOpts.pem_cert_chain = std::string_view(reinterpret_cast<char*>(client_crt), client_crt_len);
  sslOpts.pem_private_key = std::string_view(reinterpret_cast<char*>(client_key), client_key_len);

  auto channelCredentials = grpc::CompositeChannelCredentials(grpc::SslCredentials(sslOpts), callCredentials);

  grpc::ChannelArguments args;
  args.SetCompressionAlgorithm(GRPC_COMPRESS_GZIP);

  auto channel = grpc::CreateCustomChannel("localhost:50051", channelCredentials, args);

  auto stub = hello_world::GrpcServer::NewStub(channel);

  grpc::ClientContext context;
  hello_world::LoginRequest loginRequest;
  hello_world::LoginResponse loginResponse;

  loginRequest.set_username("admin");
  loginRequest.set_password("abcde");

  auto status = stub->Login(&context, loginRequest, &loginResponse);

  if (status.ok()) {
    spdlog::info("Login successfull: token={}", loginResponse.auth_token());
    authenticator->SetToken(loginResponse.auth_token());

    std::vector<std::thread> threads;

    for (int i = 0; i < 10; i++) {
      threads.emplace_back(std::thread([i, channel] { client(i, channel); }));
    }

    for (auto it = threads.begin(); it != threads.end(); it++) {
      it->join();
    }
  } else {
    spdlog::error("Login failed: {}", status.error_message());
  }

  channel.reset();

  return 0;
}
