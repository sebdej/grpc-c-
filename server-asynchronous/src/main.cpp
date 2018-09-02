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

#include <thread>
#include <grpcpp/grpcpp.h>
#include <spdlog/spdlog.h>

#include <certificates/server.h>
#include <certificates/server_key.h>
#include <certificates/trusted_chain.h>

#include <hello_world.grpc.pb.h>
#include <utilities/auth_token.h>
#include <utilities/crypto.h>

enum class CallStatus { CREATE, PROCESS, FINISH };

class BaseCall {
 public:
  virtual ~BaseCall() = default;

  virtual void Proceed(bool ok) = 0;
};

template <class REQUEST, class RESPONSE>
class AnonymousCall: public BaseCall {
 public:
  AnonymousCall(hello_world::GrpcServer::AsyncService* service, grpc::ServerCompletionQueue* completionQueue, AsymmetricKey* signingKey)
      : service_(service)
      , completionQueue_(completionQueue)
      , signingKey_(signingKey)
      , status_(CallStatus::CREATE)
      , responder_(&serverContext_) {
  }

  void Proceed(bool ok) override {
    switch (status_) {
      case CallStatus::CREATE:
        status_ = CallStatus::PROCESS;

        AcceptRequest();
        break;

      case CallStatus::PROCESS: {
        New()->Proceed(true);

        status_ = CallStatus::FINISH;

        auto const status = Respond();

        if (status.ok()) {
          responder_.Finish(response_, status, this);
        } else {
          responder_.FinishWithError(status, this);
        }
        break;
      }

      case CallStatus::FINISH:
        delete this;
        break;

      default:
        assert(false);
    }
  }

 protected:
  grpc::ServerContext serverContext_;
  hello_world::GrpcServer::AsyncService* const service_;
  grpc::ServerCompletionQueue* const completionQueue_;
  AsymmetricKey* const signingKey_;
  CallStatus status_;
  REQUEST request_;
  RESPONSE response_;
  grpc::ServerAsyncResponseWriter<RESPONSE> responder_;

  virtual BaseCall* New() = 0;
  virtual void AcceptRequest() = 0;
  virtual grpc::Status Respond() = 0;
};

template <class REQUEST, class RESPONSE>
class AuthenticatedCall: public AnonymousCall<REQUEST, RESPONSE> {
 public:
  AuthenticatedCall(hello_world::GrpcServer::AsyncService* service, grpc::ServerCompletionQueue* completionQueue, AsymmetricKey* signingKey)
      : AnonymousCall<REQUEST, RESPONSE>(service, completionQueue, signingKey) {
  }

 protected:
  grpc::Status Respond() final {
    if (auto authToken = GetAuthenticationToken(&this->serverContext_, this->signingKey_)) {
      return RespondAuthenticated(authToken.get());
    }

    return Unauthenticated();
  }

  virtual grpc::Status RespondAuthenticated(hello_world::AuthenticationToken* authToken) = 0;
};

class LoginCall: public AnonymousCall<hello_world::LoginRequest, hello_world::LoginResponse> {
 public:
  LoginCall(hello_world::GrpcServer::AsyncService* service, grpc::ServerCompletionQueue* completionQueue, AsymmetricKey* signingKey)
      : AnonymousCall(service, completionQueue, signingKey) {
  }

  BaseCall* New() override {
    return new LoginCall(service_, completionQueue_, signingKey_);
  }

 protected:
  void AcceptRequest() override {
    service_->RequestLogin(&serverContext_, &request_, &responder_, completionQueue_, completionQueue_, this);
  }

  grpc::Status Respond() override {
    if (request_.username() == "admin" && request_.password() == "abcde") {
      response_.set_auth_token(CreateAuthenticationToken("admin", {"user", "admin"}, signingKey_));

      return Success();
    }

    return Unauthenticated();
  }
};

class HelloWorldCall: public AuthenticatedCall<hello_world::HelloWorldRequest, hello_world::HelloWorldResponse> {
 public:
  HelloWorldCall(hello_world::GrpcServer::AsyncService* service, grpc::ServerCompletionQueue* completionQueue, AsymmetricKey* signingKey)
      : AuthenticatedCall(service, completionQueue, signingKey) {
  }

  BaseCall* New() override {
    return new HelloWorldCall(service_, completionQueue_, signingKey_);
  }

 protected:
  void AcceptRequest() override {
    service_->RequestHelloWorld(&serverContext_, &request_, &responder_, completionQueue_, completionQueue_, this);
  }

  grpc::Status RespondAuthenticated(hello_world::AuthenticationToken* authToken) override {
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    std::stringstream stream;
    stream << "[username: " << authToken->username() << "] Hello " << request_.name() << " from thread #" << std::this_thread::get_id() << "!";

    response_.set_message(stream.str());

    return Success();
  }
};

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
  auto completionQueue = builder.AddCompletionQueue();

  hello_world::GrpcServer::AsyncService service;

  builder.RegisterService(&service);

  std::unique_ptr<grpc::Server> server(builder.BuildAndStart());

  spdlog::info("Server listening on {}", address);

  auto signingKey = createEllipticCurve();

  (new LoginCall(&service, completionQueue.get(), signingKey.get()))->Proceed(true);
  (new HelloWorldCall(&service, completionQueue.get(), signingKey.get()))->Proceed(true);

  std::vector<std::thread> threads;

  for (int i = 0; i < 10; i++) {
    threads.emplace_back(std::thread(
        [](grpc::CompletionQueue* completionQueue) {
          void* tag = nullptr;
          bool ok = false;

          while (completionQueue->Next(&tag, &ok)) {
            static_cast<BaseCall*>(tag)->Proceed(ok);
          }
        },
        completionQueue.get()));
  }

  for (auto it = threads.begin(); it != threads.end(); it++) {
    it->join();
  }

  return 0;
}
