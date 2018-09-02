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

#ifndef _SERVER_REACTOR_H_
#define _SERVER_REACTOR_H_

#include <grpcpp/grpcpp.h>

#include <utilities/crypto.h>
#include <hello_world.grpc.pb.h>

class AuthenticatedServerUnaryReactor: public grpc::ServerUnaryReactor {
 public:
  void OnDone() override;
  void OnCancel() override;

 protected:
  AuthenticatedServerUnaryReactor(std::shared_ptr<AsymmetricKey> signingKey);

  std::shared_ptr<hello_world::AuthenticationToken> GetAuthorizationTokenOrFinish(grpc::CallbackServerContext* context);

 private:
  std::shared_ptr<AsymmetricKey> const signingKey_;
};

template <class REQUEST, class RESPONSE>
class AuthenticatedServerUnaryReactorT: public AuthenticatedServerUnaryReactor {
 protected:
  REQUEST const* const request_;
  RESPONSE* const response_;

  AuthenticatedServerUnaryReactorT(std::shared_ptr<AsymmetricKey> signingKey, REQUEST const* request, RESPONSE* response)
      : AuthenticatedServerUnaryReactor(signingKey)
      , request_(request)
      , response_(response) {
  }
};

#endif