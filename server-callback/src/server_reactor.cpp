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

#include "server_reactor.h"

#include <spdlog/spdlog.h>

#include <chrono>
#include <sstream>
#include <utilities/auth_token.h>

void AuthenticatedServerUnaryReactor::OnDone() {
  spdlog::info("AuthenticatedServerUnaryReactor::OnDone");
}

void AuthenticatedServerUnaryReactor::OnCancel() {
  spdlog::info("AuthenticatedServerUnaryReactor::OnCancel");
}

AuthenticatedServerUnaryReactor::AuthenticatedServerUnaryReactor(std::shared_ptr<AsymmetricKey> signingKey)
    : signingKey_(signingKey) {
}

std::shared_ptr<hello_world::AuthenticationToken> AuthenticatedServerUnaryReactor::GetAuthorizationTokenOrFinish(grpc::CallbackServerContext* context) {
  auto token = GetAuthenticationToken(context, signingKey_.get());

  if (!token) {
    Finish(Unauthenticated());
  }

  return token;
}