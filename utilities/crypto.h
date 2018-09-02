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

#ifndef _UTILITIES_CRYPTO_H_
#define _UTILITIES_CRYPTO_H_

#include <string>
#include <string_view>
#include <memory>

class Signer {
 public:
  virtual ~Signer() = default;

  virtual bool Update(std::string_view data) = 0;

  virtual bool Finalize(std::string& signature) = 0;
};

class Verifier {
 public:
  virtual ~Verifier() = default;

  virtual bool Update(std::string_view data) = 0;

  virtual bool Finalize(std::string_view signature) = 0;
};

class AsymmetricKey {
 public:
  virtual ~AsymmetricKey() = default;

  virtual std::unique_ptr<Signer> CreateSigner() = 0;

  virtual std::unique_ptr<Verifier> CreateVerifier() = 0;
};

std::shared_ptr<AsymmetricKey> createEllipticCurve();

#endif