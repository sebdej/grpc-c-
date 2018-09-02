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

#include <openssl/crypto.h>
#include <openssl/decoder.h>
#include <openssl/ec.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <spdlog/spdlog.h>
#include <memory>
#include <stdexcept>

#include <utilities/crypto.h>

class OpenSslSigner: public Signer {
 public:
  OpenSslSigner(EVP_MD_CTX* digestContext)
      : digestContext_(digestContext) {
  }

  ~OpenSslSigner() {
    EVP_MD_CTX_free(digestContext_);
  }

  bool Update(std::string_view data) override {
    if (EVP_DigestSignUpdate(digestContext_, data.data(), data.size()) == 1) {
      return true;
    }

    spdlog::error("EVP_DigestSignUpdate");

    return false;
  }

  bool Finalize(std::string& signature) override {
    size_t signatureLength = 0;

    if (EVP_DigestSignFinal(digestContext_, nullptr, &signatureLength)) {
      signature.resize(signatureLength);

      if (EVP_DigestSignFinal(digestContext_, (unsigned char*)&signature.front(), &signatureLength)) {
        if (signatureLength < signature.size()) {
          signature.resize(signatureLength);
        }

        return true;
      }
    }

    spdlog::error("EVP_DigestSignFinal");

    return false;
  }

 private:
  EVP_MD_CTX* const digestContext_;
};

class OpenSslVerifier: public Verifier {
 public:
  OpenSslVerifier(EVP_MD_CTX* digestContext)
      : digestContext_(digestContext) {
  }

  ~OpenSslVerifier() {
    EVP_MD_CTX_free(digestContext_);
  }

  bool Update(std::string_view data) override {
    if (EVP_DigestVerifyUpdate(digestContext_, data.data(), data.size()) == 1) {
      return true;
    }

    spdlog::error("EVP_DigestVerifyUpdate");

    return false;
  }

  bool Finalize(std::string_view signature) override {
    int errCode = EVP_DigestVerifyFinal(digestContext_, (unsigned char const*)signature.data(), signature.size());

    if (errCode == 1) {
      return true;
    }

    spdlog::error("EVP_DigestVerifyFinal failed with code {}", errCode);

    return false;
  }

 private:
  EVP_MD_CTX* const digestContext_;
};

class EllipticCurve: public AsymmetricKey {
 public:
  EllipticCurve(EVP_PKEY* pkey)
      : pkey_(pkey) {
  }

  ~EllipticCurve() {
    EVP_PKEY_free(pkey_);
  }

  std::unique_ptr<Signer> CreateSigner() override {
    EVP_MD_CTX* const digestContext = EVP_MD_CTX_new();

    if (digestContext) {
      EVP_MD const* const messageDigest = EVP_MD_fetch(nullptr, "SHA384", "provider=default");

      spdlog::debug("Message digest algorithm: {}", OBJ_nid2sn(EVP_MD_type(messageDigest)));

      if (EVP_DigestSignInit(digestContext, nullptr, messageDigest, nullptr, pkey_) == 1) {
        return std::make_unique<OpenSslSigner>(digestContext);
      } else {
        spdlog::error("EVP_DigestSignInit failed");
      }

      EVP_MD_CTX_free(digestContext);
    } else {
      spdlog::error("EVP_MD_CTX_new failed");
    }

    return nullptr;
  }

  std::unique_ptr<Verifier> CreateVerifier() override {
    EVP_MD_CTX* const digestContext = EVP_MD_CTX_new();

    if (digestContext) {
      EVP_MD const* const messageDigest = EVP_MD_fetch(nullptr, "SHA384", "provider=default");

      spdlog::debug("Message digest algorithm: {}", OBJ_nid2sn(EVP_MD_type(messageDigest)));

      if (EVP_DigestVerifyInit(digestContext, nullptr, messageDigest, nullptr, pkey_) == 1) {
        return std::make_unique<OpenSslVerifier>(digestContext);
      } else {
        spdlog::error("EVP_DigestVerifyInit failed");
      }

      EVP_MD_CTX_free(digestContext);
    } else {
      spdlog::error("EVP_MD_CTX_new failed");
    }

    return nullptr;
  }

 private:
  EVP_PKEY* const pkey_;
};

std::shared_ptr<AsymmetricKey> createEllipticCurve() {
  if (EVP_PKEY* pkey = EVP_EC_gen("secp384r1")) {
    return std::make_shared<EllipticCurve>(pkey);
  }

  return nullptr;
}