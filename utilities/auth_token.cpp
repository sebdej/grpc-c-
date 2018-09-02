#include <spdlog/spdlog.h>
#include <chrono>

#include <utilities/auth_token.h>
#include <utilities/base64.h>

std::string CreateAuthenticationToken(std::string const& username, std::vector<std::string> const& roles, AsymmetricKey* signingKey) {
  auto authenticationToken = new hello_world::AuthenticationToken();
  auto notAfter = std::chrono::utc_clock::now() + std::chrono::minutes(60);

  authenticationToken->mutable_not_after()->set_seconds(std::chrono::duration_cast<std::chrono::seconds>(notAfter.time_since_epoch()).count());
  authenticationToken->set_username(username);

  for (auto const& role : roles) {
    authenticationToken->add_roles(role);
  }

  return CreateSignedAuthenticationToken(authenticationToken, signingKey);
}

std::string CreateSignedAuthenticationToken(hello_world::AuthenticationToken const* authenticationToken, AsymmetricKey* signingKey) {
  std::string payload;

  if (!authenticationToken->SerializeToString(&payload)) {
    throw std::runtime_error("Failed to serialize payload");
  }

  std::stringstream stream;
  stream << BinaryToUrlBase64(payload) << '.';

  auto signer = signingKey->CreateSigner();

  signer->Update(payload);

  std::string signature;

  if (!signer->Finalize(signature)) {
    throw std::runtime_error("Failed to sign payload");
  }

  stream << BinaryToUrlBase64(signature);

  return stream.str();
}

std::shared_ptr<hello_world::AuthenticationToken> ParseAuthenticationToken(std::string_view value, AsymmetricKey* signingKey) {
  size_t dot1 = value.find('.');

  if (dot1 == std::string_view::npos) {
    spdlog::info("Invalid token");

    return nullptr;
  }

  std::string const payload = UrlBase64ToBinary(value.substr(0, dot1));

  auto verifier = signingKey->CreateVerifier();

  verifier->Update(payload);

  std::string const signature = UrlBase64ToBinary(value.substr(dot1 + 1));

  if (!verifier->Finalize(signature)) {
    spdlog::info("Signature mismatch");

    return nullptr;
  }

  auto token = std::make_shared<hello_world::AuthenticationToken>();

  if (!token->ParseFromString(payload)) {
    spdlog::info("Invalid payload");

    return nullptr;
  }

  if (token->has_not_after()) {
    if (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::utc_clock::now().time_since_epoch()).count() > token->not_after().seconds()) {
      spdlog::info("Token expired");

      return nullptr;
    }
  }

  return token;
}

std::shared_ptr<hello_world::AuthenticationToken> GetAuthenticationToken(grpc::ServerContextBase* context, AsymmetricKey* signingKey) {
  auto const& authMetadata = context->client_metadata();

  auto tokenPair = authMetadata.find("authorization");

  if (tokenPair == authMetadata.end()) {
    return nullptr;
  }

  auto const& value = tokenPair->second;

  if (!value.starts_with("Bearer ")) {
    spdlog::info("Authorization header is not a bearer");

    return nullptr;
  }

  auto authToken = ParseAuthenticationToken(std::string_view(tokenPair->second.data() + 7, tokenPair->second.size() - 7), signingKey);

  if (!authToken) {
    return nullptr;
  }

  return authToken;
}

grpc::Status Success() {
  return grpc::Status::OK;
}

grpc::Status Unauthenticated(std::string const& message) {
  return grpc::Status(grpc::UNAUTHENTICATED, message);
}

grpc::Status InternalError(std::string const& message) {
  return grpc::Status(grpc::INTERNAL, message);
}