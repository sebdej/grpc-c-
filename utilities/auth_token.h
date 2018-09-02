#ifndef _AUTH_TOKEN_H_
#define _AUTH_TOKEN_H_

#include <string>
#include <vector>
#include <grpcpp/grpcpp.h>

#include <hello_world.pb.h>
#include <utilities/crypto.h>

std::string CreateAuthenticationToken(std::string const& username, std::vector<std::string> const& roles, AsymmetricKey* signingKey);
std::string CreateSignedAuthenticationToken(hello_world::AuthenticationToken const* authenticationToken, AsymmetricKey* signingKey);
std::shared_ptr<hello_world::AuthenticationToken> ParseAuthenticationToken(std::string_view value, AsymmetricKey* signingKey);
std::shared_ptr<hello_world::AuthenticationToken> GetAuthenticationToken(grpc::ServerContextBase* context, AsymmetricKey* signingKey);

grpc::Status Success();
grpc::Status Unauthenticated(std::string const& message = "Unauthenticated");
grpc::Status InternalError(std::string const& message = "Internal error");


#endif
