#pragma once

#include "arqma_common.h"
#include <array>
#include <chrono>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace arqma::rpc {

using namespace std::literals;

struct parse_error : std::runtime_error {
  using std::runtime_error::runtime_error;
};

struct endpoint {
  virtual void load_from(nlohmann::json params) = 0;
};

struct no_args : endpoint {
  void load_from(nlohmann::json) {}
};

namespace {
  template <size_t... N>
  constexpr std::array<std::string_view, sizeof...(N)> NAMES(const char (&...names)[N])
  {
    static_assert(sizeof...(N) > 0, "RPC command must have at least one name");
    return {std::string_view{names, N-1}...};
  }
}

struct store final : endpoint {
  static constexpr auto names() { return NAMES("store"); }

  inline static constexpr size_t MAX_MESSAGE_BODY = 76'800;

  user_pubkey_t pubkey;
  std::chrono::system_clock::time_point timestamp;
  std::chrono::system_clock::time_point expiry;
  std::string data;

  void load_from(nlohmann::json params) override;
};

struct retrieve final : endpoint
{
  static constexpr auto names() { return NAMES("retrieve"); }

  user_pubkey_t pubkey;
  std::optional<std::string> last_hash;

  void load_from(nlohmann::json params) override;
};

struct info final : no_args
{
  static constexpr auto names() { return NAMES("info"); }
};

struct get_swarm final : endpoint
{
  static constexpr auto names() { return NAMES("get_swarm", "get_snodes_for_pubkey"); }

  user_pubkey_t pubkey;

  void load_from(nlohmann::json params) override;
};

struct arqmad_request final : endpoint
{
  static constexpr auto names() { return NAMES("arqmad_request"); }

  std::string endpoint;
  std::optional<nlohmann::json> params;

  void load_from(nlohmann::json params) override;
};

template <typename...> struct type_list {};

using client_rpc_types = type_list<
  store,
  retrieve,
  get_swarm,
  arqmad_request,
  info
>;

}
