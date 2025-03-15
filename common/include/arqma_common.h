#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <arqmamq/hex.h>

namespace arqma {

using namespace std::literals;

inline constexpr size_t MAINNET_USER_PUBKEY_SIZE = 66;
inline constexpr size_t STAGENET_USER_PUBKEY_SIZE = 64;

inline bool is_mainnet = true;

inline size_t get_user_pubkey_size() {
  return is_mainnet ? MAINNET_USER_PUBKEY_SIZE : STAGENET_USER_PUBKEY_SIZE;
}

class user_pubkey_t {
    std::string pubkey_;
    explicit user_pubkey_t(std::string pk) : pubkey_(std::move(pk)) {}

  public:
    user_pubkey_t() = default;
    explicit operator bool() const { return !pubkey_.empty(); }
    user_pubkey_t& load(std::string pk);
    const std::string& str() const { return pubkey_; }
    std::string_view key() const;
};

/// message as received by client
struct message_t {
    std::string pub_key;
    std::string data;
    std::string hash;
    std::chrono::system_clock::time_point timestamp;
    std::chrono::system_clock::time_point expiry;
};

using swarm_id_t = uint64_t;

constexpr swarm_id_t INVALID_SWARM_ID = UINT64_MAX;

} // namespace arqma
