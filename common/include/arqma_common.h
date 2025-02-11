#pragma once

#include "spdlog/fmt/ostr.h" // for operator<< overload

#include <cstdint>
#include <ostream>
#include <string>
#include <vector>

#include <boost/optional.hpp>

using sn_pub_key_t = std::string;

struct sn_record_t {

    // our 32 byte pub keys should always be 52 bytes long in base32z
    static constexpr size_t BASE_LEN = 52;

  private:
    uint16_t port_;
    std::string sn_address_; // Snode address
    std::string pub_key_base_32z_;
    std::string pubkey_x25519_hex_;
    std::string pubkey_ed25519_hex_;
    std::string pub_key_hex_;
    std::string ip_; // Snode ip

    /// Set service node's public key in base32z (without .snode part)
    void set_address(const std::string& addr) {

        if (addr.size() != BASE_LEN)
            throw std::runtime_error("snode public key has incorrect size");

        sn_address_ = addr;
        sn_address_.append(".snode");
        pub_key_base_32z_ = addr;
    }

  public:
    sn_record_t(uint16_t port, const std::string& address, const std::string& pk_hex,
                const std::string& pk_x25519, const std::string& pk_ed25519, const std::string& ip)
      : port_(port), pub_key_hex_(pk_hex), pubkey_x25519_hex_(pk_x25519),
        pubkey_ed25519_hex_(pk_ed25519), ip_(ip) {
      set_address(address);
    }

    sn_record_t() = default;

    void set_ip(const std::string& ip) { ip_ = ip; }

    uint16_t port() const { return port_; }
    const std::string& sn_address() const { return sn_address_; }
    const std::string& pub_key_base32z() const { return pub_key_base_32z_; }
    const std::string& pub_key_hex() const { return pub_key_hex_; }
    const std::string& pubkey_x25519_hex() const { return pubkey_x25519_hex_; }
    const std::string& pubkey_ed25519_hex() const { return pubkey_ed25519_hex_; }
    const std::string& ip() const { return ip_; }

    template <typename OStream>
    friend OStream& operator<<(OStream& os, const sn_record_t& record) {
#ifdef INTEGRATION_TEST
        os << record.port();
#else
        os << record.sn_address();
#endif
    }
};

namespace arqma {

constexpr size_t MAINNET_USER_PUBKEY_SIZE = 64;
constexpr size_t STAGENET_USER_PUBKEY_SIZE = 64;

struct net_type_t {
  static net_type_t& get_instance() {
    static net_type_t net_type;
    return net_type;
  }

  void set_stagenet() { is_mainnet_ = false; }
  bool is_mainnet() { return is_mainnet_; }

private:
  bool is_mainnet_ = true;
  net_type_t() = default;
};

inline bool is_mainnet() {
  return net_type_t::get_instance().is_mainnet();
}

inline void set_stagenet() {
  net_type_t::get_instance().set_stagenet();
}

inline size_t get_user_pubkey_size() {
  if (arqma::is_mainnet()) {
    return MAINNET_USER_PUBKEY_SIZE;
  } else {
    return STAGENET_USER_PUBKEY_SIZE;
  }
}

class user_pubkey_t {
    std::string pubkey_;
    user_pubkey_t() {}
    user_pubkey_t(std::string&& pk) : pubkey_(std::move(pk)) {}
    user_pubkey_t(const std::string& pk) : pubkey_(pk) {}

  public:
    static user_pubkey_t create(std::string&& pk, bool& success) {
        success = true;
        if (pk.size() != get_user_pubkey_size()) {
            success = false;
            return {};
        }
        return user_pubkey_t(std::move(pk));
    }

    static user_pubkey_t create(const std::string& pk, bool& success) {
        success = true;
        if (pk.size() != get_user_pubkey_size()) {
            success = false;
            return {};
        }
        return user_pubkey_t(pk);
    }

    const std::string& str() const { return pubkey_; }
};

/// message as received by client
struct message_t {

    std::string pub_key;
    std::string data;
    std::string hash;
    uint64_t ttl;
    uint64_t timestamp;
    std::string nonce;

    message_t(const std::string& pk, const std::string& text,
              const std::string& hash, uint64_t ttl, uint64_t timestamp)
        : pub_key(pk), data(text), hash(hash), ttl(ttl), timestamp(timestamp) {}
};

} // namespace arqma

namespace std {

template <>
struct hash<sn_record_t> {
    std::size_t operator()(const sn_record_t& k) const {
        return hash<std::string>{}(k.pub_key_hex());
    }
};

} // namespace std

inline bool operator<(const sn_record_t& lhs, const sn_record_t& rhs) {
    return lhs.pub_key_hex() < rhs.pub_key_hex();
}

static std::ostream& operator<<(std::ostream& os, const sn_record_t& sn) {
#ifdef INTEGRATION_TEST
    return os << sn.port();
#else
    return os << sn.sn_address();
#endif
}

static bool operator==(const sn_record_t& lhs, const sn_record_t& rhs) {
  return lhs.pub_key_hex() == rhs.pub_key_hex();
}

static bool operator!=(const sn_record_t& lhs, const sn_record_t& rhs) {
    return !operator==(lhs, rhs);
}

using swarm_id_t = uint64_t;

constexpr swarm_id_t INVALID_SWARM_ID = UINT64_MAX;
