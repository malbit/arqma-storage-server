#pragma once

#include <cstdint>
#include <string>
#include "arqmad_key.h"

namespace arqma {

struct sn_record_t {
  std::string ip;
  uint16_t port{0};
  uint16_t arqmq_port{0};
  legacy_pubkey pubkey_legacy{};
  ed25519_pubkey pubkey_ed25519{};
  x25519_pubkey pubkey_x25519{};
};

inline bool operator==(const sn_record_t& lhs, const sn_record_t& rhs)
{
  return lhs.pubkey_legacy == rhs.pubkey_legacy;
}

inline bool operator!=(const sn_record_t& lhs, const sn_record_t& rhs)
{
  return !(lhs == rhs);
}

}
