#pragma once

#include "arqmad_key.h"

#include <array>

namespace arqma {

constexpr size_t HASH_SIZE = 32;
constexpr size_t EC_SCALAR_SIZE = 32;

using hash = std::array<unsigned char, HASH_SIZE>;
using ec_scalar = std::array<unsigned char, EC_SCALAR_SIZE>;

struct signature {
  ec_scalar c, r;

  static signature from_base64(std::string_view b64);
};

hash hash_data(std::string_view data);

signature generate_signature(const hash& prefix_hash, const legacy_keypair& keys);

bool check_signature(const signature& sig, const hash& prefix_hash, const legacy_pubkey& pub);

} // namespace arqma
