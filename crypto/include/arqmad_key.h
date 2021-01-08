#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace arqma {

constexpr size_t KEY_LENGTH = 32;
using public_key_t = std::array<uint8_t, KEY_LENGTH>;
using private_key_t = std::array<uint8_t, KEY_LENGTH>;

struct arqmad_key_pair_t {
    private_key_t private_key;
    public_key_t public_key;
};

private_key_t parseArqmadKey(const std::string& path);

public_key_t calcPublicKey(const private_key_t& private_key);

} // namespace arqma
