#pragma once

#include <string>
#include <string_view>
#include "arqmad_key.h"

namespace arqma {

enum class EncryptType {
  aes_cbc,
  aes_gcm,
};

EncryptType parse_enc_type(std::string_view enc_type);

inline constexpr std::string_view to_string(EncryptType type)
{
  switch (type)
  {
    case EncryptType::aes_gcm: return "aes-gcm"sv;
    case EncryptType::aes_cbc: return "aes-cbc"sv;
  }
  return ""sv;
}

class ChannelEncryption {
  public:
    ChannelEncryption(x25519_seckey private_key)
      : private_key_{std::move(private_key)} {}

    std::string encrypt(EncryptType type, std::string_view plaintext, const x25519_pubkey& pubkey) const;
    std::string decrypt(EncryptType type, std::string_view ciphertext, const x25519_pubkey& pubkey) const;

    std::string encrypt_cbc(std::string_view plainText, const x25519_pubkey& pubKey) const;

    std::string encrypt_gcm(std::string_view plainText, const x25519_pubkey& pubKey) const;

    std::string decrypt_cbc(std::string_view cipherText, const x25519_pubkey& pubKey) const;

    std::string decrypt_gcm(std::string_view cipherText, const x25519_pubkey& pubKey) const;

  private:
    const x25519_seckey private_key_;
};

}