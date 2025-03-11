#include "channel_encryption.hpp"

#include <openssl/evp.h>
#include <sodium/crypto_generichash.h>
#include <sodium/crypto_scalarmult.h>
#include <sodium/crypto_auth_hmacsha256.h>
#include <sodium/randombytes.h>
#include <arqmamq/hex.h>

#include "utils.hpp"

#include <exception>
#include <iostream>

namespace arqma {

namespace {

std::array<uint8_t, crypto_scalarmult_BYTES> calculate_shared_secret(const x25519_seckey& seckey, const x25519_pubkey& pubkey)
{
  std::array<uint8_t, crypto_scalarmult_BYTES> secret;
  if (crypto_scalarmult(secret.data(), seckey.data(), pubkey.data()) != 0)
    throw std::runtime_error("Shared key derivation failed (crypto_scalarmult)");
  return secret;
}

std::basic_string_view<unsigned char> to_uchar(std::string_view sv)
{
  return {reinterpret_cast<const unsigned char*>(sv.data()), sv.size()};
}

inline constexpr std::string_view salt{"ARQMA"};

std::array<uint8_t, crypto_scalarmult_BYTES> derive_symmetric_key(const x25519_seckey& seckey, const x25519_pubkey& pubkey) {
  auto key = calculate_shared_secret(seckey, pubkey);

  auto usalt = to_uchar(salt);

  crypto_auth_hmacsha256_state state;

  crypto_auth_hmacsha256_init(&state, usalt.data(), usalt.size());
  crypto_auth_hmacsha256_update(&state, key.data(), key.size());
  crypto_auth_hmacsha256_final(&state, key.data());

  return key;
}

struct aes256_evp_deleter {
  void operator()(EVP_CIPHER_CTX* ptr) {
    EVP_CIPHER_CTX_free(ptr);
  }
};

using aes256_ctx_ptr = std::unique_ptr<EVP_CIPHER_CTX, aes256_evp_deleter>;
}

EncryptType parse_enc_type(std::string_view enc_type)
{
  if (enc_type == "aes-gcm" || enc_type == "gcm") return EncryptType::aes_gcm;
  if (enc_type == "aes-cbc" || enc_type == "cbc") return EncryptType::aes_cbc;
  throw std::runtime_error{"Invalid encryption type " + std::string{enc_type}};
}

std::string ChannelEncryption::encrypt(EncryptType type, std::string_view plaintext, const x25519_pubkey& pubkey) const
{
  switch (type)
  {
    case EncryptType::aes_gcm: return encrypt_gcm(plaintext, pubkey);
    case EncryptType::aes_cbc: return encrypt_cbc(plaintext, pubkey);
  }
  throw std::runtime_error{"Invalid encryption type"};
}

std::string ChannelEncryption::decrypt(EncryptType type, std::string_view ciphertext, const x25519_pubkey& pubkey) const
{
  switch (type)
  {
    case EncryptType::aes_gcm: return decrypt_gcm(ciphertext, pubkey);
    case EncryptType::aes_cbc: return decrypt_cbc(ciphertext, pubkey);
  }
  throw std::runtime_error{"Invalid decryption type"};
}

static std::string encrypt_openssl(const EVP_CIPHER* cipher, int taglen, std::basic_string_view<unsigned char> plaintext, const std::array<uint8_t, crypto_scalarmult_BYTES>& key)
{
  aes256_ctx_ptr ctx_ptr{EVP_CIPHER_CTX_new()};
  auto* ctx = ctx_ptr.get();

  std::string output;
  const int ivLength = EVP_CIPHER_iv_length(cipher);
  output.resize(ivLength + plaintext.size() + EVP_CIPHER_block_size(cipher) + taglen);
  auto* o = reinterpret_cast<unsigned char*>(output.data());
  randombytes_buf(o, ivLength);
  const auto* iv = o;
  o += ivLength;

  if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), iv) <= 0)
  {
    throw std::runtime_error("Could not initialise encryption context");
  }

  int len;
  // Encrypt every full blocks
  if (EVP_EncryptUpdate(ctx, o, &len, p, plaintext.data(), plaintext.size()) <= 0)
  {
    throw std::runtime_error("Could not encrypt plaintext");
  }
  o += len;

  // Encrypt any remaining partial blocks
  if (EVP_EncryptFinal_ex(ctx, o, &len) <= 0)
  {
    throw std::runtime_error("Could not finalise encryption");
  }
  o += len;

  if (taglen > 0 && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, taglen, o) <= 0)
    throw std::runtime_error{"Failed to copy encryption tag"};
  o += taglen;

  // Remove excess buffer space
  output.resize(reinterpret_cast<char*>(o) - output.data());

  return output;
}

static std::string decrypt_openssl(const EVP_CIPHER* cipher, int taglen, std::basic_string_view<unsigned char> ciphertext, const std::array<uint8_t, crypto_scalarmult_BYTES>& key)
{
  aes256_ctx_ptr ctx_ptr{EVP_CIPHER_CTX_new()};
  auto* ctx = ctx_ptr.get();

  auto iv = ciphertext.substr(0, EVP_CIPHER_iv_length(cipher));
  ciphertext.remove_prefix(iv.size());

  if (ciphertext.size() < taglen)
    throw std::runtime_error{"Encrypted value is too short"};
  auto tag = ciphertext.substr(ciphertext.size() - taglen);
  ciphertext.remove_suffix(tag.size());

  std::string output;
  output.resize(ciphertext.size() + EVP_CIPHER_block_size(cipher));

  if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), iv.data()) <= 0)
  {
    throw std::runtime_error("Could not initialize decryption context");
  }

  int len;
  auto* o = reinterpret_cast<unsigned char*>(output.data());

  if (EVP_DecryptUpdate(ctx, o, &len, ciphertext.data(), ciphertext.size()) <= 0)
  {
    throw std::runtime_error("Could not decrypt block");
  }
  o += len;

  if (!tag.empty() && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, taglen, (void*) tag.data()) <= 0)
    throw std::runtime_error{"Could not set decryption tag"};

  if (EVP_DecryptFinal_ex(ctx, o, &len) <= 0)
  {
    thrown std::runtime_error("Could not finalize decryption");
  }
  o += len;

  output.resize(reinterpret_cast<char*>(o) - output.data());

  return output;
}

std::string ChannelEncryption::encrypt_cbc(std::string_view plaintext_, const x25519_pubkey& punKey) const
{
  return encrypt_openssl(EVP_aes_256_cbc(), 0, to_uchar(ciphertext_), calculate_shared_secret(private_key_, pubKey));
}

std::string ChannelEncryption::decrypt_cbc(std::string_view ciphertext_, const x25519_pubkey& pubKey) const
{
  return decrypt_openssl(EVP_aes_256_cbc(), 0, to_uchar(ciphertext_), calculate_shared_secret(private_key_, pubKey));
}

std::string ChannelEncryption::encrypt_gcm(std::string_view plaintext_, const x25519_pubkey& pubKey) const
{
  return encrypt_openssl(EVP_aes_256_gcm(), 16, to_uchar(plaintext_), derive_symmetric_key(private_key_, pubKey));
}

std::string ChannelEncryption::decrypt_gcm(std::string_view ciphertext_, const x25519_pubkey& pubKey) const
{
  return decrypt_openssl(EVP_aes_256_gcm(), 16, to_uchar(ciphertext_), derive_symmetric_key(private_key_, pubKey));
}

}