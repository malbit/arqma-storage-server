#include "signature.h"
#include "utils.hpp"

extern "C" {
#include "arqma/crypto-ops/hash-ops.h"
}

#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_generichash.h>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>
#include <arqmamq/base32z.h>
#include <arqmamq/base64.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring> // for memcmp
#include <iterator>
#include <string>

static_assert(crypto_generichash_BYTES == arqma::HASH_SIZE, "Wrong hash size!");

namespace arqma {

using ec_point = std::array<unsigned char, 32>;
struct s_comm {
    unsigned char h[32];
    unsigned char key[32];
    unsigned char comm[32];
};

static ec_scalar monero_hash_to_scalar(const void* input, size_t size)
{
  unsigned char hash[64] = {0};
  cn_fast_hash(input, size, reinterpret_cast<char*>(hash));
  ec_scalar result;
  crypto_core_ed25519_scalar_reduce(result.data(), hash);
  return result;
}

hash hash_data(std::string_view data) {
    hash hash;
    crypto_generichash(hash.data(), hash.size(), reinterpret_cast<const unsigned char*>(data.data()), data.size(), nullptr, 0);
    return hash;
}

template <typename... T, typename Array = std::array<unsigned char, (sizeof(T) + ...)>>
static Array concatenate(const T&... v)
{
  static_assert((std::is_trivial_v<T> && ...));
  Array result;
  unsigned char* ptr = result.data();
  (
   (std::memcpy(ptr, reinterpret_cast<const void*>(&v), sizeof(T)), ptr += sizeof(T)),
   ...
  );
  return result;
}

template <size_t S, typename... T>
static std::array<unsigned char, S> hash_concatenate(const T&... v)
{
  std::array<unsigned char, S> h;
  crypto_generichash_state state;
  crypto_generichash_init(&state, nullptr, 0, h.size());
  (
   crypto_generichash_update(&state, reinterpret_cast<const unsigned char*>(&v), sizeof(T)),
   ...
  );
  crypto_generichash_final(&state, h.data(), h.size());
  return h;
}

void clamp(ec_scalar& s)
{
  s[0] &= 248;
  s[31] &= 63;
  s[31] |= 64;
}

signature generate_signature(const hash& prefix_hash, const legacy_keypair& keys)
{
    signature sig;
    const auto& [pubkey, seckey] = keys;
    crypto_generichash(sig.r.data(), sig.r.size(), seckey.data(), seckey.size(), nullptr, 0);
    auto xH = hash_concatenate<64>(sig.r, pubkey, prefix_hash);

    ec_scalar x;
    crypto_core_ed25519_scalar_reduce(x.data(), xH.data());
    clamp(x);

    ec_point X;
    crypto_scalarmult_ed25519_base_noclamp(X.data(), x.data());
    auto M_A_X = concatenate(prefix_hash, pubkey, X);
    sig.c = monero_hash_to_scalar(M_A_X.data(), M_A_X.size());
    crypto_core_ed25519_scalar_mul(sig.r.data(), seckey.data(), sig.c.data());
    crypto_core_ed25519_scalar_sub(sig.r.data(), x.data(), sig.r.data());
    return sig;
}

bool check_signature(const signature& sig, const hash& prefix_hash, const legacy_pubkey& pub)
{
  ec_point X, cA;
  if (0 != crypto_scalarmult_ed25519_base_noclamp(X.data(), sig.r.data()))
    return false;
  if (0 != crypto_scalarmult_ed25519_noclamp(cA.data(), sig.c.data(), pub.data()))
    return false;
  if (0 != crypto_core_ed25519_add(X.data(), X.data(), cA.data()))
    return false;
  if (1 != crypto_core_ed25519_is_valid_point(X.data()))
    return false;

  auto M_A_X = concatenate(prefix_hash, pub, X);
  auto expected_c = monero_hash_to_scalar(M_A_X.data(), M_A_X.size());
  return 0 == sodium_memcmp(expected_c.data(), sig.c.data(), expected_c.size());
}

signature signature::from_base64(std::string_view signature_b64)
{
    if (!arqmamq::is_base64(signature_b64))
      throw std::runtime_error{"Invalid data: not base64-encoded"};

    // 64 bytes bytes -> 86/88 base64 encoded bytes with/without padding
    if (!(signature_b64.size() == 86 || (signature_b64.size() == 88 && signature_b64.substr(86) == "==")))
      throw std::runtime_error{"Invalid data: b64 data size does not match signature size"};

    // convert signature
    signature sig;
    static_assert(sizeof(sig) == 64);
    arqmamq::from_base64(signature_b64.begin(), signature_b64.end(), reinterpret_cast<unsigned char*>(&sig));
    return sig;
}

} // namespace arqma
