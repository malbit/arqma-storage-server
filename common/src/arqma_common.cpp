#include "arqma_common.h"
#include <arqmamq/hex.h>

namespace arqma {

user_pubkey_t& user_pubkey_t::load(std::string pk)
{
  if (pk.size() == get_user_pubkey_size() && arqmamq::is_hex(pk))
    pubkey_ = std::move(pk);
  else
    pubkey_.clear();
  return *this;
}

std::string_view user_pubkey_t::key() const
{
  std::string_view r{pubkey_};
  if (is_mainnet)
    r.remove_prefix(2);
  return r;
}

}
