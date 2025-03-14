#pragma once

#include "arqmad_key.h"
#include <string_view>
#include <arqma-mq/arqmamq.h>
#include <arqma-mq/hex.h>

namespace arqma {

using arqmad_seckeys = std::tuple<legacy_seckey, ed25519_seckey, x25519_seckey>;

arqmad_seckeys get_sn_privkeys(std::string_view arqmad_rpc_address);

}
