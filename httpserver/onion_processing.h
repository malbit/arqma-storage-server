#pragma once

#include <nlohmann/json_fwd.hpp>
#include <string>
#include <variant>
#include "arqmad_key.h"

namespace arqma {

inline constexpr int MAX_ONION_HOPS = 15;

using CiphertextPlusJson = std::pair<std::string, nlohmann::json>;

struct RelayToNodeInfo {
  std::string ciphertext;
  x25519_pubkey ephemeral_key;
  ed25519_pubkey next_node;
};

std::ostream& operator<<(std::ostream& os, const RelayToNodeInfo& p);

bool operator==(const RelayToNodeInfo& lhs, const RelayToNodeInfo& rhs);

struct RelayToServerInfo {
  std::string payload;
  std::string host;
  uint16_t port;
  std::string protocol;
  std::string target;
};

std::ostream& operator<<(std::ostream& os, const RelayToServerInfo& p);

bool operator==(const RelayToServerInfo& lhs, const RelayToServerInfo& rhs);

struct FinalDestinationInfo {
  std::string body;
  bool json = false;
  bool base64 = true;
};

std::ostream& operator<<(std::ostream& os, const FinalDestinationInfo& p);

bool operator==(const FinalDestinationInfo & lhs, const FinalDestinationInfo& rhs);

enum class ProcessCiphertextError {
  INVALID_CIPHERTEXT,
  INVALID_JSON,
};

using ParsedInfo = std::variant<RelayToNodeInfo, RelayToServerInfo, FinalDestinationInfo, ProcessCiphertextError>;

ParsedInfo process_ciphertext_v2(const ChannelEncryption& decryptor, std::string_view ciphertext, const x25519_pubkey& ephem_key, EncryptType enc_type);

auto parse_combined_payload(std::string_view payload) -> CiphertextPlusJson;

auto process_inner_request(std::string plaintext) -> ParsedInfo;

bool is_onion_url_target_allowed(std::string_view url);

}