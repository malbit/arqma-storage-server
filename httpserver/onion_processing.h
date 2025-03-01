#pragma once

#include <string>
#include <variant>
#include "arqmad_key.h"

namespace arqma {

struct CiphertextPlusJson {
  std::string ciphertext;
  std::string json;
};

struct RelayToNodeInfo {
  std::string ciphertext;
  std::string ephemeral_key;
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
};

std::ostream& operator<<(std::ostream& os, const FinalDestinationInfo& p);

bool operator==(const FinalDestinationInfo & lhs, const FinalDestinationInfo& rhs);

enum class ProcessCiphertextError {
  INVALID_CIPHERTEXT,
  INVALID_JSON,
};

using ParsedInfo = std::variant<RelayToNodeInfo, RelayToServerInfo, FinalDestinationInfo, ProcessCiphertextError>;

auto parse_combined_payload(const std::string& payload) -> CiphertextPlusJson;

auto process_inner_request(const CiphertextPlusJson& parsed, std::string plaintext) -> ParsedInfo;
