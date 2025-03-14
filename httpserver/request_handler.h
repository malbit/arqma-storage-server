#pragma once

#include "channel_encryption.hpp"
#include "http.h"
#include "onion_processing.h"
#include "arqma_common.h"
#include "arqmad_key.h"
#include "service_node.h"
#include "string_utils.hpp"
#include <chrono>
#include <forward_list>
#include <future>
#include <string>
#include <string_view>

#include <nlohmann/json_fwd.hpp>

namespace arqma {

constexpr size_t MAX_MESSAGE_BODY = 102400;

inline constexpr auto TEST_RETRY_INTERVAL = 50ms;
inline constexpr auto TEST_RETRY_PERIOD = 55s;

struct Response {
  http::response_code status = http::OK;
  std::string body;
  std::string_view content_type = http::plaintext;
  std::vector<std::pair<std::string, std::string>> headers;
};

std::string to_string(const Response& res);

std::string computeMessageHash(std::vector<std::string_view> parts, bool hex);

struct OnionRequestMetadata {
  x25519_pubkey ephem_key;
  std::function<void(Response)> cb;
  int hop_no = 0;
  EncryptType enc_type = EncryptType::aes_gcm;
};

class RequestHandler {
  ServiceNode& service_node_;
  const ChannelEncryption& channel_cipher_;

  std::forward_list<std::future<void>> pending_proxy_requests_;

  // Wrap response `res` to an intermediate node
  Response wrap_proxy_response(Response res, const x25519_pubkey& client_key, EncryptType enc_type, bool json = false, bool base64 = true) const;
  // Return the correct swarm for `pubKey`
  Response handle_wrong_swarm(const user_pubkey_t& pubKey);
  // ===== Session Client Requests =====
  // Similar to `handle_wrong_swarm`; but used when the swarm is requested explicitly
  Response process_snodes_by_pk(const nlohmann::json& params) const;
    // Save the message and relay the swarm
  Response process_store(const nlohmann::json& params);
  // Query the database and return requested messages
  Response process_retrieve(const nlohmann::json& params);
  void process_onion_exit(std::string_view payload, std::function<void(Response)> cb);
  // ===================================
public:
  RequestHandler(ServiceNode& sn, const ChannelEncryption& ce);
  // Process all Session client requests
  void process_client_req(std::string_view req_json, std::function<void(Response)> cb);

  void process_storage_test_req(uint64_t height, legacy_pubkey tester, std::string msg_hash_hex, std::function<void(MessageTestStatus, std::string, std::chrono::steady_clock::duration)> callback);
  // Test only: retrieve all db entires
  Response process_retrieve_all();
  // Handle a Session client reqeust sent via SN proxy
  void process_proxy_exit(const x25519_pubkey& client_key, std::string_view payload, std::function<void(Response)> cb);

  // The result will arrive asynchronously, so it needs a callback handler
  void process_onion_req(std::string_view ciphertext, OnionRequestMetadata data);

private:
  void process_onion_req(FinalDestinationInfo&& res, OnionRequestMetadata&& data);
  void process_onion_req(RelayToNodeInfo&& res, OnionRequestMetadata&& data);
  void process_onion_req(RelayToServerInfo&& res, OnionRequestMetadata&& data);
  void process_onion_req(ProcessCiphertextError&& res, OnionRequestMetadata&& data);
};

}