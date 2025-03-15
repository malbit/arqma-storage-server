#pragma once

#include "channel_encryption.hpp"
#include "client_rpc_endpoints.h"
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
#include <type_traits>

#include <nlohmann/json_fwd.hpp>

namespace arqma {

inline constexpr auto TEST_RETRY_INTERVAL = 50ms;
inline constexpr auto TEST_RETRY_PERIOD = 55s;
inline constexpr auto TTL_MINIMUM = 10s;
inline constexpr auto TTL_MAXIMUM = 14 * 24h;

struct Response {
  http::response_code status = http::OK;
  std::string body;
  std::string_view content_type = http::plaintext;
  std::vector<std::pair<std::string, std::string>> headers;
};

std::string to_string(const Response& res);

namespace detail {

template <typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
std::string_view to_hashable(const T& val, char*& buffer)
{
  auto [p, ec] = std::to_chars(buffer, buffer+20, val);
  std::string_view s(buffer, p-buffer);
  buffer = p;
  return s;
}
inline std::string_view to_hashable(const std::chrono::system_clock::time_point& val, char*& buffer)
{
  return to_hashable(std::chrono::duration_cast<std::chrono::milliseconds>(val.time_since_epoch()).count(), buffer);
}
template <typename T, std::enable_if_t<std::is_convertible_v<T, std::string_view>, int> = 0>
std::string_view to_hashable(const T& value, char*&)
{
  return value;
}

}

std::string computeMessageHash(std::vector<std::string_view> parts);

template <typename... T>
std::string computeMessageHash(const T&... args)
{
  std::array<char, (0 + ... + (std::is_integral_v<T> || std::is_same_v<T, std::chrono::system_clock::time_point> ? 20 : 0))> buffer;
  auto* b = buffer.data();
  return computeMessageHash({detail::to_hashable(args, b)...});
}

bool validateTTL(std::chrono::system_clock::duration ttl);

bool validateTimestamp(std::chrono::system_clock::time_point timestamp, std::chrono::system_clock::time_point expiry);

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
  // ===================================
public:
  RequestHandler(ServiceNode& sn, const ChannelEncryption& ce);

  void process_client_req(rpc::store&& req, std::function<void(Response)> cb);
  void process_client_req(rpc::retrieve&& req, std::function<void(Response)> cb);
  void process_client_req(rpc::get_swarm&& req, std::function<void(Response)> cb);
  void process_client_req(rpc::arqmad_request&& req, std::function<void(Response)> cb);
  void process_client_req(rpc::info&&, std::function<void(Response)> cb);

  using rpc_map = std::unordered_map<
    std::string_view,
    std::function<void(RequestHandler&, const nlohmann::json&, std::function<void(Response)>)>
  >;
  static const rpc_map client_rpc_endpoints;

  void process_client_req(std::string_view req_json, std::function<void(Response)> cb);
  void process_client_req(std::string_view method, nlohmann::json params, std::function<void(Response)> cb);

  void process_storage_test_req(uint64_t height, legacy_pubkey tester, std::string msg_hash_hex, std::function<void(MessageTestStatus, std::string, std::chrono::steady_clock::duration)> callback);
  // Test only: retrieve all db entires
  Response process_retrieve_all();
  // The result will arrive asynchronously, so it needs a callback handler
  void process_onion_req(std::string_view ciphertext, OnionRequestMetadata data);

private:
  void process_onion_req(FinalDestinationInfo&& res, OnionRequestMetadata&& data);
  void process_onion_req(RelayToNodeInfo&& res, OnionRequestMetadata&& data);
  void process_onion_req(RelayToServerInfo&& res, OnionRequestMetadata&& data);
  void process_onion_req(ProcessCiphertextError&& res, OnionRequestMetadata&& data);
};

}