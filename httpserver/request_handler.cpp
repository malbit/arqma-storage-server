#include "request_handler.h"
#include "channel_encryption.hpp"
#include "http.h"
#include "arqmamq_server.h"
#include "arqma_logger.h"
#include "signature.h"
#include "service_node.h"
#include "string_utils.hpp"
#include "utils.hpp"

#include <chrono>
#include <cpr/cpr.h>
#include <future>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <arqmamq/base32z.h>
#include <arqmamq/base64.h>
#include <arqmamq/hex.h>

using nlohmann::json;

namespace arqma {

inline constexpr auto ONION_URL_TIMEOUT = 25s;

std::string to_string(const Response& res) {

    std::stringstream ss;

    ss << "Status: " << res.status.first << " " << res.status.second
       << ", ContentType: " << (res.content_type.empty() ? "(unspecified)" : res.content_type)
       << ", Body: <" << res.body << ">";

    return ss.str();
}

namespace {

json snodes_to_json(const std::vector<sn_record_t>& snodes)
{
    json res_body;
    json snodes_json = json::array();

    for (const auto& sn : snodes) {
      snodes_json.push_back(json{
        {"address", arqmamq::to_base32z(sn.pubkey_legacy.view()) + ".snode"},
        {"pubkey_legacy", sn.pubkey_legacy.hex()},
        {"pubkey_x25519", sn.pubkey_x25519.hex()},
        {"pubkey_ed25519", sn.pubkey_ed25519.hex()},
        {"port", std::to_string(sn.port)},
        {"ip", sn.ip}});
    }

    res_body["snodes"] = std::move(snodes_json);

    return res_body;
}

std::string obfuscate_pubkey(std::string_view pk)
{
    std::string res;
    res += pk.substr(0, 2);
    res += "...";
    res += pk.substr(pk.length() - 3);
    return res;
}

}

std::string computeMessageHash(std::vector<std::string_view> parts, bool hex)
{
  SHA512_CTX ctx;
  SHA512_Init(&ctx);
  for (const auto& s : parts)
    SHA512_Update(&ctx, s.data(), s.size());

  std::string hashResult;
  hashResult.resize(SHA512_DIGEST_LENGTH);
  SHA512_Final(reinterpret_cast<unsigned char*>(hashResult.data()), &ctx);
  if (hex)
    hashResult = arqmamq::to_hex(hashResult);
  return hashResult;
}

RequestHandler::RequestHandler(ServiceNode& sn, const ChannelEncryption& ce) : service_node_{sn}, channel_cipher_(ce)
{
  service_node_.arqmq_server()->add_timer([this] {
    pending_proxy_requests_.remove_if(
      [](auto& f) { return f.wait_for(0ms) == std::future_status::ready; });
  }, 1s);
}

Response RequestHandler::handle_wrong_swarm(const user_pubkey_t& pubKey)
{
  ARQMA_LOG(trace, "Got client request to a wrong swarm");
  return {http::MISDIRECTED_REQUEST, snodes_to_json(service_node_.get_snodes_by_pk(pubKey)).dump(), http::json};
}

Response RequestHandler::process_store(const json& params)
{
    for (const auto& field : {"pubKey", "ttl", "timestamp", "data"})
    {
        if (!params.contains(field))
        {
            ARQMA_LOG(debug, "Bad client request: no `{}` field", field);
            return {http::BAD_REQUEST, fmt::format("invalid json: no `{}` field\n", field)};
        }
    }

    const auto& ttl = params.at("ttl").get_ref<const std::string&>();
    const auto& timestamp = params.at("timestamp").get_ref<const std::string&>();
    const auto& data = params.at("data").get_ref<const std::string&>();

    ARQMA_LOG(trace, "Storing message: {}", data);

    bool created;
    auto pk =
        user_pubkey_t::create(params.at("pubKey").get<std::string>(), created);

    if (!created) {
        auto msg = fmt::format("Pubkey must be {} characters long\n",
                                  get_user_pubkey_size());
        ARQMA_LOG(debug, "{}", msg);
        return {http::BAD_REQUEST, std::move(msg)};
    }

    if (data.size() > MAX_MESSAGE_BODY) {
        ARQMA_LOG(debug, "Message body too long: {}", data.size());

        auto msg = fmt::format("Message body exceeds maximum allowed length of {}\n",
                        MAX_MESSAGE_BODY);
        return {http::BAD_REQUEST, std::move(msg)};
    }

    if (!service_node_.is_pubkey_for_us(pk)) {
        return this->handle_wrong_swarm(pk);
    }

    uint64_t ttlInt;
    if (!util::parseTTL(ttl, ttlInt)) {
        ARQMA_LOG(debug, "Forbidden. Invalid TTL: {}", ttl);
        return {http::FORBIDDEN, "Provided TTL is not valid.\n"};
    }

    uint64_t timestampInt;
    if (!util::parseTimestamp(timestamp, ttlInt, timestampInt)) {
        ARQMA_LOG(debug, "Forbidden. Invalid Timestamp: {}", timestamp);
        return {http::NOT_ACCEPTABLE, "Timestamp error: check your clock\n"};
    }

    auto messageHash = computeMessageHash({timestamp, ttl, pk.str(), data}, true;
    bool success;

    try {
        success = service_node_.process_store({pk.str(), data, messageHash, ttlInt, timestampInt});
    } catch (const std::exception e) {
        ARQMA_LOG(critical,
                 "Internal Server Error. Could not store message for {}",
                 obfuscate_pubkey(pk.str()));
        return {http::INTERNAL_SERVER_ERROR, e.what()};
    }

    if (!success) {

        ARQMA_LOG(warn, "Service node is initializing");
        return {http::SERVICE_UNAVAILABLE, "Service node is initializing\n"};
    }

    ARQMA_LOG(trace, "Successfully stored message for {}",
             obfuscate_pubkey(pk.str()));

    json res_body;
    res_body["difficulty"] = 1;

    return {http::OK, res_body.dump(), http::json};
}

Response RequestHandler::process_retrieve_all() {

    std::vector<storage::Item> all_entries;

    bool res = service_node_.get_all_messages(all_entries);

    if (!res) {
        return {http::INTERNAL_SERVER_ERROR, "could not retrieve all entries\n"};
    }

    json messages = json::array();

    for (auto& entry : all_entries) {
        json item;
        item["data"] = entry.data;
        item["pk"] = entry.pub_key;
        messages.push_back(item);
    }

    json res_body;
    res_body["messages"] = messages;

    return {http::OK, res_body.dump(), http::json};
}

Response RequestHandler::process_snodes_by_pk(const json& params) const
{
    auto it = params.find("pubKey");
    if (it == params.end())
    {
        ARQMA_LOG(debug, "Bad client request: no `pubKey` field");
        return {http::BAD_REQUEST, "invalid json: no `pubKey` field\n"};
    }

    bool success;
    const auto pk =
        user_pubkey_t::create(params.at("pubKey").get<std::string>(), success);
    if (!success) {

        auto msg = fmt::format("Pubkey must be {} characters long\n",
                               get_user_pubkey_size());
        ARQMA_LOG(debug, "{}", msg);
        return {http::BAD_REQUEST, std::move(msg)};
    }

    const std::vector<sn_record_t> nodes = service_node_.get_snodes_by_pk(pk);

    ARQMA_LOG(debug, "Snodes by pk size: {}", nodes.size());

    const json res_body = snodes_to_json(nodes);

    ARQMA_LOG(debug, "Snodes by pk: {}", res_body.dump());

    return {http::OK, res_body.dump(), http::json};
}

Response RequestHandler::process_retrieve(const json& params) {

    constexpr const char* fields[] = {"pubKey", "lastHash"};

    for (const auto& field : fields) {
        if (!params.contains(field)) {
            auto msg = fmt::format("invalid json: no `{}` field", field);
            ARQMA_LOG(debug, "{}", msg);
            return {http::BAD_REQUEST, std::move(msg)};
        }
    }

    bool success;
    const auto pk =
        user_pubkey_t::create(params["pubKey"].get<std::string>(), success);

    if (!success) {

        auto msg = fmt::format("Pubkey must be {} characters long\n",
                               get_user_pubkey_size());
        ARQMA_LOG(debug, "{}", msg);
        return {http::BAD_REQUEST, std::move(msg)};
    }

    if (!service_node_.is_pubkey_for_us(pk)) {
        return this->handle_wrong_swarm(pk);
    }

    const std::string& last_hash = params.at("lastHash").get_ref<const std::string&>();

    // Note: We removed long-polling

    std::vector<storage::Item> items;

    if (!service_node_.retrieve(pk.str(), last_hash, items)) {

        auto msg = fmt::format(
            "Internal Server Error. Could not retrieve messages for {}",
            obfuscate_pubkey(pk.str()));
        ARQMA_LOG(critical, "{}", msg);

        return {http::INTERNAL_SERVER_ERROR, std::move(msg)};
    }

    if (!items.empty()) {
        ARQMA_LOG(trace, "Successfully retrieved messages for {}",
                 obfuscate_pubkey(pk.str()));
    }

    json res_body;
    json messages = json::array();

    for (const auto& item : items) {
        json message;
        message["hash"] = item.hash;
        /// TODO: calculate expiration time once only?
        message["expiration"] = item.timestamp + item.ttl;
        message["data"] = item.data;
        messages.push_back(message);
    }

    res_body["messages"] = messages;

    return {http::OK, res_body.dump(), http::json};
}

void RequestHandler::process_client_req(std::string_view req_json, std::function<void(arqma::Response)> cb)
{
    ARQMA_LOG(trace, "process_client_req str <{}>", req_json);

    const json body = json::parse(req_json, nullptr, false);
    if (body.is_discarded()) {
        ARQMA_LOG(debug, "Bad client request: invalid json");
        return cb(Response{http::BAD_REQUEST, "invalid json\n"});
    }

    if (ARQMA_LOG_ENABLED(trace))
      ARQMA_LOG(trace, "process_client_req json <{}>", body.dump(2));

    const auto method_it = body.find("method");
    if (method_it == body.end() || !method_it->is_string()) {
        ARQMA_LOG(debug, "Bad client request: no method field");
        return cb(Response{http::BAD_REQUEST, "invalid json: no `method` field\n"});
    }

    const auto& method_name = method_it->get_ref<const std::string&>();

    ARQMA_LOG(trace, " - method name: {}", method_name);

    const auto params_it = body.find("params");
    if (params_it == body.end() || !params_it->is_object()) {
        ARQMA_LOG(debug, "Bad client request: no params field");
        return cb(Response{http::BAD_REQUEST, "invalid json: no `params` field\n"});
    }

    if (method_name == "store") {
        ARQMA_LOG(debug, "Process client request: store");
        return cb(process_store(*params_it));
    }
    if (method_name == "retrieve") {
        ARQMA_LOG(debug, "Process client request: retrieve");
        return cb(process_retrieve(*params_it));
    }
        // TODO: maybe we should check if (some old) clients requests long-polling and
        // then wait before responding to prevent spam

    if (method_name == "get_snodes_for_pubkey") {
        ARQMA_LOG(debug, "Process client request: snodes for pubkey");
        return cb(process_snodes_by_pk(*params_it));
    }

    ARQMA_LOG(debug, "Bad client request: unknown method '{}'", method_name);
    return cb({http::BAD_REQUEST, "no method " + method_name});
}

void RequestHandler::process_storage_test_req(uint64_t height, legacy_pubkey tester, std::string msg_hash_hex, std::function<void(MessageTestStatus, std::string, std::chrono::steady_clock::duration)> callback)
{
  auto started = std::chrono::steady_clock::now();
  auto [status, answer] = service_node_.process_storage_test_req(height, tester, msg_hash_hex);

  if (status == MessageTestStatus::RETRY)
  {
    auto timer = std::make_shared<arqmamq::TimerID>();
    auto& timer_ref = *timer;
    service_node_.arqmq_server()->add_timer(timer_ref, [
        this,
        timer=std::move(timer),
        height,
        tester,
        hash=std::move(msg_hash_hex),
        started,
        callback=std::move(callback)]
    {
      auto elapsed = std::chrono::steady_clock::now() - started;

      ARQMA_LOG(trace, "Performing storage test retry, {} since started", util::friendly_duration(elapsed));

      auto [status, answer] = service_node_.process_storage_test_req(height, tester, hash);
      if (status == MessageTestStatus::RETRY && elapsed < TEST_RETRY_PERIOD && !service_node_.shutting_down())
        return;
      service_node_.arqmq_server()->cancel_timer(*timer);
      callback(status, std::move(answer), elapsed);
    }, TEST_RETRY_INTERVAL);
  }
  else
  {
    callback(status, std::move(answer), std::chrono::steady_clock::now() - started);
  }
}

Response RequestHandler::wrap_proxy_response(Response res, const x25519_pubkey& client_key, EncryptType enc_type, bool embed_json, bool base64) const
{
  int status = res.status.first;
  std::string body;
  if (embed_json && res.content_type == http::json)
    body = fmt::format(R"({{"status":{},"body":{}}})", status, res.body);
  else
    body = json{{"status", status}, {"body", res.body}}.dump();

  std::string ciphertext = channel_cipher_.encrypt(enc_type, body, client_key);
  if (base64)
    ciphertext = arqmamq::to_base64(std::move(ciphertext));

  return Response{http::OK, std::move(ciphertext), http::json};
}

void RequestHandler::process_onion_req(std::string_view ciphertext, OnionRequestMetadata data)
{
  if (!service_node_.snode_ready())
    return data.cb({http::SERVICE_UNAVAILABLE, fmt::format("Snode not ready: {}", service_node_.own_address().pubkey_ed25519)});

  ARQMA_LOG(debug, "process_onion_req");

  service_node_.record_onion_request();

  var::visit([&](auto&& x) { process_onion_req(std::move(x), std::move(data)); },
             process_ciphertext_v2(channel_cipher_, ciphertext, data.ephem_key, data.enc_type));
}

void RequestHandler::process_onion_req(FinalDestinationInfo&& info, OnionRequestMetadata&& data)
{
  ARQMA_LOG(debug, "We are the final destination in the onion request!");

  process_onion_exit(info.body, [this, data = std::move(data), json = info.json, b64 = info.base64]
                    (arqma::Response res) {
                      data.cb(wrap_proxy_response(std::move(res), data.ephem_key, data.enc_type, json, b64));
                    });
}

void RequestHandler::process_onion_req(RelayToNodeInfo&& info, OnionRequestMetadata&& data)
{
  auto& [payload, ekey, etype, dest] = info;

  auto dest_node = service_node_.find_node(dest);
  if (!dest_node)
  {
    auto msg = fmt::format("Next node not found: {}", dest);
    ARQMA_LOG(warn, "{}", msg);
    return data.cb({http::BAD_GATEWAY, std::move(msg)});
  }

  auto on_response = [cb=std::move(data.cb)](bool success, std::vector<std::string> data)
  {
    if (!success)
    {
      ARQMA_LOG(debug, "[Onion request] Request time out");
      return cd({http::GATEWAY_TIMEOUT, "Request time out"});
    }

    if (data.size() < 2)
    {
      ARQMA_LOG(debug, "[Onion request] Invalid response; expected at least 2 parts");
      return cb9[http::INTERNAL_SERVER_ERROR, "Invalid response from snode"});
    }

    Response res{http::INTERNAL_SERVER_ERROR, std::move(data[1]), http::json};
    if (int code; util::parse_int(data[0], code))
      res.status = http::from_code(code);

    if (res.status != http::OK)
      ARQMA_LOG(debug, "Onion request relay failed with: {}", res.body);

    cb(std::move(res));
  };

  ARQMA_LOG(debug, "send_onion_to_sn, sn: {}", dest_node->pubkey_legacy);

  data.ephem_key = ekey;
  data.enc_type = etype;
  service_node_.send_onion_to_sn(*dest_node, std::move(payload), std::move(data), std::move(on_response));
}

void RequestHandler::process_onion_req(RelayToServerInfo&& info, OnionRequestMetadata&& data)
{
  ARQMA_LOG(debug, "We are to forward the request to url: {}{}", info.host, info.target);

  if (!(info.protocol == "http" || info.protocol == "https") || !is_onion_url_target_allowed(info.target))
    return data.cb(wrap_proxy_response({http::BAD_REQUEST, "invalid url"}, data.ephem_key, data.enc_type));

  std::string urlstr;
  urlstr.reserve(info.protocol.size() + 3 + info.host.size() + 6 /*:port*/ + 1 + info.target.size());
  urlstr += info.protocol;
  urlstr += "://";
  urlstr += info.host;
  if (info.port != (info.protocol == "https" ? 443 : 80))
  {
    urlstr += ':';
    urlstr += std::to_string(info.port);
  }
  if (!util::starts_with(info.target, "/"))
    urlstr += '/';
  urlstr += info.target;

  service_node_.record_proxy_request();

  pending_proxy_requests_.emplace_front(
    cpr::PostCallback(
      [&arqmq=*service_node_.arqmq_server(), cb=std::move(data.cb)](cpr::Response r)
      {
        Response res;
        if (r.error.code != cpr::ErrorCode::OK)
        {
          ARQMA_LOG(debug, "Onion proxied request to {} failed: {}", r.url.str(), r.error.message);
          res.body = r.error.message;
          if (r.error.code == cpr::ErrorCode::OPERATION_TIMEDOUT)
            res.status = http::GATEWAY_TIMEOUT;
          else
            res.status = http::BAD_GATEWAY;
        }
        else
        {
          res.status.first = r.status_code;
          res.status.second = r.status_line;
          for (auto& [k, v] : r.header)
          {
            auto& [header, val] = res.headers.emplace_back(std::move(k), std::move(v));
            if (util::string_iequal(header, "content-type"))
              res.content_type = val;
          }
          res.body = std::move(r.text);
        }

        cb(std::move(res));
      },
      cpr::Url{std::move(urlstr)},
      cpr::Timeout{ONION_URL_TIMEOUT},
      cpr::Ssl(cpr::ssl::TLSv1_2{}),
      cpr::MaxRedirects{0},
      cpr::Body{std::move(info.payload)}
    }
  };
}

void RequestHandler::process_onion_req(ProcessCiphertextError&& error, OnionRequestMetadata&& data)
{
  switch (error)
  {
    case ProcessCiphertextError::INVALID_CIPHERTEXT: return data.cb({http::BAD_REQUEST, "Invalid ciphertext"});
    case ProcessCiphertextError::INVALID_JSON: return data.cb(wrap_proxy_response({http::BAD_REQUEST, "Invalid json"}, data.ephem_key, data.enc_type));
  }
}

void RequestHandler::process_onion_exit(std::string_view body, std::function<void(arqma::Response)> cb)
{
    ARQMA_LOG(debug, "Processing onion exit!");

    if (!service_node_.snode_ready())
      return cb({http::SERVICE_UNAVAILABLE, "Snode not ready"});

    this->process_client_req(body, std::move(cb));
}

void RequestHandler::process_proxy_exit(const x25519_pubkey& client_key, std::string_view payload, std::function<void(arqma::Response)> cb)
{
    if (!service_node_.snode_ready())
      return cb(wrap_proxy_response({http::SERVICE_UNAVAILABLE, "Snode not ready"}, client_key, EncryptType::aes_cbc));

    static int proxy_idx = 0;
    int idx = proxy_idx++;

    ARQMA_LOG(debug, "[{}] Process proxy exit", idx);

    std::string plaintext;

    try
    {
      plaintext = channel_cipher_.decrypt_cbc(payload, client_key);
    } catch (const std::exception& e) {
      auto msg = fmt::format("Invalid ciphertext: {}", e.what());
      ARQMA_LOG(debug, "{}", msg);

      return cb(wrap_proxy_response({http::BAD_REQUEST, std::move(msg)}, client_key, EncryptType::aes_cbc));
    }

    std::string body;

    try {
        const json req = json::parse(plaintext, nullptr, true);
        body = req.at("body").get<std::string>();
    } catch (const std::exception& e) {
        auto msg = fmt::format("JSON parsing error: {}", e.what());
        ARQMA_LOG(debug, "[{}] {}", idx, msg);
        return cb(wrap_proxy_response({http::BAD_REQUEST, std::move(msg)}, client_key, EncryptType::aes_cbc));
    }

    this->process_client_req(body, [this, cb = std::move(cb), client_key, idx](arqma::Response res)
    {
      ARQMA_LOG(debug, "[{}] proxy about to respond with: {}", idx, res.status.first);
      cb(wrap_proxy_response(std::move(res), client_key, EncryptType::aes_cbc);
    });
}

} // namespace arqma
