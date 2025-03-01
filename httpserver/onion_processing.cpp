#include "channel_encryption.hpp"
#include "arqma_logger.h"
#include "request_handler.h"
#include "service_node.h"
#include <boost/endian/conversion.hpp>
#include <nlohmann/json.hpp>
#include <arqmamq/base64.h>
#include "onion_processing.h"
#include <arqmamq/base64.h>
#include <charconv>
#include <variant>

using nlohmann::json;

namespace arqma {

auto process_inner_request(const CiphertextPlusJson& parsed, std::string plaintext) -> ParsedInfo
{
  try
  {
    const json inner_json = json::parse(parsed.json, nullptr, true);
    if (inner_json.find("headers") != inner_json.end())
    {
      ARQMA_LOG(trace, "Found body: <{}>", parsed.ciphertext);
      return FinalDestinationInfo{parsed.ciphertext};
    }
    else if (inner_json.find("host") != inner_json.end())
    {
      const auto& host = inner_json.at("host").get_ref<const std::string&>();
      const auto& target = inner_json.at("target").get_ref<const std::string&>();
      std::string protocol = "https";
      uint16_t port = 443;

      if (inner_json.find("port") != inner_json.end())
      {
        port = inner_json.at("port").get<uint16_t>();
      }

      if (inner_json.find("protocol") != inner_json.end())
      {
        protocol = inner_json.at("protocol").get_ref<const std::string&>();
      }

      return RelayToServerInfo{plaintext, host, port, protocol, target};
    }
    else
    {
      const auto& dest = ed25519_pubkey::from_hex(inner_json.at("destination").get_ref<const std::string&>());
      const auto& ekey = inner_json.at("ephemeral_key").get_ref<const std::string&>();

      return RelayToNodeInfo{parsed.ciphertext, ekey, dest};
    }
  }
  catch (std::exception& e)
  {
    ARQMA_LOG(debug, "Error parsing inner JSON in onion request: {}", e.what());
    return ProcessCiphertextError::INVALID_JSON;
  }
}

static auto process_ciphertext_v2(const ChannelEncryption& decryptor, std::string_view ciphertext, const x25519_pubkey& ephem_key) -> ParsedInfo
{
  std::string plaintext;

  try
  {
    plaintext = decryptor.decrypt_gcm(ciphertext, ephem_key);
  }
  catch (std::exception& e)
  {
    ARQMA_LOG(debug, "Error decrypting an onion request: {}", e.what());
    return ProcessCiphertextError::INVALID_CIPHERTEXT;
  }

  ARQMA_LOG(debug, "onion request decrypted: (len: {})", plaintext.size());

  const auto parsed = parse_combined_payload(plaintext);

  return process_inner_requesrt(parsed, plaintext);
}

static auto gateway_timeout() -> arqma::Response
{
  return arqma::Response{Status::GATEWAY_TIMEOUT, "Request time out"};
}

static auto make_status(std::string_view status) -> arqma::Status
{
  int code;
  auto res = std::from_chars(status.data(), status.data() + status.size(), code);

  if (res.ec == std::errc::invalid_argument || res.ec == std::errc::result_out_of_range)
  {
    return Status::INTERNAL_SERVER_ERROR;
  }

  switch (code)
  {
    case 200: return Status::OK;
    case 400: return Status::BAD_REQUEST;
    case 403: return Status::FORBIDDEN;
    case 406: return Status::NOT_ACCEPTABLE;
    case 421: return Status::MISDIRECTED_REQUEST;
    case 500: return Status::INTERNAL_SERVER_ERROR;
    case 502: return Status::BAD_GATEWAY;
    case 503: return Status::SERVICE_UNAVAILABLE;
    case 504: return Status::GATEWAY_TIMEOUT;
    default: return Status::INTERNAL_SERVER_ERROR;
  }
}

static void relay_to_node(const ServiceNode& service_node, const RelayToNodeInfo& info, std::function<void(arqma::Response)> cb, bool v2)
{
  const auto& dest = info.next_node;
  const auto& payload = info.ciphertext;
  const auto& ekey = info.ephemeral_key;

  auto dest_node = service_node.find_node(dest);

  if (!dest_node)
  {
    auto msg = fmt::format("Next node not found: {}", dest);
    ARQMA_LOG(warn, "{}", msg);
    auto res = arqma::Response{Status::BAD_GATEWAY, std::move(msg)};
    cb(std::move(res));
    return;
  }

  nlohmann::json req_body;

  req_body["ciphertext"] = payload;
  req_body["ephemeral_key"] = ekey;

  auto on_response = [cb, &service_node](bool success, std::vector<std::string> data) {
    if (!success)
    {
      ARQMA_LOG(debug, "[Onion request] Request time out");
      cb(gateway_timeout());
      return;
    }

    if (data.size() != 2)
    {
      ARQMA_LOG(debug, "[Onion request] Incorrect number of messages: {}", data.size());
      cb(arqma::Response{Status::INTERNAL_SERVER_ERROR, "Incorrect number of messages from gateway"});
      return;
    }

    if (data[0] != "200")
    {
      ARQMA_LOG(debug, "Onion request relay failed with: {}", data[1]);
    }
    cb(arqma::Reasponse{make_status(data[0]), std::move(data[1])});
  };

  ARQMA_LOG(debug, "send_onion_to_sn, sn: {} reqidx: {}", dest_node->pubkey_legacy);

  if (v2)
  {
    service_node.send_onion_to_sn_v2(*dest_node, payload, ekey, on_response);
  }
  else
  {
    service_node.send_onion_to_sn_v1(*dest_node, payload, ekey, on_response);
  }
}

void RequestHandler::process_onion_req(std::string_view ciphertext, const x25519_pubkey& ephem_key, std::function<void(arqma::Response)> cb, bool v2)
{
  if (!service_node_.snode_ready())
  {
    auto msg = fmt::format("Snode not ready: {}", service_node_.own_address().pubkey_ed25519);
    cb(arqma::Response{Status::SERVICE_UNAVAILABLE, std::move(msg)});
    return;
  }

  ARQMA_LOG(debug, "process_onion_req: {}", v2);

  if (!v2)
  {
    cb(arqma::Response{Status::BAD_REQUEST, "BAD onion request"});
    return;
  }

  ParsedInfo res = process_ciphertext_v2(channel_cipher_, ciphertext, ephem_key);

  if (const auto info = std::get_if<FinalDestinationInfo>(&res))
  {
    ARQMA_LOG(debug, "We are the final destination in the onion request");

    this->process_onion_exit(ephem_key, info->body,
      [this, ephem_key, cb = std::move(cb)](arqma::Response res)
      {
        cb(wrap_proxy_response(res, ephem_key, EncryptType::aes_gcm));
      });
    return;
  }
  else if (const auto info = std::get_if<RelayToNodeInfo>(&res))
  {
    relay_to_node(this->service_node_, *info, std::move(cb), v2);
  }
  else if (const auto info = std::get_if<RelayToServerInfo>(&res))
  {
    ARQMA_LOG(debug, "We are to forward the request to url" {}{}", info->host, info->target);

    const auto& target = info->target;

    if ((util::ends_with(target, "/lsrpc")) && (target.find('?') == std::string::npos))
    {
      this->process_onion_to_url(info->protocol, info->host, info->port, target, info->payload, std::move(cb));
    }
    else
    {
      cb(wrap_proxy_response({Status::BAD_REQUEST, "Invalid url"}, ephem_key, EncryptType::aes_gcm));
    }
  }
  else if (const auto error = std::get_if<ProcessCiphertextError>(&res))
  {
    switch (*error)
    {
      case ProcessCiphertextError::INVALID_CIPHERTEXT:
      {
        cb(arqma::Response{Status::BAD_REQUEST, "Invalid ciphertext"});
        break;
      }
      case ProcessCiphertextError::INVALID_JSON:
      {
        cb(wrap_proxy_response({Status::BAD_REQUEST, "Invalid json"}, ephem_key, EncryptType::aes_gcm));
        break;
      }
    }
  }
  else
  {
    ARQMA_LOG(error, "UNKNOWN VARIANT");
  }
}

auto parse_combined_payload(const std::string& payload) -> CiphertextPlusJson
{
  ARQMA_LOG(trace, "Parsing payload of length: {}", payload.size());

  auto it = payload.begin();

  if (payload.size() < 4)
  {
    ARQMA_LOG(warn, "Unexpected payload size");
    throw std::exception();
  }

  uint32_t n;
  std::memcpy(&n, payload.data(), sizeof(uint32_t));
  boost::endian::little_to_native_inplace(n);

  ARQMA_LOG(trace, "Ciphertext length: {}", n);

  if (payload.size() < 4 + n)
  {
    ARQMA_LOG(warn, "Unexpected payload size");
    throw std::exception();
  }

  it += sizeof(uint32_t);

  const auto ciphertext = std::string(it, it + n);
  ARQMA_LOG(debug, "ciphertext length: {}", ciphertext.size());
  const auto json_blob = std::string(it + n, payload.end());
  ARQMA_LOG(debug, "json blob: (len: {})", json_blob.size());

  return CiphertextPlusJson{ciphertext, json_blob};
}

std::ostream& operator<<(std::ostream& os, const FinalDestinationInfo& d)
{
  return os << fmt::format("[\"body\": {}]", d.body);
}

bool operator==(const FinalDestinationInfo& lhs, const FinalDestinationInfo& rhs)
{
  return lhs.body == rhs.body;
}

std::ostream& operator<<(std::ostream& os, const RelayToServerInfo& d)
{
  return os << fmt::format("[\"protocol\": {}, \"host\": {}, \"port\": {}, "
                           "\"target\": {}, \"payload\": {}]",
                           d.protocol, d.host, d.port, d.target, d.payload);
}

bool operator==(const RelayToServerInfo& lhs, const RelayToServerInfo& rhs)
{
  return (lhs.protocol == rhs.protocol) && (lhs.host == rhs.host) && (lhs.port == rhs.port) &&
         (lhs.target == rhs.target) && (lhs.payload == rhs.payload);
}

std::ostream& operator<<(std::ostream& os, const RelayToNodeInfo& d)
{
  return os << fmt::format("[\"ciphertext\": {}, \"ephemeral_key\": {}, \"next_node\": {}]",
                           d.ciphertext, d.ephemeral_key, d.next_node);
}

bool operator==(const RelayToNodeInfo& a, const RelayToNodeInfo& b)
{
  return std::tie(a.ciphertext, a.ephemeral_key, a.next_node) == std::tie(b.ciphertext, b.ephemeral_key, b.next_node);
}

} // namespace arqma