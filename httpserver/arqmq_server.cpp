#include "arqmq_server.h"
#include "dev_sink.h"
#include "http.h"
#include "arqma_common.h"
#include "arqma_logger.h"
#include "arqmad_key.h"
#include "channel_encryption.hpp"
#include "rate_limiter.h"
#include "service_node.h"
#include "request_handler.h"

#include <nlohmann/json.hpp>
#include <arqmamq/hex.h>
#include <arqmamq/arqmamq.h>

#include <optional>

namespace arqma {

std::string ArqmamqServer::peer_lookup(std::string_view pubkey_bin) const
{
    ARQMA_LOG(trace, "[ARQMQ] Peer Lookup");

    if (pubkey_bin.size() != sizeof(x25519_pubkey))
      return "";
    x25519_pubkey pubkey;
    std::memcpy(pubkey.data(), pubkey_bin.data(), sizeof(x25519_pubkey));

    if (auto sn = service_node_->find_node(pubkey))
      return fmt::format("tcp://{}:{}", sn->ip, sn->arqmq_port);

    ARQMA_LOG(debug, "[ARQMQ] peer node not found via x25519 pubkey {}", pubkey);
    return "";
}

void ArqmamqServer::handle_sn_data(arqmamq::Message& message)
{
    ARQMA_LOG(debug, "[ARQMQ] handle_sn_data");
    ARQMA_LOG(debug, "[ARQMQ] thread id: {}", std::this_thread::get_id());
    ARQMA_LOG(debug, "[ARQMQ] from: {}", arqmamq::to_hex(message.conn.pubkey()));

    std::stringstream ss;

    for (auto& part : message.data) {
        ss << part;
    }

    service_node_->process_push_batch(ss.str());

    ARQMA_LOG(debug, "[ARQMQ] send reply");

    message.send_reply();
};

void ArqmamqServer::handle_ping(arqmamq::Message& message)
{
  ARQMA_LOG(debug, "Remote pinged me");
  service_node_->update_last_ping(ReachType::AMQ);
  message.send_reply("pong");
}

void ArqmamqServer::handle_storage_test(arqmamq::Message& message)
{
  if (message.conn.pubkey().size() != 32)
  {
    ARQMA_LOG(err, "bug: invalid sn.storage_test arqmq request from {} with no pubkey", message.remote);
    return message.send_reply("invalid parameters");
  }
  else if (message.data.size() < 2)
  {
    ARQMA_LOG(warn, "invalid sn.storage_test arqmq request from {}: not enough data parts; expected 2, received {}", message.remote, message.data.size());
    return message.send_reply("invalid parameters");
  }
  legacy_pubkey tester_pk;
  if (auto node = service_node_->find_node(x25519_pubkey::from_bytes(message.conn.pubkey())))
  {
    tester_pk = node->pubkey_legacy;
    ARQMA_LOG(debug, "incoming sn.storage_test request from {}@{}", tester_pk, message.remote);
  }
  else
  {
    ARQMA_LOG(warn, "invalid sn.storage_test arqmq request from {}: sender is not an active SN", message.remote);
    return message.send_reply("invalid pubkey");
  }

  uint64_t height;
  if (!util::parse_int(message.data[0], height) || !height)
  {
    ARQMA_LOG(warn, "invalid sn.storage_test arqmq request from {}@{}: '{}' is not a valid height", tester_pk, message.remote, height);
    return message.send_reply("invalid height");
  }
  if (message.data[1].size() != 64)
  {
    ARQMA_LOG(warn, "invalid sn.storage_test arqmq request from {}@{}: message hash is {} bytes, expected 64", tester_pk, message.remote, message.data[1].size());
    return message.send_reply("invalid msg hash");
  }

  request_handler_->process_storage_test_req(height, tester_pk, arqmamq::to_hex(message.data[1]),
      [reply=message.send_later()](MessageTestStatus status, std::string answer, std::chrono::steady_clock::duration elapsed)
  {
    switch (status)
    {
      case MessageTestStatus::SUCCESS:
        ARQMA_LOG(debug, "Storage test success after {}", util::friendly_duration(elapsed));
        reply.reply("OK", answer);
        return;
      case MessageTestStatus::WRONG_REQ:
        reply.reply("wrong request");
        return;
      case MessageTestStatus::RETRY:
        [[fallthrough]];
      case MessageTestStatus::ERROR:
        ARQMA_LOG(debug, "Failed storage test, tried for {}", util::friendly_duration(elapsed));
        reply.reply("other");
    }
  });
}

void ArqmamqServer::handle_onion_request(std::string_view payload, OnionRequestMetadata&& data, arqmamq::Message::DeferredSend send)
{
    data.cb = [send](arqma::Response res)
    {
      if (ARQMA_LOG_ENABLED(trace))
        ARQMA_LOG(trace, "on response: {}...", to_string(res).substr(0, 100));

      send.reply(std::to_string(res.status.first), std::move(res).body);
    };

    if (data.hop_no > MAX_ONION_HOPS)
      return data.cb({http::BAD_REQUEST, "onion request max path length exceeded"});

    request_handler_->process_onion_req(payload, std::move(data));
}

void ArqmamqServer::handle_onion_request(arqmamq::Message& message)
{
  std::pair<std::string_view, OnionRequestMetadata> data;
  try
  {
    if (message.data.size() != 1)
      throw std::runtime_error{"expected 1 part, got " + std::to_string(message.data.size())};

    data = decode_onion_data(message.data[0]);
  }
  catch (const std::exception& e)
  {
    auto msg = "Invalid internal onion request: "s + e.what();
    ARQMA_LOG(err, msg);
    message.send_reply(std::to_string(http::BAD_REQUEST.first), msg);
    return;
  }

  handle_onion_request(data.first, std::move(data.second), message.send_later());
}

void ArqmamqServer::handle_get_logs(arqmamq::Message& message)
{
  ARQMA_LOG(debug, "Received get_logs request via ARQMQ");

  auto dev_sink = dynamic_cast<arqma::dev_sink_mt*>(spdlog::get("arqma_logger")->sinks()[2].get());

  if (dev_sink == nullptr)
  {
    ARQMA_LOG(critical, "Sink #3 should be dev sink");
    assert(false);
    auto err_msg = "Developer error: sink #3 is not a dev sink";
    message.send_reply(err_msg);
  }

  nlohmann::json val;
  val["entries"] = dev_sink->peek();
  message.send_reply(val.dump(4));
}

void ArqmamqServer::handle_get_stats(arqmamq::Message& message)
{
  ARQMA_LOG(debug, "Received get_stats request via ARQMQ");

  auto payload = service_node_->get_stats();
  message.send_reply(payload);
}

void ArqmamqServer::handle_client_request(std::string_view method, arqmamq::Message& message)
{
  ARQMA_LOG(debug, "Handling AMQ RPC request for {}", method);
  auto it = RequestHandler::client_rpc_endpoints.find(method);
  assert(it != RequestHandler::client_rpc_endpoints.end());

  if (message.data.size() != 1)
  {
    ARQMA_LOG(warn, "Invalid AMQ RPC request for {}: incorrect number of message parts ({})", method, message.data.size());
    message.send_reply(std::to_string(http::BAD_REQUEST.first), "Invalid request: expected 1 message part, received " + std::to_string(message.data.size()));
    return;
  }

  if (rate_limiter_->should_rate_limit_client(message.remote))
  {
    ARQMA_LOG(debug, "Rate limiting client request from {}", message.remote);
    return message.send_reply(std::to_string(http::TOO_MANY_REQUESTS.first), "Too many requests, try again later");
  }

  auto params = nlohmann::json::parse(message.data[0], nullptr, false);
  if (params.is_discarded())
  {
    ARQMA_LOG(debug, "Bad AMQ storage RPC request: invalid json");
    return message.send_reply(std::to_string(http::BAD_REQUEST.first), "invalid json");
  }

  it->second(*request_handler_, params, [send=message.send_later()](arqma::Response res)
  {
    if (res.status == http::OK)
    {
      ARQMA_LOG(debug, "AMQ RPC request successful, returning {}-byte response", res.body.size());
      send.reply(std::move(res.body));
    }
    else
    {
      ARQMA_LOG(debug, "AMQ RPC request failed, replying with [{}, {}]", res.status.first, res.body);
      send.reply(std::to_string(res.status.first), res.body);
    }
  });
}

void arqmq_logger(arqmamq::LogLevel level, const char* file, int line, std::string message)
{
#define AMQ_LOG_MAP(AMQ_LVL, SS_LVL)                        \
  case arqmamq::LogLevel::AMQ_LVL:                          \
    ARQMA_LOG(SS_LVL, "[{}:{}]: {}", file, line, message);  \
    break;

    switch (level)
    {
      AMQ_LOG_MAP(fatal, critical);
      AMQ_LOG_MAP(error, err);
      AMQ_LOG_MAP(warn, warn);
      AMQ_LOG_MAP(info, info);
      AMQ_LOG_MAP(trace, trace);
      AMQ_LOG_MAP(debug, debug);
    }
#undef AMQ_LOG_MAP
}

ArqmamqServer::ArqmamqServer(
               const sn_record_t& me,
               const x25519_seckey& privkey,
               const std::vector<x25519_pubkey>& stats_access_keys) :
      arqmq_{
           std::string{me.pubkey_x25519.view()},
           std::string{privkey.view()},
           true,
           [this](auto pk) { return peer_lookup(pk); },
           arqmq_logger,
           arqmamq::LogLevel::info}
{
  for (const auto& key : stats_access_keys)
    stats_access_keys_.emplace(key.view());

  ARQMA_LOG(info, "ArqmaMQ is listening on port {}", me.arqmq_port);

  arqmq_.listen_curve(fmt::format("tcp://0.0.0.0:{}", me.arqmq_port),
                    [this](std::string_view /*addr*/, std::string_view pk, bool/*sn*/)
                    {
                      return stats_access_keys_.count(std::string{pk}) ? arqmamq::AuthLevel::admin : arqmamq::AuthLevel::none;
                    });

  arqmq_.add_category("sn", arqmamq::Access{arqmamq::AuthLevel::none, true, false}, 2, 1000)
        .add_request_command("data", [this](auto& m) { handle_sn_data(m); })
        .add_request_command("ping", [this](auto& m) { handle_ping(m); })
        .add_request_command("storage_test", [this](auto& m) { handle_storage_test(m); })
        .add_request_command("onion_request", [this](auto& m) { handle_onion_request(m); });

  auto st_cat = arqmq_.add_category("storage", arqmamq::AuthLevel::none, 1, 200);
  for (const auto& [name, _cb] : RequestHandler::client_rpc_endpoints)
    st_cat.add_request_command(std::string{name}, [this, name=name](auto& m) { handle_client_request(name, m); });

  arqmq_.add_category("service", arqmamq::AuthLevel::admin)
        .add_request_command("get_stats", [this](auto& m) { handle_get_stats(m); })
        .add_request_command("get_logs", [this](auto& m) { handle_get_logs(m); });

  arqmq_.add_category("notify", arqmamq::AuthLevel::admin)
        .add_request_command("block", [this](auto& m) {
          ARQMA_LOG(debug, "Received new block notification from arqmad, updating swarms");
          if (service_node_)
            service_node_->update_swarms();
        });

  arqmq_.set_general_threads(1);

  arqmq_.MAX_MSG_SIZE = 10 * 1024 * 1024;

  arqmq_.EPHEMERAL_ROUTING_ID = true;
}

void ArqmamqServer::connect_arqmad(const arqmamq::address& arqmad_rpc)
{
  arqmad_conn_ = arqmq_.connect_remote(arqmad_rpc,
    [this](auto&&)
    {
      ARQMA_LOG(info, "Connection to Arqmad established");
      service_node_->on_arqmad_connected();
    },
    [this, arqmad_rpc](auto&&, std::string_view reason)
    {
      ARQMA_LOG(warn, "failed to connect to local arqmad @ {}: {}; retrying", arqmad_rpc, reason);
      connect_arqmad(arqmad_rpc);
    },
    arqmamq::connect_option::ephemeral_routing_id{},
    arqmamq::AuthLevel::admin);
}

void ArqmamqServer::init(ServiceNode* sn, RequestHandler* rh, RateLimiter* rl, arqmamq::address arqmad_rpc)
{
  assert(!service_node_);
  service_node_ = sn;
  request_handler_ = rh;
  rate_limiter_ = rl;
  arqmq_.start();
  connect_arqmad(arqmad_rpc);
}

std::string ArqmamqServer::encode_onion_data(std::string_view payload, const OnionRequestMetadata& data)
{
  return arqmamq::bt_serialize<arqmamq::bt_dict>({
      {"data", payload},
      {"enc_type", to_string(data.enc_type)},
      {"ephemeral_key", data.ephem_key.view()},
      {"hop_no", data.hop_no},
  });
}

std::pair<std::string_view, OnionRequestMetadata> ArqmamqServer::decode_onion_data(std::string_view data)
{
  std::pair<std::string_view, OnionRequestMetadata> result;
  auto& [payload, meta] = result;
  arqmamq::bt_dict_consumer d{data};
  if (!d.skip_until("data"))
    throw std::runtime_error{"required data payload not found"};
  payload = d.consume_string_view();

  if (d.skip_until("enc_type"))
    meta.enc_type = parse_enc_type(d.consume_string_view());
  else
    meta.enc_type = EncryptType::aes_gcm;

  if (!d.skip_until("ephemeral_key"))
    throw std::runtime_error{"ephemeral key not found"};
  meta.ephem_key = x25519_pubkey::from_bytes(d.consume_string_view());

  if (d.skip_until("hop_no"))
    meta.hop_no = d.consume_integer<int>();
  if (meta.hop_no < 1)
    meta.hop_no = 1;

  return result;
}

} // namespace arqma