#include "arqmq_server.h"
#include "dev_sink.h"
#include "arqma_common.h"
#include "arqma_logger.h"
#include "arqmad_key.h"
#include "channel_encryption.hpp"
#include "arqmamq/connection.h"
#include "arqmamq/arqmamq.h"
#include "service_node.h"
#include "request_handler.h"

#include <arqmamq/hex.h>
#include <nlohmann/json.hpp>

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

static std::optional<x25519_pubkey> extract_x25519_from_hex(std::string_view hex)
{
  try
  {
    return x25519_pubkey::from_hex(hex);
  } catch (const std::exception& e) {
    ARQMA_LOG(warn, "Failed to decode client key: {}", e.what());
  }
  return std::nullopt;
}

void ArqmamqServer::handle_sn_proxy_exit(arqmamq::Message& message)
{
    ARQMA_LOG(debug, "[ARQMQ] handle_sn_proxy_exit");
    ARQMA_LOG(debug, "[ARQMQ] thread id: {}", std::this_thread::get_id());
    ARQMA_LOG(debug, "[ARQMQ] from: {}", arqmamq::to_hex(message.conn.pubkey()));

    if (message.data.size() != 2)
    {
        ARQMA_LOG(debug, "Expected 2 message parts, got {}", message.data.size());
        return;
    }

    auto client_key = extract_x25519_from_hex(message.data[0]);
    if (!client_key) return;
    const auto& payload = message.data[1];

    request_handler_->process_proxy_exit(*client_key, payload, [send=message.send_later()](arqma::Response res)
    {
      ARQMA_LOG(debug, "  Proxy exit status: {}", res.status());
      if (res.status() == Status::OK)
      {
        send.reply(res.message());
      } else {
        send.reply(fmt::format("{}", res.status()), res.message());
        ARQMA_LOG(debug, "Error: status is not OK for proxy_exit: {}", res.status());
      }
    });
}

void ArqmamqServer::handle_ping(arqmamq::Message& message)
{
  ARQMA_LOG(debug, "Remote pinged me");
  service_node_->update_last_ping(ReachType::AMQ);
  message.send_reply("pong");
}

void ArqmamqServer::handle_onion_request(std::string_view payload, OnionRequestMetadata&& data, arqmamq::Message::DefferedSend send)
{
    data.cb = [send](arqma::Response res)
    {
      if (ARQMA_LOG_ENABLED(trace))
        ARQMA_LOG(trace, "on response: {}...", to_string(res).substr(0, 100));

      send.reply(std::to_string(static_cast<int>(res.status())), std::move(res).message());
    };

    if (data.hop_no > MAX_ONION_HOPS)
      return data.cb({Status::BAD_REQUEST, "onion request max path length exceeded"});

    request_handler_->process_onion_req(rayload, std::move(data));
}

void ArqmamqServer::handle_onion_request(arqmamq::Message& message)
{
  std::pair<std::string_view, OnionRequestMetadata> data;
  try
  {
    if (message.data.size() != 1)
      thrown std::runtime_error{"expected 1 part, got " + std::to_string(message.data.size())};

    data = decode_onion_data(message.data[0]);
  }
  catch (const std::exception& e)
  {
    auto msg = "Invalid internal onion request: "s + e.what();
    ARQMA_LOG(error, "{}", msg);
    message.send_reply(std::to_string(static_cast<int>(Status::BAD_REQUEST)), msg);
    return;
  }

  handle_onion_request(data.first, std::move(data.second), message.send_later());
}

void ArqmamqServer::handle_onion_req_v2(arqmamq::Message& message)
{
  ARQMA_LOG(debug, "Got v2 onion request over ArqmaMQ");

  const int bad_code = static_casr<int>(Status::BAD_REQUEST);
  if (message.data.size() != 2)
  {
    ARQMA_LOG(error, "Expected 2 message parts, got {}", message.data.size());
    message.send_reply(std::to_string(bad_code), "Incorrect number of onion request message parts");
    return;
  }

  auto eph_key = extract_x25519_from_hex(message.data[0]);
  if (!eph_key)
  {
    ARQMA_LOG(error, "no ephemeral key in arqmq onion request");
    message.send_reply(std::to_string(bad_code), "Missing ephemeral key");
    return;
  }

  handle_onion_request(message.data[1], {*eph_key, nullptr, 1, EncryptType::aes_gcm}, message.send_later());
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

void arqmq_logger(arqmamq::LogLevel level, const char* file, int line, std::string message)
{
#define AMQ_LOG_MAP(AMQ_LVL, SS_LVL)                        \
  case arqmamq::LogLevel::AMQ_LVL:                          \
    ARQMA_LOG(SS_LVL, "[{}:{}]: {}", file, line, message);  \
    break;

    switch (level)
    {
      AMQ_LOG_MAP(fatal, critical);
      AMQ_LOG_MAP(error, error);
      AMQ_LOG_MAP(warn, warn);
      ARQ_LOG_MAP(info, info);
      ARQ_LOG_MAP(trace, trace);
      AMQ_LOG_MAP(debug, debug);
    }
#undef AMQ_LOG_MAP
}

ArqmamqServer::ArqmamqServer(
               const sn_record_t& me,
               const x25519_seckey& privkey;
               const std::vector<x25519_pubkey>& stats_access_keys) :
      amq_{
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

  amq_.listen_curve(fmt::format("tcp://0.0.0.0:{}", me.arqmq_port),
                    [this](std::string_view /*addr*/, std::string_view pk, bool/*sn*/)
                    {
                      return stats_access_keys_.count(std::string{pk}) ? arqmamq::AuthLevel::admin : arqmamq::AuthLevel::none;
                    });

  amq_.add_category("sn", arqmamq::Access{arqmamq::AuthLevel::none, true, false})
      .add_request_command("data", [this](auto& m) { this->handle_sn_data(m); })
      .add_request_command("proxy_exit", [this](auto& m) { this->handle_sn_proxy_exit(m); })
      .add_request_command("ping", [this](auto& m) { handle_ping(m); })
      .add_request_command("onion_request", [this](auto& m) { handle_onion_request(m); });

  amq_.add_category("service", arqmamq::AuthLevel::admin)
      .add_request_command("get_stats", [this](auto& m) { this->handle_get_stats(m); })
      .add_request_command("get_logs", [this](auto& m) { this->handle_get_logs(m); });

  amq_.add_category("notify", arqmamq::AuthLevel::admin)
      .add_request_command("block", [this](auto& m) {
        ARQMA_LOG(debug, "Received new block notification from arqmad, updating swarms");
        if (service_node_)
          service_node_->update_swarms();
      });

  amq_.set_general_threads(1);

  amq_.MAX_MSG_SIZE = 10 * 1024 * 1024;

  amq_.EPHEMERAL_ROUTING_ID = true;
}

void ArqmamqServer::connect_arqmad(const arqmamq::address& arqmad_rpc)
{
  arqmad_conn_ = amq_.connect_remote(arqmad_rpc,
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

void ArqmamqServer::init(ServiceNode* sn, RequestHandler* rh, arqmamq::address arqmad_rpc)
{
  assert(!service_node_);
  service_node_ = sn;
  request_handler_ = rh;
  amq_.start();
  connect_arqmad(arqmad_rpc);
}

std::string ArqmamqServer::encode_onion_data(std::string_view payload, const OnionRequestMetadata& data)
{
  return arqmamq::bt_serialize<arqmqmq::bt_dict>({
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