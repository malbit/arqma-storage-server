#include "arqmq_server.h"
#include "dev_sink.h"
#include "arqma_common.h"
#include "arqma_logger.h"
#include "arqmad_key.h"
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

void ArqmamqServer::handle_onion_request(arqmamq::Message& message, bool v2)
{
    ARQMA_LOG(debug, "Got an onion request over ARQMQ");

    auto on_response = [send=message.send_later()](arqma::Response res)
    {
      if (ARQMA_LOG_ENABLED(trace))
        ARQMA_LOG(trace, "on response: {}...", to_string(res).substr(0, 100));

      send.reply(std::to_string(static_cast<int>(res.status())), std::move(res).message());
    };

    if (message.data.size() == 1 && message.data[0] == "ping")
    {
      ARQMA_LOG(info, "Remote pinged me");
      service_node_->update_last_ping(true);
      on_response(arqma::Response{Status::OK, "pong"});
      return;
    }

    if (message.data.size() != 2)
    {
        ARQMA_LOG(error, "Expected 2 message parts, got {}", message.data.size());
        on_response(arqma::Response{Status::BAD_REQUEST, "Incorrect number of messages"});
        return;
    }

    auto eph_key = extract_x25519_from_hex(message.data[0]);
    if (!eph_key) return;
    const auto& ciphertext = message.data[1];

    request_handler_->process_onion_req(std::string(ciphertext), *eph_key, on_response, v2);
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
      .add_request_command("onion_req", [this](auto& m) { this->handle_onion_request(m, false); })
      .add_request_command("onion_req_v2", [this](auto& m) { this->handle_onion_request(m, true); });

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

} // namespace arqma