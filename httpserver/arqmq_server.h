#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <arqmamq/arqmamq.h>
#include "sn_record.h"

namespace arqma {

struct arqmad_key_pair_t;

class ServiceNode;
class RequestHandler;

void arqmq_logger(arqmamq::LogLevel level, const char* file, int line, std::string message);

class ArqmamqServer {
  arqmamq::ArqmaMQ amq_;
  arqmamq::ConnectionID arqmad_conn_;

  ServiceNode* service_node_ = nullptr;
  RequestHandler* request_handler_ = nullptr;

  std::string peer_lookup(std::string_view pubkey_bin) const;

  void handle_sn_data(arqmamq::Message& message);
  void handle_sn_proxy_exit(arqmamq::Message& message);
  void handle_onion_request(arqmamq::Message& message, bool v2);
  void handle_get_logs(arqmamq::Message& message);
  void handle_get_stats(arqmamq::Message& message);

  std::unordered_map<std::string> stats_access_keys_;

  void connect_arqmad(const arqmamq::address& arqmad_rpc);

public:
  ArqmamqServer(const sn_record_t& me, const x25519_seckey& privkey, const std::vector<x25519_pubkey>& stats_access_keys_hex);
  void init(ServiceNode* sn, RequestHandler* rh, arqmamq::address arqmad_rpc);
  arqmamq::ArqmaMQ& operator*() { return amq_; }
  arqmamq::ArqmaMQ* operator->() { return &amq_; }

  const arqmamq::ConnectionID& arqmad_conn() const { return arqmad_conn_; }

  template <typename... Args>
  void arqmad_request(Args&&... args)
  {
    assert(arqmad_conn_);
    amq_.request(arqmad_conn(), std::forward<Args>(args)...);
  }

  template <typename... Args>
  void arqmad_send(Args&&... args)
  {
    assert(arqmad_conn_);
    amq_.send(arqmad_conn(), std::forward<Args>(args)...);
  }
};

}