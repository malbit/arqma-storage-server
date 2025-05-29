#pragma once

#include <set>
#include "arqma_logger.h"

struct net_stats_t {
  uint32_t connections_in = 0;
  uint32_t http_connections_out = 0;
  uint32_t https_connections_out = 0;

  std::set<int> open_fds;

  void record_socket_open(int sockfd) {
    open_fds.insert(sockfd);
  }

  void record_socket_close(int sockfd) {
    open_fds.erase(sockfd);
  }
};

inline net_stats_t& get_net_stats() {
    static net_stats_t stats;
    return stats;
}
