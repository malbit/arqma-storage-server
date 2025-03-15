#pragma once

#include "arqma_common.h"
#include "sn_record.h"

#include <atomic>
#include <chrono>
#include <deque>
#include <mutex>
#include <unordered_map>

namespace arqmamq { class ArqmaMQ; }

namespace arqma {

inline constexpr std::chrono::seconds STATS_CLEANUP_INTERVAL = 10min;
inline constexpr size_t RECENT_STATS_COUNT = 6;

struct time_entry_t {
    time_t timestamp;
};

enum class ResultType { OK, MISMATCH, OTHER, REJECTED };

struct test_result_t {
    std::chrono::system_clock::time_point timestamp;
    ResultType result;
};

inline constexpr const char* to_str(ResultType result) {
  switch (result) {
    case ResultType::OK: return "OK";
    case ResultType::MISMATCH: return "MISMATCH";
    case ResultType::REJECTED: return "REJECTED";
    case ResultType::OTHER:
    default: return "OTHER";
    }
}

// Stats per peer
struct peer_stats_t {

    // how many times a single request failed
    uint64_t requests_failed = 0;
    // how many times a series of push requests failed
    // causing this node to give up re-transmitting
    uint64_t pushes_failed = 0;

    std::deque<test_result_t> storage_tests;
};

struct period_stats {
  uint64_t
    client_store_requests = 0,
    client_retrieve_requests = 0,
    proxy_requests = 0,
    onion_requests = 0;
};

class all_stats_t {
  std::atomic<uint64_t>
    total_client_store_requests{0},
    current_client_store_requests{0},
    total_client_retrieve_requests{0},
    current_client_retrieve_requests{0},
    total_proxy_requests{0},
    current_proxy_requests{0},
    total_onion_requests{0},
    current_onion_requests{0};

  std::deque<std::pair<std::chrono::steady_clock::time_point, period_stats>> previous_stats;
  std::chrono::steady_clock::time_point last_rotate = std::chrono::steady_clock::now();
  mutable std::mutex prev_stats_mutex;
  std::unordered_map<legacy_pubkey, peer_stats_t> peer_report_;
  mutable std::mutex peer_report_mutex;

  void cleanup();

public:
  explicit all_stats_t(arqmamq::ArqmaMQ& arqmq);

  void record_request_failed(const legacy_pubkey& sn)
  {
    std::lock_guard lock{peer_report_mutex};
    peer_report_[sn].requests_failed++;
  }

  void record_push_failed(const legacy_pubkey& sn)
  {
    std::lock_guard lock{peer_report_mutex};
    peer_report_[sn].pushes_failed++;
  }

  void record_storage_test_result(const legacy_pubkey& sn, ResultType result)
  {
    std::lock_guard lock{peer_report_mutex};
    peer_report_[sn].storage_tests.push_back({std::chrono::system_clock::now(), result});
  }

  std::unordered_map<legacy_pubkey, peer_stats_t> peer_report() const
  {
    std::lock_guard lock{peer_report_mutex};
    return peer_report_;
  }

  void bump_proxy_requests()
  {
    total_proxy_requests++;
    current_proxy_requests++;
  }
  void bump_onion_requests()
  {
    total_onion_requests++;
    current_onion_requests++;
  }
  void bump_store_requests()
  {
    total_client_store_requests++;
    current_client_store_requests++;
  }
  void bump_retrieve_requests()
  {
    total_client_retrieve_requests++;
    current_client_retrieve_requests++;
  }

  uint64_t get_total_proxy_requests() const { return total_proxy_requests; }
  uint64_t get_total_onion_requests() const { return total_onion_requests; }
  uint64_t get_total_store_requests() const { return total_client_store_requests; }
  uint64_t get_total_retrieve_requests() const { return total_client_retrieve_requests; }

  std::pair<std::chrono::steady_clock::duration, period_stats> get_recent_requests() const;
};

} // namespace arqma
