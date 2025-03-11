#pragma once

#include "arqma_common.h"
#include "arqmad_key.h"
#include "sn_record.h"

#include <chrono>
#include <queue>
#include <random>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace arqma {

namespace detail {

template <typename T, size_t N>
struct nth_greater {
  constexpr bool operator()(const T& lhs, const T& rhs) const
  {
    return std::greater<std::tuple_element_t<N, T>>{}(std::get<N>(lhs), std::get<N>(rhs));
  }
};

struct incoming_test_state {
  time_point_t last_test{};
  time_point_t last_whine{};
  bool was_failing = false;
};

}

class Swarm;

enum class ReachType { HTTPS, AMQ };

class reachability_testing {
  public:
    inline static constexpr auto TESTING_TIMER_INTERVAL = 50ms;
    inline static thread_local std::normal_distribution<float> TESTING_INTERVAL{10.0, 3.0};
    inline static constexpr auto TESTING_BACKOFF = 10s;
    inline static constexpr auto TESTING_BACKOFF_MAX = 2min;
    inline static constexpr int MAX_RETESTS_PER_TICK = 4;
    inline static constexpr auto MAX_TIME_WITHOUT_PING = 2min;
    inline static constexpr auto WHINING_INTERVAL = 2min;

  private:
    std::vector<legacy_pubkey> testing_queue;
    time_point_t next_general_test = time_point_t::min();
    const time_point_t startup = std::chrono::steady_clock::now();

    using FailingPK = std::tuple<legacy_pubkey, time_point_t, int>;
    std::priority_queue<FailingPK, std::vector<FailingPK>, detail::nth_greater<FailingPK, 1>> failing_queue;
    std::unordered_set<legacy_pubkey> failing;

    detail::incoming_test_state last_https;
    detail::incoming_test_state last_amq;

  public:

    std::optional<sn_record_t> next_random(const Swarm& swarm, const time_point_t& now = std::chrono::steady_clock::now(), bool requeue = true);
    std::vector<std::pair<sn_record_t, int>> get_failing(const Swarm& swarm, const time_point_t& now = std::chrono::steady_clock::now());
    void add_failing_node(const legacy_pubkey& pk, int previous_failures = 0);
    void incoming_ping(ReachType type, const time_point_t& now = std::chrono::steady_clock::now());
    void check_incoming_tests(const time_point_t& now = std::chrono::steady_clock::now());
};

} // namespace arqma
