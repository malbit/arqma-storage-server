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
  std::chrono::steady_clock::time_point last_test{};
  std::chrono::steady_clock::time_point last_whine{};
  bool was_failing = false;
};

}

class Swarm;

enum class ReachType { HTTPS, AMQ };

class reachability_testing {
  public:
    inline static constexpr auto TESTING_TIMER_INTERVAL = 200ms;
    inline static thread_local std::normal_distribution<float> TESTING_INTERVAL{10.0, 3.0};
    inline static constexpr auto TESTING_BACKOFF = 10s;
    inline static constexpr auto TESTING_BACKOFF_MAX = 2min;
    inline static constexpr int MAX_RETESTS_PER_TICK = 4;
    inline static constexpr auto MAX_TIME_WITHOUT_PING = 2min;
    inline static constexpr auto WHINING_INTERVAL = 2min;

    using clock = std::chrono::steady_clock;

  private:
    std::vector<legacy_pubkey> testing_queue;
    clock::time_point next_general_test = clock::time_point::min();
    const clock::time_point startup = clock::now();

    using FailingPK = std::tuple<legacy_pubkey, clock::time_point, int>;
    std::priority_queue<FailingPK, std::vector<FailingPK>, detail::nth_greater<FailingPK, 1>> failing_queue;
    std::unordered_set<legacy_pubkey> failing;

    detail::incoming_test_state last_https;
    detail::incoming_test_state last_arqmq;

  public:

    std::optional<sn_record_t> next_random(const Swarm& swarm, const clock::time_point& now = clock::now(), bool requeue = true);
    std::vector<std::pair<sn_record_t, int>> get_failing(const Swarm& swarm, const clock::time_point& now = clock::now());
    void add_failing_node(const legacy_pubkey& pk, int previous_failures = 0);
    void incoming_ping(ReachType type, const clock::time_point& now = clock::now());
    void check_incoming_tests(const clock::time_point& now = clock::now());
};

} // namespace arqma
