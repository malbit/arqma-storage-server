#pragma once

#include "arqma_common.h"
#include <chrono>
#include <unordered_map>

namespace arqma {

namespace detail {

class reach_record_t {

    using time_point_t = std::chrono::time_point<std::chrono::steady_clock>;

  public:
    time_point_t first_failure;
    time_point_t last_tested;
    bool reported = false;

    reach_record_t();
};
} // namespace detail

class reachability_records_t {
    std::unordered_map<sn_pub_key_t, detail::reach_record_t> offline_nodes_;

  public:
    bool record_unreachable(const sn_pub_key_t& sn);

    bool expire(const sn_pub_key_t& sn);

    void set_reported(const sn_pub_key_t& sn);

    boost::optional<sn_pub_key_t> next_to_test();
};

} // namespace arqma
