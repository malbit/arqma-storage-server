#pragma once

#include <Database.hpp>
#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <thread>
#include <unordered_map>

#include <boost/asio.hpp>
#include <boost/beast/http.hpp>
#include <boost/circular_buffer.hpp>

#include "arqma_common.h"
#include "arqmad_key.h"
#include "reachability_testing.h"
#include "stats.h"
#include "swarm.h"
#include <string_view>

namespace http = boost::beast::http;
using request_t = http::request<http::string_body>;

namespace arqma {

inline constexpr size_t BLOCK_HASH_CACHE_SIZE = 30;
inline constexpr int STORAGE_SERVER_HARDFORK = 16;

namespace storage {
struct Item;
} // namespace storage

struct sn_response_t;

class ArqmamqServer;
struct OnionRequestMetadata;

namespace ss_client
{
  class Request;
  enum class ReqMethod;
  using Callback = std::function<void(bool success, std::vector<std::string>)>;
}

namespace http_server {
class connection_t;
}

struct arqmad_key_pair_t;

using connection_ptr = std::shared_ptr<http_server::connection_t>;

class Swarm;

struct signature;

enum class MessageTestStatus { SUCCESS, RETRY, ERROR, WRONG_REQ };
enum class SnodeStatus { UNKNOWN, UNSTAKED, DECOMMISSIONED, ACTIVE };

/// All service node logic that is not network-specific
class ServiceNode {
    using listeners_t = std::vector<connection_ptr>;

    boost::asio::io_context& ioc_;

    bool syncing_ = true;
    bool active_ = false;
    bool got_first_response_ = false;
    int hardfork_ = 0;
    uint64_t block_height_ = 0;
    uint64_t target_height_ = 0;
    std::string block_hash_;
    std::unique_ptr<Swarm> swarm_;
    std::unique_ptr<Database> db_;

    SnodeStatus status_ = SnodeStatus::UNKNOWN;

    const sn_record_t our_address_;
    const legacy_seckey our_seckey_;

    /// Cache for block_height/block_hash mapping
    boost::circular_buffer<std::pair<uint64_t, std::string>> block_hashes_cache_{BLOCK_HASH_CACHE_SIZE};

    ArqmamqServer& arqmq_server_;

    bool force_start_ = false;

    std::atomic<int> arqmad_pings_ = 0;

    reachability_testing reach_records_;

    std::vector<message_t> relay_buffer_;

    mutable all_stats_t all_stats_;
    mutable std::recursive_mutex sn_mutex_;
    void save_if_new(const message_t& msg);

    // Save items to the database, notifying listeners as necessary
    void save_bulk(const std::vector<storage::Item>& items);

    void on_bootstrap_update(block_update_t& bu);

    void on_swarm_update(block_update_t& bu);

    void bootstrap_data();

    void bootstrap_peers(const std::vector<sn_record_t>& peers) const;

    void bootstrap_swarms(const std::vector<swarm_id_t>& swarms) const;

    /// Distribute all our data to where it belongs
    /// (called when our old node got dissolved)
    void salvage_data() const;

    void attach_signature(request_t& request, const signature& sig) const;

    void attach_pubkey(std::shared_ptr<request_t>& request) const;

    void relay_data_reliable(const std::string& blob, const sn_record_t& address) const;

    template <typename Message>
    void relay_messages(const std::vector<Message>& messages,
                        const std::vector<sn_record_t>& snodes) const;

    void ping_peers();

    void relay_buffered_messages();

    void arqmad_ping();

    /// Return tester/testee pair based on block_height
    bool derive_tester_testee(uint64_t block_height, sn_record_t& tester,
                              sn_record_t& testee);

    /// Send a request to a SN under test
    void send_storage_test_req(const sn_record_t& testee, uint64_t test_height,
                               const storage::Item& item);

    void process_storage_test_response(const sn_record_t& testee, const storage::Item& item,
                                       uint64_t test_height, sn_response_t&& res);

    /// Check if it is our turn to test and initiate peer test if so
    void initiate_peer_test();

    // Select a random message from our database, return false on error
    bool select_random_message(storage::Item& item);

    void test_reachability(const sn_record_t& sn, int previous_failures);

    void report_reachability(const sn_record_t& sn, bool reachable, int previous_failures);

    void sign_request(request_t& req) const;

  public:
    ServiceNode(boost::asio::io_context& ioc,
                sn_record_t address, const legacy_seckey& skey,
                ArqmamqServer& arqmq_server,
                const std::string& db_location,
                const bool force_start);

    const sn_record_t& own_address() { return our_address_; }
    void update_last_ping(ReachType type);
    void record_proxy_request();
    void record_onion_request();

    void send_onion_to_sn(const sn_record_t& sn, std::string_view payload, OnionRequestMetadata&& data, ss_client::Callback cb) const;

    void send_to_sn(const sn_record_t& sn, ss_client::ReqMethod method, ss_client::Request req, ss_client::Callback cb) const;

    bool hf_at_least(int hardfork) const { return hardfork_ >= hardfork; }

    // Return true if the service node is ready to start running
    bool snode_ready(std::string* reason = nullopt);

    /// Process message received from a client, return false if not in a swarm
    bool process_store(const message_t& msg);

    /// Process incoming blob of messages: add to DB if new
    void process_push_batch(const std::string& blob);

    // Attempt to find an answer (message body) to the storage test
    MessageTestStatus process_storage_test_req(uint64_t blk_height,
                                               const legacy_pubkey& tester_addr,
                                               const std::string& msg_hash,
                                               std::string& answer);

    bool is_pubkey_for_us(const user_pubkey_t& pk) const;

    std::vector<sn_record_t> get_snodes_by_pk(const user_pubkey_t& pk);

    /// return all messages for a particular PK (in JSON)
    bool get_all_messages(std::vector<storage::Item>& all_entries) const;

    bool retrieve(const std::string& pubKey, const std::string& last_hash, std::vector<storage::Item>& items);

    std::string get_stats_for_session_client() const;

    std::string get_stats() const;

    std::string get_status_line() const;

    template <typename PubKey>
    std::optional<sn_record_t> find_node(const PubKey& pk) const
    {
      std::lock_guard guard{sn_mutex_};
      if (swarm_)
        return swarm_->find_node(pk);
      return std::nullopt;
    }

    void on_arqmad_connected();

    void update_swarms();
};

} // namespace arqma
