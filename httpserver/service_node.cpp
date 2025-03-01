#include "service_node.h"

#include "Database.hpp"
#include "Item.hpp"
#include "arqma_common.h"
#include "arqma_logger.h"
#include "arqmad_key.h"
#include "http_connection.h"
#include "https_client.h"
#include "arqmq_server.h"
#include "net_stats.h"
#include "serialization.h"
#include "signature.h"
#include "utils.hpp"
#include "version.h"
#include <nlohmann/json.hpp>
#include <arqmamq/base32z.h>
#include <arqmamq/base64.h>
#include <arqmamq/hex.h>
#include <arqmamq/arqmamq.h>
#include "request_handler.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <string_view>
#include <boost/endian/conversion.hpp>

using json = nlohmann::json;
namespace sp = std::placeholders;

namespace arqma {

using storage::Item;

constexpr std::array<std::chrono::seconds, 8> RETRY_INTERVALS = { 1s, 5s, 10s, 20s, 40s, 80s, 160s, 320s };
constexpr std::chrono::milliseconds RELAY_INTERVAL = 350ms;

static void make_sn_request(boost::asio::io_context& ioc, const sn_record_t& sn,
                            std::shared_ptr<request_t> req,
                            http_callback_t&& cb) {
    ARQMA_LOG(trace, "make sn_request to {} @ {}:{}", sn.pubkey_legacy, sn.ip, sn.port);
    make_https_request_to_sn(ioc, sn, std::move(req}, std::move(cb));
}

/// TODO: there should be config.h to store constants like these
constexpr std::chrono::seconds STATS_CLEANUP_INTERVAL = 60min;
constexpr std::chrono::seconds ARQMAD_PING_INTERVAL = 30s;
constexpr int CLIENT_RETRIEVE_MESSAGE_LIMIT = 100;

ServiceNode::ServiceNode(boost::asio::io_context& ioc,
                         sn_record_t address,
                         const legacy_seckey& skey,
                         ArqmamqServer& arqmq_server,
                         const std::string& db_location,
                         const bool force_start)
  : ioc_(ioc),
    db_(std::make_unique<Database>(ioc, db_location)),
    our_address_{std::move(address)},
    our_seckey_{skey},
    arqmad_ping_timer_(ioc),
    stats_cleanup_timer_(ioc),
    peer_ping_timer_(ioc),
    relay_timer_(ioc),
    arqmq_server_(arqmq_server),
    force_start_(force_start)
{
  swarm_ = std::make_unique<Swarm>(our_address_);

  ARQMA_LOG(info, "Requesting initial swarm state");

  cleanup_timer_tick();
}

void ServiceNode::on_arqmad_connected()
{
  update_swarms();
  arqmad_ping_timer_tick();
  arqmq_server_->add_timer([this] { std::lock_guard l{sn_mutex_}; ping_peers_tick(); }, reachability_testing::TESTING_TIMER_INTERVAL);
}

static block_update_t parse_swarm_update(const std::string& response_body, bool from_json_rpc = false)
{
  if (response_body.empty())
  {
    ARQMA_LOG(critical, "Bad arqmad rpc response: no response body");
    throw std::runtime_error("Failed to parse swarm update");
  }

  std::map<swarm_id_t, std::vector<sn_record_t>> swarm_map;
  block_update_t bu;

  ARQMA_LOG(debug, "swarm response: {}", response_body);

  try
  {
    json result = json::parse(response_body, nullptr, true);
    if (from_json_rpc)
      result = result.ar("result");

    bu.height = result.at("height").get<uint64_t>();
    bu.block_hash = result.at("block_hash").get<std::string>();
    bu.hardfork = result.at("hardfork").get<int>();
    bu.unchanged = result.count("unchanged") && result.at("unchanged").get<bool>();
    if (bu.unchanged)
      return bu;

    const json service_node_states = result.at("service_node_states");

    for (const auto& sn_json : service_node_states) {
      const auto& pk_x25519_hex = sn_json.at("pubkey_x25519").get_ref<const std::string&>();
      const auto& pk_ed25519_hex = sn_json.at("pubkey_ed25519").get_ref<const std::string&>();

      if (pk_x25519_hex.empty() || pk_ed25519_hex.empty())
      {
        ARQMA_LOG(warn, "ed25519/x25519 pubkeys are missing from sn info");
        continue;
      }

      if (!sn_json.at("funded").get<bool>()) {
        continue;
      }

      auto sn = sn_record_t{
        sn_json.at("public_ip").get_ref<const std::string&>(),
        sn_json.at("storage_port").get<uint16_t>(),
        sn_json.at("storage_arqmq_port").get<uint16_t>(),
        legacy_pubkey::from_hex(sn_json.at("service_node_pubkey").get_ref<const std::string&>()),
        ed25519_pubkey::from_hex(pk_ed25519_hex),
        x25519_pubkey::from_hex(pk_x25519_hex)};

      const swarm_id_t swarm_id = sn_json.at("swarm_id").get<swarm_id_t>();

      if (swarm_id == INVALID_SWARM_ID) {
        bu.decommissioned_nodes.push_back(std::move(sn));
      } else {
        bu.active_x25519_pubkeys.emplace(sn.pubkey_x25519.view());

        swarm_map[swarm_id].push_back(std::move(sn));
      }
    }
  } catch (const std::exception& e) {
    ARQMA_LOG(critical, "Bad arqmad rpc response: invalid json ({})", e.what());
    throw std::runtime_error("Failed to parse swarm update");
  }

  for (auto const& swarm : swarm_map) {
    bu.swarms.emplace_back(SwarmInfo{swarm.first, swarm.second});
  }

  return bu;
}

void ServiceNode::bootstrap_data() {

    std::lock_guard guard(sn_mutex_);

    ARQMA_LOG(trace, "Bootstrapping peer data");

    json params{
      {"fields", {
        {"service_node_pubkey", true},
        {"swarm_id", true},
        {"storage_port", true},
        {"public_ip", true},
        {"height", true},
        {"block_hash", true},
        {"hardfork", true},
        {"funded", true},
        {"pubkey_x25519", true},
        {"pubkey_ed25519", true},
        {"storage_arqmq_port", true}
      }}
    };

    std::vector<std::pair<std::string, uint16_t>> seed_nodes;
    if (arqma::is_mainnet) {
      seed_nodes = {{{"us.pool.arqma.com", 19994},
                     {"eu.supportarqma.com", 19994},
                     {"194.233.64.43", 19994}}};
    } else {
      seed_nodes = {{{"161.97.102.172", 39994},
                     {"144.217.242.16", 39994}}};
    }

    auto req_counter = std::make_shared<size_t>(0);

    for (const auto& [addr, port] : seed_nodes)
    {
      arqmad_json_rpc_request(
        ioc_, addr, port, "get_service_nodes", params,
        [this, addr=addr, req_counter, node_count = seed_nodes.size()]
        (sn_response_t&& res) {
          if (res.error_code == SNodeError::NO_ERROR && res.body) {
            ARQMA_LOG(info, "Parsing response from seed {}", addr);
            try
            {
              const block_update_t bu = parse_swarm_update(*res.body, true);
              if (!bu.unchanged)
              {
                this->on_bootstrap_update(std::move(bu));
              }
              ARQMA_LOG(info, "Bootstrapped from {}", addr);
            } catch (const std::exception& e) {
              ARQMA_LOG(
                        error,
                        "Exception caught while bootstrapping from {}: {}",
                        addr, e.what());
            }
          } else {
            ARQMA_LOG(error, "Failed to contact bootstrap node {}", addr);
          }

          (*req_counter)++;

          if (*req_counter == node_count)
          {
            ARQMA_LOG(info, "Bootstrapping done");
            if (this->target_height_ > 0)
            {
              update_swarms();
            }
            else
            {
              ARQMA_LOG(warn, "Could not contact any of the seed nodes to get target "
                        "height. Going to assume our height is correct.");
              this->syncing_ = false;
            }
          }
        });
    }
}

bool ServiceNode::snode_ready(std::string* reason) {

    std::lock_guard guard(sn_mutex_);

    std::vector<std::string> problems;
    if (!hf_at_least(STORAGE_SERVER_HARDFORK))
      problems.push_back("yet not on Hardfork " + std::to_string(STORAGE_SERVER_HARDFORK));
    if (!swarm_ || !swarm_->is_valid())
      problems.push_back("not in any swarm");
    if (syncing_)
      problems.push_back("yet not done syncing");

    if (reason)
        *reason = util::join("; ", problems);

    return problems.empty() || force_start_;
}

void ServiceNode::send_onion_to_sn_v1(const sn_record_t& sn, const std::string& payload, const std::string& eph_key, ss_client::Callback cb) const
{
  arqmq_server_->request(sn.pubkey_x25519.view(), "sn.onion_req", std::move(cb), eph_key, payload);
}

void ServiceNode::send_onion_to_sn_v2(const sn_record_t& sn, const std::string& payload, const std::string& eph_key, ss_client::Callback cb) const
{
  arqmq_server_->request(sn.pubkey_x25519.view(), "sn.onion_req_v2", std::move(cb), arqmamq::send_option::request_timeout{10s}, eph_key, payload);
}

void ServiceNode::send_to_sn(const sn_record_t& sn, ss_client::ReqMethod method, ss_client::Request req, ss_client::Callback cb) const
{
  std::lock_guard guard(sn_mutex_);

  switch (method)
  {
    case ss_client::ReqMethod::DATA:
    {
      ARQMA_LOG(debug, "Sending sn.data request to {}", arqmamq::to_hex(sn.pubkey_x25519.view()));
      arqmq_server_->request(sn.pubkey_x25519.view(), "sn.data", std::move(cb), req.body);
      break;
    }
    case ss_client::ReqMethod::PROXY_EXIT:
    {
      auto client_key = req.headers.find(ARQMA_SENDER_KEY_HEADER);
      if (client_key != req.headers.end())
      {
        ARQMA_LOG(debug, "Sending sn.proxy_exit request to {}", arqmamq::to_hex(sn.pubkey_x25519.view()));
        arqmq_server_->request(sn.pubkey_x25519.view(), "sn.proxy_exit", std::move(cb), client_key->second, req.body);
      }
      else
      {
        ARQMA_LOG(debug, "Developer error: no {} passed in headers", ARQMA_SENDER_KEY_HEADER);
        assert(false);
      }
      break;
    }
    case ss_client::ReqMethod::ONION_REQUEST:
    {
      ARQMA_LOG(error, "Onion requests should not use this interface");
      assert(false);
      break;
    }
  }
}

void ServiceNode::relay_data_reliable(const std::string& blob, const sn_record_t& sn) const
{
  auto reply_callback = [](bool success, std::vector<std::string> data)
  {
    if (!success)
    {
      ARQMA_LOG(error, "Failed to send batch data: time-out");
    }
  };

  ARQMA_LOG(debug, "Relaying data to: {}, sn.pubkey_legacy);

  auto req = ss_client::Request{blob, {}};

  this->send_to_sn(sn, ss_client::ReqMethod::DATA, std::move(req), reply_callback);
}

void ServiceNode::record_proxy_request()
{
  all_stats_.bump_proxy_requests();
}

void ServiceNode::record_onion_request()
{
  all_stats_.bump_onion_requests();
}

/// do this asynchronously on a different thread? (on the same thread?)
bool ServiceNode::process_store(const message_t& msg) {
    std::lock_guard guard(sn_mutex_);

    /// only accept a message if we are in a swarm
    if (!swarm_) {
        // This should never be printed now that we have "snode_ready"
        ARQMA_LOG(error, "error: my swarm in not initialized");
        return false;
    }

    all_stats_.bump_store_requests();

    /// store in the database
    this->save_if_new(msg);

    this->relay_buffer_.push_back(msg);

    return true;
}

void ServiceNode::save_if_new(const message_t& msg) {
    std::lock_guard guard(sn_mutex_);

    if (db_->store(msg.hash, msg.pub_key, msg.data, msg.ttl, msg.timestamp, msg.nonce)) {
        ARQMA_LOG(trace, "saved message: {}", msg.data);
    }
}

void ServiceNode::save_bulk(const std::vector<Item>& items) {
    std::lock_guard guard(sn_mutex_);

    if (!db_->bulk_store(items)) {
        ARQMA_LOG(error, "failed to save batch to the database");
        return;
    }

    ARQMA_LOG(trace, "saved messages count: {}", items.size());
}

void ServiceNode::on_bootstrap_update(block_update_t& bu) {
    std::lock_guard guard(sn_mutex_);

    swarm_->apply_swarm_changes(bu.swarms);
    target_height_ = std::max(target_height_, bu.height);

    if (syncing_)
      arqmq_server_->set_active_sns(std::move(bu.active_x25519_pubkeys));
}

template <typename OStream>
OStream& operator<<(OStream& os, const SnodeStatus& status)
{
  switch (status)
  {
    case SnodeStatus::UNSTAKED: return os << "Unstaked";
    case SnodeStatus::DECOMMISSIONED: return os << "Decommissioned";
    case SnodeStatus::ACTIVE: return os << "Active";
    default: return os << "Unknown";
  }
}

static SnodeStatus derive_snode_status(const block_update_t& bu, const sn_record_t& our_address)
{
  const auto our_swarm_it = std::find_if(bu.swarms.begin(), bu.swarms.end(), [&our_address](const SwarmInfo& swarm_info) {
    const auto& snodes = swarm_info.snodes;
    return std::find(snodes.begin(), snodes.end(), our_address) != snodes.end();
  });

  if (our_swarm_it != bu.swarms.end())
  {
    return SnodeStatus::ACTIVE;
  }

  if (std::find(bu.decommissioned_nodes.begin(), bu.decommissioned_nodes.end(), our_address) != bu.decommissioned_nodes.end())
  {
    return SnodeStatus::DECOMMISSIONED;
  }

  return SnodeStatus::UNSTAKED;
}

void ServiceNode::on_swarm_update(const block_update_t& bu)
{
    if (this->hardfork_ != bu.hardfork)
    {
      ARQMA_LOG(debug, "New hardfork: {}", bu.hardfork);
      hardfork_ = bu.hardfork;
    }

    if (syncing_)
    {
      if (target_height_ == 0)
      {
        ARQMA_LOG(info, "Target height is 0, assuming we are synced");

        syncing_ = false;
      }
      else
      {
        syncing_ = bu.height < target_height_;
      }
    }

    /// We don't have anything to do until we have synced
    if (syncing_) {
        ARQMA_LOG(debug, "Still syncing: {}/{}", bu.height, target_height_);
        return;
    }

    if (bu.block_hash != block_hash_) {

        ARQMA_LOG(debug, "new block, height: {}, hash: {}", bu.height,
                  bu.block_hash);

        if (bu.height > block_height_ + 1 && block_height_ != 0) {
            ARQMA_LOG(warn, "Skipped some block(s), old: {} new: {}",
                      block_height_, bu.height);
            /// TODO: if we skipped a block, should we try to run peer tests for
            /// them as well?
        } else if (bu.height <= block_height_) {
            // TODO: investigate how testing will be affected under reorg
            ARQMA_LOG(warn,
                      "new block height is not higher than the current height");
        }

        block_height_ = bu.height;
        block_hash_ = bu.block_hash;

        block_hashes_cache_.push_back(std::make_pair(bu.height, bu.block_hash));

    } else {
        ARQMA_LOG(trace, "already seen this block");
        return;
    }

    arqmq_server_->set_active_sns(std::move(bu.active_x25519_pubkeys));

    const SwarmEvents events = swarm_->derive_swarm_events(bu.swarms);

    const auto status = derive_snode_status(bu, our_address_);

    if (this->status_ != status)
    {
      ARQMA_LOG(info, "Node status updated: {}", status);
      this->status_ = status;
    }

    swarm_->set_swarm_id(events.our_swarm_id);

    if (std::string reason; !snode_ready(&reason)) {
        ARQMA_LOG(warn, "Storage server is still not ready: {}", reason);
        return;
    } else {
        static bool active = false;
        if (!active) {
            ARQMA_LOG(info, "Storage server is now active!");

            relay_timer_.expires_after(RELAY_INTERVAL);
            relay_timer_.async_wait(std::bind(&ServiceNode::relay_buffered_messages, this));

            active = true;
        }
    }

    swarm_->update_state(bu.swarms, bu.decommissioned_nodes, events);

    if (!events.new_snodes.empty()) {
        this->bootstrap_peers(events.new_snodes);
    }

    if (!events.new_swarms.empty()) {
        this->bootstrap_swarms(events.new_swarms);
    }

    if (events.dissolved) {
        /// Go through all our PK and push them accordingly
        this->salvage_data();
    }

    this->initiate_peer_test();
}

void ServiceNode::relay_buffered_messages()
{
  std::lock_guard guard(sn_mutex_);

  relay_timer_.expires_after(RELAY_INTERVAL);
  relay_timer_.async_wait(std::bind(&ServiceNode::relay_buffered_messages, this));

  if (relay_buffer_.empty())
    return;

  ARQMA_LOG(debug, "Relaying {} messages from buffer to {} nodes", relay_buffer_.size(), swarm_->other_nodes().size());

  this->relay_messages(relay_buffer_, swarm_->other_nodes());
  relay_buffer_.clear();
}

void ServiceNode::update_swarms()
{
    std::lock_guard guard(sn_mutex_);

    ARQMA_LOG(debug, "Swarm update triggered");

    json params{
      {"fields", {
        {"service_node_pubkey", true},
        {"swarm_id", true},
        {"storage_port", true},
        {"public_ip", true},
        {"height", true},
        {"block_hash", true},
        {"hardfork", true},
        {"funded", true},
        {"pubkey_x25519", true},
        {"pubkey_ed25519", true},
        {"storage_arqmq_port", true}
      }},
      {"active_only", false}
    };
    if (!got_first_response_ && !block_hash_.empty())
      params["poll_block_hash"] = block_hash_;

    arqmq_server_.arqmad_request("rpc.get_service_nodes",
      [this](bool success, std::vector<std::string> data)
      {
        if (!success || data.size() < 2)
        {
          ARQMA_LOG(critical, "Failed to contact local arqmad for service node list");
          return;
        }
        try
        {
          std::lock_guard guard(sn_mutex_);
          block_update_t bu = parse_swarm_update(data[1]);
          if (!got_first_response_)
          {
            ARQMA_LOG(info, "Got initial swarm information from local Arqmad");
            got_first_response_ = true;

            auto [missing, total] = count_missing_data(bu);
            if (total >= (arqma::is_mainnet ? 100 : 10) && missing < 3*total/100)
            {
              ARQMA_LOG(info, "Initialized from arqmad with {}/{} SN records", total-missing, total);
              syncing_ = false;
            }
            else
            {
              ARQMA_LOG(info, "Detected some missing SN data ({}/{}); "
                        "querying bootstrap nodes for help", missing, total);
              this->bootstrap_data();
            }
          }

          if (!bu.unchanged)
          {
            OXEN_LOG(debug, "Blockchain updated, rebulding swarm list");
            on_swarm_update(std::move(bu));
          }
        }
        catch (const std::exception& e)
        {
          ARQMA_LOG(error, "Exception caught on swarm update: {}", e.what());
        }
      },
      params.dump();
    };
}

void ServiceNode::cleanup_timer_tick() {

    std::lock_guard guard(sn_mutex_);
    all_stats_.cleanup();

    stats_cleanup_timer_.expires_after(STATS_CLEANUP_INTERVAL);
    stats_cleanup_timer_.async_wait(std::bind(&ServiceNode::cleanup_timer_tick, this));
}

void ServiceNode::update_last_ping(bool arqmq)
{
  reach_records_.incoming_ping(arqmq);
}

void ServiceNode::ping_peers_tick() {

    if (this->status_ == SnodeStatus::UNSTAKED || this->status_ == SnodeStatus::UNKNOWN)
    {
      ARQMA_LOG(trace, "Skipping peer testing (unstaked)");
      return;
    }

    auto now = std::chrono::steady_clock::now();

    reach_records_.check_incoming_tests(now);

    if (this->status_ == SnodeStatus::DECOMMISSIONED)
    {
      ARQMA_LOG(trace, "Skipping peer testing (decommissioned)");
      return;
    }

    auto to_test = reach_records_.get_failing(*swarm_, now);
    if (auto rando = reach_records_.next_random(*swarm_, now))
      to_test.emplace_back(std::move(*rando), 0);

    if (to_test.empty())
      return;

    for (const auto& [sn, prev_fails] : to_test)
      test_reachability(sn, prev_fails);
}

void ServiceNode::sign_request(request_t& req) const
{
  const auto hash = hash_data(req.body());
  const auto signature = generate_signature(hash, {our_address_.pubkey_legacy, our_seckey_});
  attach_signature(req, signature);
}

void ServiceNode::test_reachability(const sn_record_t& sn, int previous_failures)
{
    ARQMA_LOG(debug, "Testing {} SN {} for reachability",
              previous_failures > 0 ? "previously failing" : "random",
              sn.pubkey_legacy);

    static constexpr uint8_t TEST_WAITING = 0, TEST_FAILED = 1, TEST_PASSED = 2;

    auto test_results = std::make_shared<std::pair<const sn_record_t, std::atomic<uint8_t>>>(sn, 0);

    auto http_callback = [this, test_results, previous_failures](sn_response_t&& res)
    {
      auto& [sn, result] = *test_results;

      ARQMA_LOG(debug, "{} response for HTTP ping test of {}",
                success ? "Successful" : "FAILED", sn.pubkey_legacy);

      if (result.exchange(success ? TEST_PASSED : TEST_FAILED) != TEST_WAITING)
        report_reachability(sn, success && result == TEST_PASSED, previous_failures);
    };

    auto req = build_post_request(sn.pubkey_ed25519, "/swarms/ping_test/v1", "{}");
    this->sign_request(*req);

    make_sn_request(ioc_, sn, std::move(req), std::move(http_callback));

    arqmq_server_->request(
      sn.pubkey_x25519.view(), "sn.onion_req",
      [this, test_results=std::move(test_results), previous_failures](bool success, const auto&) {
        auto& [sn, result] = *test_results;

        ARQMA_LOG(debug, "{} response for ArqmaMQ ping test of {}",
                  success ? "Successful" : "FAILED", sn.pubkey_legacy);

        if (result.exchange(success ? TEST_PASSED : TEST_FAILED) != TEST_WAITING)
          report_reachability(sn, success && result == TEST_PASSED, previous_failures);
      },
      "ping",
      arqmamq::send_option::outgoing{}
    );
}

void ServiceNode::arqmad_ping_timer_tick() {

    std::lock_guard guard(sn_mutex_);

    json params{
      {"version", STORAGE_SERVER_VERSION},
      {"https_port", our_address_.port()},
      {"arqmq_port", our_address_.arqmq_port()}};

    arqmq_server_.arqmad_request("admin.storage_server_ping",
      [this](bool success, std::vector<std::string> data) {
        if (!success)
          ARQMA_LOG(critical, "Could not ping arqmad: Request failed ({})", data.front());
        else if (data.size() < 2 || data[1].empty())
          ARQMA_LOG(critical, "Could not ping arqmad: Empty body on reply");
        else
          try {
            if (const auto status = json::parse(data[1]).at("status").get<std::string>();
                status == "OK")
            {
              auto good_pings = ++arqmad_pings_;
              if (good_pings == 1)
                ARQMA_LOG(info, "Successfully pinged Arqmad");
              else if (good_pings % (1h / ARQMAD_PING_INTERVAL) == 0)
                ARQMA_LOG(info, "{} successful Arqmad pings", good_pings);
              else
                ARQMA_LOG(debug, "Successfully pinged Arqmad ({} consecutive times)", good_pings);
            }
            else
            {
              ARQMA_LOG(critical, "Could not ping arqmad: {}", status);
              arqmad_pings_ = 0;
            }
          } catch (...) {
            ARQMA_LOG(critical, "Could not ping arqmad: bad json in response");
          }
      },
      params.dump()
    };

    arqmq_server_.arqmad_request("sub.block", [](bool success, auto&& result) {
      if (!success || result.empty())
        ARQMA_LOG(critical, "Failed to subscribe to arqmad block notifications: {}",
                  result.empty() ? "response is empty" : result.front());
      else if (result.front() == "OK")
        ARQMA_LOG(info, "Subscribed to arqmad new block notifications");
      else if (result.front() == "ALREADY")
        ARQMA_LOG(debug, "Renewed arqmad new block notificarion subscription");
    });

    arqmad_ping_timer_.expires_after(ARQMAD_PING_INTERVAL);
    arqmad_ping_timer_.async_wait(
        std::bind(&ServiceNode::arqmad_ping_timer_tick, this));
}

void ServiceNode::attach_signature(request_t& request,
                                   const signature& sig) const {

    std::string raw_sig;
    raw_sig.reserve(sig.c.size() + sig.r.size());
    raw_sig.insert(raw_sig.begin(), sig.c.begin(), sig.c.end());
    raw_sig.insert(raw_sig.end(), sig.r.begin(), sig.r.end());

    const std::string sig_b64 = arqmamq::to_base64(raw_sig);
    request.set(ARQMA_SNODE_SIGNATURE_HEADER, sig_b64);

    request.set(ARQMA_SENDER_SNODE_PUBKEY_HEADER, arqmamq::to_base32z(our_address_.pubkey_legacy.view()));
}

void ServiceNode::process_storage_test_response(const sn_record_t& testee, const Item& item,
                                                uint64_t test_height, sn_response_t&& res) {

  std::lock_guard guard(sn_mutex_);

  if (res.error_code != SNodeError::NO_ERROR) {
    this->all_stats_.record_storage_test_result(testee.pubkey_legacy, ResultType::OTHER);
    ARQMA_LOG(debug, "Failed to send a storage test request to snode: {}", testee.pubkey_legacy);
    return;
  }

  if (!res.body) {
    this->all_stats_.record_storage_test_result(testee.pubkey_legacy, ResultType::OTHER);
    ARQMA_LOG(debug, "Empty body in storage test response");
    return;
  }

  ResultType result = ResultType::OTHER;

  try {

    json res_json = json::parse(*res.body);

    const auto status = res_json.at("status").get<std::string>();

    if (status == "OK") {
      const auto value = res_json.at("value").get<std::string>();
      if (value == item.data) {
        ARQMA_LOG(debug, "Storage test is successful for: {} at height: {}", testee.pubkey_legacy, test_height);
        result = ResultType::OK;
      } else {
        ARQMA_LOG(debug, "Test answer doesn't match for: {} at height: {}", testee.pubkey_legacy, test_height);
        result = ResultType::MISMATCH;
      }
    } else if (status == "wrong request") {
      ARQMA_LOG(debug, "Storage test rejected by testee");
      result = ResultType::REJECTED;
    } else {
      result = ResultType::OTHER;
      ARQMA_LOG(debug, "Storage test failed for unknown reason");
    }
  } catch(...) {
    result = ResultType::OTHER;
    ARQMA_LOG(debug, "Invalid json in storage test response");
  }

  this->all_stats_.record_storage_test_result(testee.pubkey_legacy, result);
}

void ServiceNode::send_storage_test_req(const sn_record_t& testee,
                                        uint64_t test_height,
                                        const Item& item) {

    std::lock_guard guard(sn_mutex_);

    nlohmann::json json_body;

    json_body["height"] = test_height;
    json_body["hash"] = item.hash;

    auto req = build_post_request(testee.pubkey_ed25519, "/swarms/storage_test/v1", json_body.dump());

    this->sign_request(*req);

    make_sn_request(ioc_, testee, req, [testee, item, height = this->block_height_, this](sn_response_t&& res) {
      this->process_storage_test_response(testee, item, height, std::move(res));
    });
}

void ServiceNode::report_reachability(const sn_record_t& sn, bool reachable, int previous_failures)
{
  auto cb = [sn_pk=sn.pubkey_legacy, reachable](bool success, std::vector<std::string> data)
  {
    if (!success)
    {
      ARQMA_LOG(warn, "Could not report node status: {}", data.empty() ? "unknown reason" : data[0]);
      return;
    }

    if (data.size() < 2 || data[1].empty()) {
            ARQMA_LOG(warn, "Empty body on Arqmad reportnode status");
            return;
    }

    try {
            const auto status = json::parse(data[1]).at("status").get<std::string>();

            if (status == "OK") {
              ARQMA_LOG(debug, "Successfully reported {} node: {}", reachable ? "reachable" : "UNREACHABLE", sn_pk);
            } else {
                ARQMA_LOG(warn, "Could not report node: {}", status);
            }
        } catch (...) {
            ARQMA_LOG(error,
                      "Could not report node status: bad json in reponse");
        }
  };

  json params{
    {"type", "reachability"},
    {"pubkey", sn.pubkey_legacy.hex()},
    {"passed", reachable}
  };

  arqmq_server_.arqmad_request("admin.report_peer_storage_server_status",
                                       std::move(cb), params.dump());
  if (!reachable)
  {
    std::lock_guard guard(sn_mutex_);
    reach_records_.add_failing_node(sn.pubkey_legacy, previous_failures);
  }
}

// Deterministically selects two random swarm members; returns true on success
bool ServiceNode::derive_tester_testee(uint64_t blk_height, sn_record_t& tester,
                                       sn_record_t& testee) {
    std::lock_guard guard(sn_mutex_);
    std::vector<sn_record_t> members = swarm_->other_nodes();
    members.push_back(our_address_);

    if (members.size() < 2) {
        ARQMA_LOG(debug, "Could not initiate peer test: swarm too small");
        return false;
    }

    std::sort(members.begin(), members.end(), [](const auto& a, const auto& b) { return a.pubkey_legacy < b.pubkey_legacy; });

    std::string block_hash;
    if (blk_height == block_height_) {
        block_hash = block_hash_;
    } else if (blk_height < block_height_) {

        ARQMA_LOG(trace, "got storage test request for an older block: {}/{}",
                  blk_height, block_height_);

        const auto it =
            std::find_if(block_hashes_cache_.begin(), block_hashes_cache_.end(),
                         [=](const std::pair<uint64_t, std::string>& val) {
                             return val.first == blk_height;
                         });

        if (it != block_hashes_cache_.end()) {
            block_hash = it->second;
        } else {
            ARQMA_LOG(trace, "Could not find hash for a given block height");
            // TODO: request from arqmad?
            return false;
        }
    } else {
        assert(false);
        ARQMA_LOG(debug, "Could not find hash: block height is in the future");
        return false;
    }

    uint64_t seed;
    if (block_hash.size() < sizeof(seed)) {
        ARQMA_LOG(error, "Could not initiate peer test: invalid block hash");
        return false;
    }

    std::memcpy(&seed, block_hash.data(), sizeof(seed));
    boost::endian::little_to_native_inplace(seed);
    std::mt19937_64 mt(seed);
    const auto tester_idx =
        util::uniform_distribution_portable(mt, members.size());
    tester = members[tester_idx];

    uint64_t testee_idx;
    do {
        testee_idx = util::uniform_distribution_portable(mt, members.size());
    } while (testee_idx == tester_idx);

    testee = members[testee_idx];

    return true;
}

MessageTestStatus ServiceNode::process_storage_test_req(
    uint64_t blk_height, const legacy_pubkey& tester_pk,
    const std::string& msg_hash, std::string& answer) {

    std::lock_guard guard(sn_mutex_);
    // 1. Check height, retry if we are behind
    std::string block_hash;

    if (blk_height > block_height_) {
        ARQMA_LOG(debug, "Our blockchain is behind, height: {}, requested: {}",
                  block_height_, blk_height);
        return MessageTestStatus::RETRY;
    }

    // 2. Check tester/testee pair
    {
        sn_record_t tester;
        sn_record_t testee;
        this->derive_tester_testee(blk_height, tester, testee);

        if (testee != our_address_) {
            ARQMA_LOG(error, "We are NOT the testee for height: {}",
                      blk_height);
            return MessageTestStatus::WRONG_REQ;
        }

        if (tester.pubkey_legacy != tester_pk) {
            ARQMA_LOG(debug, "Wrong tester: {}, expected: {}", tester_pk,
                      tester.pubkey_legacy);
            return MessageTestStatus::WRONG_REQ;
        } else {
            ARQMA_LOG(trace, "Tester is valid: {}", tester_pk);
        }
    }

    // 3. If for a current/past block, try to respond right away
    Item item;
    if (!db_->retrieve_by_hash(msg_hash, item)) {
        return MessageTestStatus::RETRY;
    }

    answer = item.data;
    return MessageTestStatus::SUCCESS;
}

bool ServiceNode::select_random_message(Item& item) {

    uint64_t message_count;
    if (!db_->get_message_count(message_count)) {
        ARQMA_LOG(error, "Could not count messages in the database");
        return false;
    }

    ARQMA_LOG(debug, "total messages: {}", message_count);

    if (message_count == 0) {
        ARQMA_LOG(debug, "No messages in the database to initiate a peer test");
        return false;
    }

    // SNodes don't have to agree on this, rather they should use different
    // messages
    const auto msg_idx = util::uniform_distribution_portable(message_count);

    if (!db_->retrieve_by_index(msg_idx, item)) {
        ARQMA_LOG(error, "Could not retrieve message by index: {}", msg_idx);
        return false;
    }

    return true;
}

void ServiceNode::initiate_peer_test() {

    std::lock_guard guard(sn_mutex_);
    // 1. Select the tester/testee pair
    sn_record_t tester, testee;

    constexpr uint64_t TEST_BLOCKS_BUFFER = 4;

    if (block_height_ < TEST_BLOCKS_BUFFER) {
        ARQMA_LOG(debug, "Height {} is too small, skipping all tests",
                  block_height_);
        return;
    }

    const uint64_t test_height = block_height_ - TEST_BLOCKS_BUFFER;

    if (!this->derive_tester_testee(test_height, tester, testee)) {
        return;
    }

    ARQMA_LOG(trace, "For height {}; tester: {} testee: {}", test_height,
              tester.pubkey_legacy, testee.pubkey_legacy);

    if (tester != our_address_) {
        /// Not our turn to initiate a test
        return;
    }

    /// 2. Storage Testing
    {
        // 2.1. Select a message
        Item item;
        if (!this->select_random_message(item)) {
            ARQMA_LOG(debug, "Could not select a message for testing");
        } else {
            ARQMA_LOG(trace, "Selected random message: {}, {}", item.hash,
                      item.data);

            // 2.2. Initiate testing request
            this->send_storage_test_req(testee, test_height, item);
        }
    }
}

void ServiceNode::bootstrap_peers(const std::vector<sn_record_t>& peers) const {

    std::vector<Item> all_entries;
    this->get_all_messages(all_entries);

    this->relay_messages(all_entries, peers);
}

void ServiceNode::bootstrap_swarms(
    const std::vector<swarm_id_t>& swarms) const {

    std::lock_guard guard(sn_mutex_);

    if (swarms.empty()) {
        ARQMA_LOG(info, "Bootstrapping all swarms");
    } else {
        ARQMA_LOG(info, "Bootstrapping swarms: [{}]", util::join(" ", swarms));
    }

    const auto& all_swarms = swarm_->all_valid_swarms();

    std::vector<Item> all_entries;
    if (!get_all_messages(all_entries)) {
        ARQMA_LOG(error, "Could not retrieve entries from the database");
        return;
    }

    std::unordered_map<swarm_id_t, size_t> swarm_id_to_idx;
    for (auto i = 0u; i < all_swarms.size(); ++i) {
        swarm_id_to_idx.insert({all_swarms[i].swarm_id, i});
    }

    /// See what pubkeys we have
    std::unordered_map<std::string, swarm_id_t> cache;

    ARQMA_LOG(debug, "We have {} messages", all_entries.size());

    std::unordered_map<swarm_id_t, std::vector<Item>> to_relay;

    for (auto& entry : all_entries) {

        swarm_id_t swarm_id;
        const auto it = cache.find(entry.pub_key);
        if (it == cache.end()) {
            bool success;
            auto pk = user_pubkey_t::create(entry.pub_key, success);

            if (!success) {
                ARQMA_LOG(error, "Invalid pubkey in a message while "
                                 "bootstrapping other nodes");
                continue;
            }

            swarm_id = get_swarm_by_pk(all_swarms, pk);
            cache.insert({entry.pub_key, swarm_id});
        } else {
            swarm_id = it->second;
        }

        bool relevant = false;
        for (const auto swarm : swarms) {

            if (swarm == swarm_id) {
                relevant = true;
            }
        }

        if (relevant || swarms.empty()) {

            to_relay[swarm_id].emplace_back(std::move(entry));
        }
    }

    ARQMA_LOG(trace, "Bootstrapping {} swarms", to_relay.size());

    for (const auto& [swarm_id, items] : to_relay) {
        /// what if not found?
        const size_t idx = swarm_id_to_idx[swarm_id];

        relay_messages(items, all_swarms[idx].snodes);
    }
}

template <typename Message>
void ServiceNode::relay_messages(const std::vector<Message>& messages,
                                 const std::vector<sn_record_t>& snodes) const {
    std::vector<std::string> batches = serialize_messages(messages);

    ARQMA_LOG(debug, "Relayed messages:");
    for (auto msg : batches)
    {
      ARQMA_LOG(debug, "    {}", msg);
    }
    ARQMA_LOG(debug, "To Snodes:");
    for (auto sn : snodes)
    {
      ARQMA_LOG(debug, "    {}", sn.pubkey_legacy);
    }

    ARQMA_LOG(debug, "Serialised batches: {}", batches.size());
    for (const sn_record_t& sn : snodes) {
        for (auto& batch : batches) {
            this->relay_data_reliable(batch, sn);
        }
    }
}

void ServiceNode::salvage_data() const {

    /// This is very similar to ServiceNode::bootstrap_swarms, so just reuse it
    bootstrap_swarms({});
}

bool ServiceNode::retrieve(const std::string& pubKey,
                           const std::string& last_hash,
                           std::vector<Item>& items) {
    std::lock_guard guard(sn_mutex_);

    all_stats_.bump_retrieve_request();

    return db_->retrieve(pubKey, items, last_hash,
                         CLIENT_RETRIEVE_MESSAGE_LIMIT);
}

void to_json(nlohmann::json& j, const test_result_t& val) {
    j["timestamp"] = val.timestamp;
    j["result"] = to_str(val.result);
}

static nlohmann::json to_json(const all_stats_t& stats) {

    nlohmann::json json;

    json["total_store_requests"] = stats.get_total_store_requests();
    json["recent_store_requests"] = stats.get_recent_store_requests();
    json["previous_period_store_requests"] = stats.get_previous_period_store_requests();

    json["total_retrieve_requests"] = stats.get_total_retrieve_requests();
    json["recent_store_requests"] = stats.get_recent_store_requests();
    json["previous_period_retrieve_requests"] = stats.get_previous_period_retrieve_requests();
    json["previous_period_onion_requests"] = stats.get_previous_period_onion_requests();

    json["reset_time"] = std::chrono::duration_cast<std::chrono::seconds>(stats.get_reset_time().time_since_epoch()).count();

    nlohmann::json peers;

    for (const auto& [pk, stats] : stats.peer_report_) {
        auto pubkey = pk.hex();

        peers[pubkey]["requests_failed"] = stats.requests_failed;
        peers[pubkey]["pushes_failed"] = stats.requests_failed;
        peers[pubkey]["storage_tests"] = stats.storage_tests;
    }

    json["peers"] = peers;
    return json;
}

std::string ServiceNode::get_stats_for_session_client() const
{
  nlohmann::json res;
  res["version"] = STORAGE_SERVER_VERSION_STRING;

  constexpr bool PRETTY = true;
  constexpr int indent = PRETTY ? 4 : 0;
  return res.dump(indent);
}

std::string ServiceNode::get_stats() const {

    std::lock_guard guard(sn_mutex_);

    auto val = to_json(all_stats_);

    val["version"] = STORAGE_SERVER_VERSION_STRING;
    val["height"] = block_height_;
    val["target_height"] = target_height_;

    uint64_t total_stored;
    if (db_->get_message_count(total_stored)) {
        val["total_stored"] = total_stored;
    }

    val["connections_in"] = get_net_stats().connections_in.load();
    val["http_connections_out"] = get_net_stats().http_connections_out.load();
    val["https_connections_out"] = get_net_stats().https_connections_out.load();

    /// we want pretty (indented) json, but might change that in the future
    constexpr bool PRETTY = true;
    constexpr int indent = PRETTY ? 4 : 0;
    return val.dump(indent);
}

std::string ServiceNode::get_status_line() const
{
  std::lock_guard guard(sn_mutex_);

  std::ostringstream s;
  s << 'v' << STORAGE_SERVER_VERSION_STRING;
  if (!arqma::is_mainnet) s << " (STAGENET)";

  if (syncing_)
    s << "; SYNCING";
  s << "; sw=";
  if (!swarm_ || !swarm_->is_valid())
    s << "NONE";
  else
  {
    std::string swarm = std::to_string(swarm_->our_swarm_id());
    if (swarm.size() <= 6)
      s << swarm;
    else
      s << swarm.substr(0, 4) << u8"…" << swarm.back();
    s << "(n=" << (1 + swarm_->other_nodes().size()) << ")";
  }
  uint64_t total_stored;
  if (db_->get_message_count(total_stored))
    s << "; " << total_stored << " msgs";
  s << "; reqs(S/R): " << all_stats_.get_total_store_requests() << '/' << all_stats_.get_total_retrieve_requests();
  s << "; conns(in/http/https): " << get_net_stats().connections_in << '/' << get_net_stats().http_connections_out << '/' << get_net_stats().https_connections_out;
  return s.str();
}

bool ServiceNode::get_all_messages(std::vector<Item>& all_entries) const {

    std::lock_guard guard(sn_mutex_);

    ARQMA_LOG(trace, "Get all messages");

    return db_->retrieve("", all_entries, "");
}

void ServiceNode::process_push_batch(const std::string& blob)
{
    std::lock_guard guard(sn_mutex_);

    if (blob.empty())
        return;

    std::vector<message_t> messages = deserialize_messages(blob);

    ARQMA_LOG(trace, "Saving all: begin");

    ARQMA_LOG(debug, "Got {} messages from peers, size: {}", messages.size(),
              blob.size());

    std::vector<Item> items;
    items.reserve(messages.size());

    // TODO: avoid copying m.data
    // Promoting message_t to Item:
    std::transform(messages.begin(), messages.end(), std::back_inserter(items),
                   [](const message_t& m) {
                       return Item{m.hash, m.pub_key,           m.timestamp,
                                   m.ttl,  m.timestamp + m.ttl, m.nonce,
                                   m.data};
                   });

    this->save_bulk(items);

    ARQMA_LOG(trace, "Saving all: end");
}

bool ServiceNode::is_pubkey_for_us(const user_pubkey_t& pk) const
{
    std::lock_guard guard(sn_mutex_);

    if (!swarm_) {
        ARQMA_LOG(error, "Swarm data missing");
        return false;
    }
    return swarm_->is_pubkey_for_us(pk);
}

std::vector<sn_record_t>
ServiceNode::get_snodes_by_pk(const user_pubkey_t& pk)
{
    std::lock_guard guard(sn_mutex_);

    if (!swarm_) {
        ARQMA_LOG(error, "Swarm data missing");
        return {};
    }

    const auto& all_swarms = swarm_->all_valid_swarms();

    swarm_id_t swarm_id = get_swarm_by_pk(all_swarms, pk);

    // TODO: have get_swarm_by_pk return idx into all_swarms instead,
    // so we don't have to find it again

    for (const auto& si : all_swarms) {
        if (si.swarm_id == swarm_id)
            return si.snodes;
    }

    ARQMA_LOG(critical, "Something went wrong in get_snodes_by_pk");

    return {};
}

} // namespace arqma
