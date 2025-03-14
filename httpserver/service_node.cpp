#include "service_node.h"

#include "Database.hpp"
#include "Item.hpp"
#include "http.h"
#include "arqma_logger.h"
#include "request_handler.h"
#include "arqmq_server.h"
#include "serialization.h"
#include "signature.h"
#include "string_utils.hpp"
#include "utils.hpp"
#include "version.h"

#include <boost/endian/conversion.hpp>
#include <cpr/cpr.h>
#include <nlohmann/json.hpp>
#include <arqma-mq/base32z.h>
#include <arqma-mq/base64.h>
#include <arqma-mq/hex.h>
#include <arqma-mq/arqmamq.h>

#include <algorithm>

using json = nlohmann::json;
namespace sp = std::placeholders;

namespace arqma {

using storage::Item;

constexpr std::chrono::milliseconds RELAY_INTERVAL = 350ms;

using MISSING_PUBKEY_THRESHOLD = std::ratio<3, 100>;

/// TODO: there should be config.h to store constants like these
constexpr std::chrono::seconds STATS_CLEANUP_INTERVAL = 60min;
constexpr std::chrono::seconds ARQMAD_PING_INTERVAL = 30s;
constexpr int CLIENT_RETRIEVE_MESSAGE_LIMIT = 100;

ServiceNode::ServiceNode(sn_record_t address,
                         const legacy_seckey& skey,
                         ArqmamqServer& arqmq_server,
                         const std::filesystem::path& db_location,
                         const bool force_start)
  : force_start_{force_start},
    db_{std::make_unique<Database>(db_location)},
    our_address_{std::move(address)},
    our_seckey_{skey},
    arqmq_server_{arqmq_server}
{
  swarm_ = std::make_unique<Swarm>(our_address_);

  ARQMA_LOG(info, "Requesting initial swarm state");

  arqmq_server->add_timer([this] { std::lock_guard l{sn_mutex_}; db_->clean_expired(); }, Database::CLEANUP_PERIOD);

  arqmq_server_->add_timer([this] { std::lock_guard l{sn_mutex_}; all_stats_.cleanup(); }, STATS_CLEANUP_INTERVAL);

  arqmq_server_->add_timer([this] { outstanding_https_reqs_.remove_if([](auto& f) { return f.wait_for(0ms) == std::future_status::ready; }); }, 1s);

  auto delay_timer = std::make_shared<arqmamq::TimerID>();
  auto& dtimer = *delay_timer;
  arqmq_server_->add_timer(dtimer, [this, timer=std::move(delay_timer)]
  {
    arqmq_server_->cancel_timer(*timer);
    std::lock_guard lock{sn_mutex_};
    if (!syncing_)
      return;
    ARQMA_LOG(warn, "Block syncing is taking too long. Activating SS regardless");
    syncing_ = false;
  }, 1h);
}

void ServiceNode::on_arqmad_connected()
{
  update_swarms();
  arqmad_ping();
  arqmq_server_->add_timer([this] { arqmad_ping(); }, ARQMAD_PING_INTERVAL);
  arqmq_server_->add_timer([this] { ping_peers(); }, reachability_testing::TESTING_TIMER_INTERVAL);
  arqmq_server_->add_timer([this] { relay_buffered_messages(); }, RELAY_INTERVAL);
}

static block_update_t parse_swarm_update(const std::string& response_body)
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

    bu.height = result.at("height").get<uint64_t>();
    bu.block_hash = result.at("block_hash").get<std::string>();
    bu.hardfork = result.at("hardfork").get<int>();
    bu.unchanged = result.count("unchanged") && result.at("unchanged").get<bool>();
    if (bu.unchanged)
      return bu;

    const json service_node_states = result.at("service_node_states");

    int missing_aux_pks = 0, total = 0;

    for (const auto& sn_json : service_node_states)
    {
      if (!sn_json.at("funded").get<bool>())
      {
        continue;
      }

      total++;
      const auto& pk_hex = sn_json.at("service_node_pubkey").get_ref<const std::string&>();
      const auto& pk_x25519_hex = sn_json.at("pubkey_x25519").get_ref<const std::string&>();
      const auto& pk_ed25519_hex = sn_json.at("pubkey_ed25519").get_ref<const std::string&>();

      if (pk_x25519_hex.empty() || pk_ed25519_hex.empty())
      {
        missing_aux_pks++;
        ARQMA_LOG(debug, "ed25519/x25519 pubkeys are missing from sn info {}", pk_hex);
        continue;
      }

      auto sn = sn_record_t{
        sn_json.at("public_ip").get_ref<const std::string&>(),
        sn_json.at("storage_port").get<uint16_t>(),
        sn_json.at("storage_arqmq_port").get<uint16_t>(),
        legacy_pubkey::from_hex(pk_hex),
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

    if (missing_aux_pks > MISSING_PUBKEY_THRESHOLD::num*total/MISSING_PUBKEY_THRESHOLD::den)
    {
      ARQMA_LOG(warn, "Missing ed25519/x25519 pubkeys for {}/{} service nodes; "
                      "arqmad may be out of sync with the network", missing_aux_pks, total);
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

    std::string params = json{
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
    }.dump();

    std::vector<arqmamq::address> seed_nodes;
    if (arqma::is_mainnet) {
      seed_nodes = {{
        "tcp://us.pool.arqma.com:19994",
        "tcp://eu.supportarqma.com:19994",
        "tcp://194.233.64.43:19994
      }};
    } else {
      seed_nodes = {{
        "tcp://161.97.102.172:39994",
        "tcp://144.217.242.16:39994"
      }};
    }

    auto req_counter = std::make_shared<std::atomic<int>>(0);

    for (const auto& addr : seed_nodes)
    {
      auto connid = arqmq_server_->connect_remote(addr,
        [addr](arqmamq::ConnectionID)
        {
          ARQMA_LOG(debug, "Connected to bootstrap node {}", addr);
        },
        [addr](arqmamq::ConnectionID, auto reason)
        {
          ARQMA_LOG(debug, "Failed to connect to bootstrap node {}: {}", addr, reason);
        },
        arqmamq::connect_option::ephemeral_routing_id{true};,
        arqmamq::connect_option::timeout{BOOTSTRAP_TIMEOUT}
      };
      arqmq_server_->request(connid, "rpc.get_service_nodes",
        [this, connid, addr, req_counter, node_count=(int)seed_nodes.size()](bool success, auto data)
        {
          if (!success)
            ARQMA_LOG(err, "Failed to contact bootstrap node {}: request timed out", addr);
          else if (data.empty())
            ARQMA_LOG(err, "Failed to request bootstrap node data from {}: request returned no data", addr);
          else if (data[0] != "200")
            ARQMA_LOG(err, "Failed to request bootstrap node data from {}: request returned failure status {}", addr, data[0]);
          else
          {
            ARQMA_LOG(info, "Parsing response from bootstrap node {}", addr);
            try
            {
              auto update = parse_swarm_update(data[1]);
              if (!update.unchanged)
                on_bootstrap_update(std::move(update));
              ARQMA_LOG(info, "Bootstrapped from {}", addr);
            } catch (const std::exception& e) {
              ARQMA_LOG(err, "Exception caught while bootstrapping from {}: {}", addr, e.what());
            }
          }

          arqmq_server_->disconned(connid);

          if (++(*req_counter) == node_count)
          {
            ARQMA_LOG(info, "Bootstrapping done");
            if (target_height_ > 0)
              update_swarms();
            else
            {
              ARQMA_LOG(warn, "Could not contact any of the seed nodes to get target height. Going to assume our height is correct.");
              syncing_ = false;
            }
          }
        },
        params,
        arqmamq::send_option::request_timeout{BOOTSTRAP_TIMEOUT}
      );
    }
}

void ServiceNode::shutdown()
{
  shutting_down_ = true;
}

bool ServiceNode::snode_ready(std::string* reason)
{
    if (shutting_down())
    {
      if (reason)
        *reason = "shutting down";
      return false;
    }

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

void ServiceNode::send_onion_to_sn(const sn_record_t& sn, std::string_view payload, OnionRequestMetadata&& data, std::function<void(bool success, std::vector<std::string> data)> cb) const
{
  data.hop_no++;
  arqmq_server_->request(sn.pubkey_x25519.view(), "sn.onion_request", std::move(cb), arqmamq::send_option::request_timeout{30s}, arqmq_server_.encode_onion_data(payload, data));
}

void ServiceNode::relay_data_reliable(const std::string& blob, const sn_record_t& sn) const
{
  ARQMA_LOG(debug, "Relaying data to: {} (x25519_pubkey {})", sn.pubkey_legacy, sn.pubkey_x25519);
  arqmq_server_->request(sn.pubkey_x25519.view(), "sn.data", [](bool success, auto&& data)
  {
    if (!success)
      ARQMA_LOG(err, "Failed to send batch data: time-out");
  }, blob);
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
        ARQMA_LOG(err, "error: my swarm in not initialized");
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
        ARQMA_LOG(err, "failed to save batch to the database");
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

        while (block_hashes_cache_.size() >= BLOCK_HASH_CACHE_SIZE)
          block_hashes_cache_.erase(block_hashes_cache_.begin());

        block_hashes_cache_.emplace_hint(block_hashes_cache_.end(), bu.height, std::move(bu.block_hash));
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
        if (!active_) {
            ARQMA_LOG(info, "Storage server is now active!");
            active_ = true;
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

  if (relay_buffer_.empty())
    return;

  ARQMA_LOG(debug, "Relaying {} messages from buffer to {} nodes", relay_buffer_.size(), swarm_->other_nodes().size());

  this->relay_messages(relay_buffer_, swarm_->other_nodes());
  relay_buffer_.clear();
}

void ServiceNode::update_swarms()
{
    if (updating_swarms_.exchange(true))
    {
      ARQMA_LOG(debug, "Swarm update already in progress.");
      return;
    }

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
        updating_swarms_ = false;
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
            if (total >= (arqma::is_mainnet ? 100 : 10) && missing <= MISSING_PUBKEY_THRESHOLD::num*total/MISSING_PUBKEY_THRESHOLD::den)
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
          ARQMA_LOG(err, "Exception caught on swarm update: {}", e.what());
        }
      },
      params.dump();
    };
}

void ServiceNode::update_last_ping(ReachType type)
{
  reach_records_.incoming_ping(type);
}

void ServiceNode::ping_peers() {

    std::lock_guard lock{sn_mutex_};
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

std::vector<std::pair<std::string, std::string>> ServiceNode::sign_request(std::string_view body) const
{
  std::vector<std::pair<std::string, std::string>> headers;
  const auto signature = generate_signature(hash_data(body), {our_address_.pubkey_legacy, our_seckey_});
  headers.emplace_back(http::SNODE_SIGNATURE_HEADER, arqmamq::to_base64(util::view_guts(signature)));
  headers.emplace_back(http::SNODE_SENDER_HEADER, arqmamq::to_base32z(our_address_.pubkey_legacy.view()));
  return headers;
}

void ServiceNode::test_reachability(const sn_record_t& sn, int previous_failures)
{
    ARQMA_LOG(debug, "Testing {} SN {} for reachability",
              previous_failures > 0 ? "previously failing" : "random",
              sn.pubkey_legacy);

    if (sn.ip == "0.0.0.0")
    {
      ARQMA_LOG(debug, "Skipping HTTPS test of {}: no public IP received yet");
      return;
    }

    static constexpr uint8_t TEST_WAITING = 0, TEST_FAILED = 1, TEST_PASSED = 2;

    auto test_results = std::make_shared<std::pair<const sn_record_t, std::atomic<uint8_t>>>(sn, 0);

    bool cur_ping_test = !hf_at_least(FUTURE_HF_IMPL); // Future IMPLEMENTATIONS
    cpr::Url url{fmt::format("https://{}:{}{}/ping_test/v1", sn.ip, sn.port, cur_ping_test ? "/swarms" : "")};
    cpr::Body body{""};
    cpr::Header headers{{"Host", sn.pubkey_ed25519 ? arqmamq::to_base32z(sn.pubkey_ed25519.view()) + ".snode" : "service-node.snode"}};

    if (cur_ping_test)
      for (auto& [h, v] : sign_request(body.str()))
        headers[h] = std::move(v);

    outstanding_https_reqs_.emplace_front(
      cpr::PostCallback(
        [this, &arqmq=*arqmq_server(), cur_ping_test, test_results, previous_failures]
        (cpr::Response r)
        {
          auto& [sn, result] = *test_results;
          auto& pk = sn.pubkey_legacy;
          bool success = false;
          if (r.error.code != cpr::ErrorCode::OK)
          {
            ARQMA_LOG(debug, "FAILED HTTPS ping test of {}: {}", pk, r.error.message);
          }
          else if (r.status_code != 200)
          {
            ARQMA_LOG(debug, "FAILED HTTPS ping test of {}: received non-200 status {}", pk, r.status_code, r.status_line);
          }
          else
          {
            if (cur_ping_test)
            {
              if (r.header.count(http::SNODE_SIGNATURE_HEADER))
                success = true;
              else
                ARQMA_LOG(debug, "FAILED HTTPS ping test of {}: {} response header missing", pk, http::SNODE_SIGNATURE_HEADER);
            }
            else
            {
              if (auto it = r.header.find(http::SNODE_PUBKEY_HEADER); it == r.header.end())
                ARQMA_LOG(debug, "FAILED HTTPS ping test of {}: {} response header missing", pk, http::SNODE_PUBKEY_HEADER);
              else if (auto remote_pk = parse_legacy_pubkey(it->second); remote_pk != pk)
                ARQMA_LOG(debug, "FAILED HTTPS ping test of {}: reply has wrong pubkey {}", pk, remote_pk);
              else
                success = true;
            }
          }
          if (success)
            ARQMA_LOG(debug, "Successful HTTPS ping test of {}", pk);

          if (auto r = result.exchange(success ? TEST_PASSED : TEST_FAILED); r != TEST_WAITING)
            report_reachability(sn, success && r == TEST_PASSED, previous_failures);
        },
        std::move(url);
        cpr::Timeout{SN_PING_TIMEOUT},
        cpr::Ssl(cpr::ssl::TLSv1_2{},
                 cpr::ssl::VerifyHost{false},
                 cpr::ssl::VerifyPeer{false},
                 cpr::ssl::VerifyStatus{false}),
        cpr::MaxRedirects{0},
        std::move(headers),
        std::move(body)
      )
    );

    arqmq_server_->request(
      sn.pubkey_x25519.view(), "sn.ping",
      [this, test_results=std::move(test_results), previous_failures](bool success, const auto&) {
        auto& [sn, result] = *test_results;

        ARQMA_LOG(debug, "{} response for ArqmaMQ ping test of {}",
                  success ? "Successful" : "FAILED", sn.pubkey_legacy);

        if (auto r = result.exchange(success ? TEST_PASSED : TEST_FAILED); r != TEST_WAITING)
          report_reachability(sn, success && r == TEST_PASSED, previous_failures);
      },
      arqmamq::send_option::outgoing{},
      arqmamq::send_option::request_timeout{SN_PING_TIMEOUT}
    );
}

void ServiceNode::arqmad_ping() {

    std::lock_guard guard(sn_mutex_);

    json arqmad_params{
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
      arqmad_params.dump()
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
}

void ServiceNode::process_storage_test_response(const sn_record_t& testee, const Item& item,
                                                uint64_t test_height, std::string status, std::string answer)
{
  ResultType result = ResultType::OTHER;

  if (status.empty()) {
    ARQMA_LOG(debug, "Failed to send a storage test request to snode: {}", testee.pubkey_legacy);
  }
  else if (status == "OK")
  {
    if (answer == item.data)
    {
      ARQMA_LOG(debug, "Storage test is successful for: {} at height: {}", testee.pubkey_legacy, test_height);
      result = ResultType::OK;
    }
    else
    {
      ARQMA_LOG(debug, "Test answer doesn't match for: {} at height: {}", testee.pubkey_legacy, test_height);
      result = ResultType::MISMATCH;
    }
  }
  else if (status == "wrong request")
  {
    ARQMA_LOG(debug, "Storage test rejected by testee");
    result = ResultType::REJECTED;
  }
  else
  {
    ARQMA_LOG(debug, "Storage test failed for some other reason: {}", status);
  }

  std::lock_guard guard{sn_mutex_};
  all_stats_.record_storage_test_result(testee.pubkey_legacy, result);
}

void ServiceNode::send_storage_test_req(const sn_record_t& testee,
                                        uint64_t test_height,
                                        const Item& item)
{
  if (!hf_at_least(FUTURE_HF_IMPL))
  {
    cpr::Body body{json{{"height", test_height}, {"hash", item.hash}}.dumo()};
    cpr::Header headers{{"Host", testee.pubkey_ed25519 ? arqmamq::to_base32z(testee.pubkey_ed25519.view()) + ".snode" : "service-node.snode"}};

    for (auto& [h, v] : sign_request(body.str()))
      headers[h] = std::move(v);

    outstanding_https_reqs_.emplace_front(
      cpr::PostCallback(
        [this, testee, item, height=block_height_]
        (cpr::Response r)
        {
          auto& pk = testee.pubkey_legacy;
          std::string status;
          std::string answer;
          if (r.error.code != cpr::ErrorCode::OK)
            ARQMA_LOG(debug, "Failed storage test of {}: {}", pk, r.error.message);
          else if (r.status_code != 200)
            ARQMA_LOG(debug, "Failed storage test of {}: received non-200 status{}", pk, r.status_code, r.status_line);
          else if (r.text.empty())
            ARQMA_LOG(debug, "Failed storage test of {}: received empty body", pk);
          else
          {
            try
            {
              json res_json = json::parse(r.text);
              status = res_json.at("status").get<std::string>();
              answer = res_json.at("value").get<std::string>();
            }
            catch (const std::exception& e)
            {
              ARQMA_LOG(debug, "Failed storage test of {}: invalid json response ({})", pk, e.what());
              status.clear();
              answer.clear();
            }
          }

          process_storage_test_response(testee, item, height, std::move(status), std::move(answer));
        },
        cpr::Url{fmt::format("https://{}:{}/swarms/storage_test/v1", testee.ip, testee.port)},
        cpr::Timeout{STORAGE_TEST_TIMEOUT},
        cpr::Ssl(cpr::ssl::TLSv1_2{},
                 cpr::ssl::VerifyHost{false},
                 cpr::ssl::VerifyPeer{false},
                 cpr::ssl::VerifyStatus{false}),
        cpr::MaxRedirects{0},
        std::move(headers),
        std::move(body)
      }
    };
    return;
  }

  assert(arqmamq::is_hex(item.hash));

  arqmq_server_->request(
    testee.pubkey_x25519.view(), "sn.storage_test",
    [this, testee, item, height=block_height_](bool success, auto data)
    {
      if (!success || data.size() != 2)
      {
        ARQMA_LOG(debug, "Storage test request failed: {}", !success ? "request timed out" : "wrong number of elements in response");
      }
      if (data.size() < 2)
        data.resize(2);
      process_storage_test_response(testee, item, height, std::move(data[0]), std::move(data[1]));
    },
    arqmamq::send_option::request_timeout{STORAGE_TEST_TIMEOUT},
    std::to_string(block_height_),
    arqmamq::from_hex(item.hash)
  );
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
            ARQMA_LOG(err,
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

        if (auto it = block_hashes_cache_.find(blk_keight); it != block_hashes_cache_.end())
        {
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
        ARQMA_LOG(err, "Could not initiate peer test: invalid block hash");
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

std::pair<MessageTestStatus, std::string> ServiceNode::process_storage_test_req(
    uint64_t blk_height, const legacy_pubkey& tester_pk,
    const std::string& msg_hash_hex)
{
    std::lock_guard guard(sn_mutex_);
    // 1. Check height, retry if we are behind
    std::string block_hash;

    if (blk_height > block_height_) {
        ARQMA_LOG(debug, "Our blockchain is behind, height: {}, requested: {}",
                  block_height_, blk_height);
        return {MessageTestStatus::RETRY, ""};
    }

    // 2. Check tester/testee pair
    {
        sn_record_t tester;
        sn_record_t testee;
        this->derive_tester_testee(blk_height, tester, testee);

        if (testee != our_address_) {
            ARQMA_LOG(err, "We are NOT the testee for height: {}",
                      blk_height);
            return {MessageTestStatus::WRONG_REQ, ""};
        }

        if (tester.pubkey_legacy != tester_pk) {
            ARQMA_LOG(debug, "Wrong tester: {}, expected: {}", tester_pk,
                      tester.pubkey_legacy);
            return {MessageTestStatus::WRONG_REQ, ""};
        } else {
            ARQMA_LOG(trace, "Tester is valid: {}", tester_pk);
        }
    }

    // 3. If for a current/past block, try to respond right away
    Item item;
    if (!db_->retrieve_by_hash(msg_hash_hex, item)) {
        return {MessageTestStatus::RETRY, ""};
    }

    answer = item.data;
    return {MessageTestStatus::SUCCESS, std::move(item.data)};
}

std::optional<Item> ServiceNode::select_random_message() {

    uint64_t message_count;
    if (!db_->get_message_count(message_count)) {
        ARQMA_LOG(err, "Could not count messages in the database");
        return {};
    }

    ARQMA_LOG(debug, "total messages: {}", message_count);

    if (message_count == 0) {
        ARQMA_LOG(debug, "No messages in the database to initiate a peer test");
        return {};
    }

    // SNodes don't have to agree on this, rather they should use different
    // messages
    const auto msg_idx = util::uniform_distribution_portable(message_count);

    auto item = std::make_optional<Item>();
    if (!db_->retrieve_by_index(msg_idx, *item)) {
        ARQMA_LOG(err, "Could not retrieve message by index: {}", msg_idx);
        return {};
    }

    return item;
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
    if (auto item = select_random_message())
    {
      ARQMA_LOG(trace, "Selected random message: {}, {}", item->hash, item->data);
      send_storage_test_req(testee, test_height, *item);
    }
    else
    {
      ARQMA_LOG(debug, "Could not select a message for testing");
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
        ARQMA_LOG(err, "Could not retrieve entries from the database");
        return;
    }

    std::unordered_map<swarm_id_t, size_t> swarm_id_to_idx;
    for (size_t i = 0; i < all_swarms.size(); ++i) {
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
                ARQMA_LOG(err, "Invalid pubkey in a message while "
                                 "bootstrapping other nodes");
                continue;
            }

            swarm_id = get_swarm_by_pk(all_swarms, pk).swarm_id;
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

    val["connections_in"] = -1;
    val["http_connections_out"] = -1;
    val["https_connections_out"] = -1;

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
  /*s << "; conns(in/http/https): " << get_net_stats().connections_in << '/' << get_net_stats().http_connections_out << '/' << get_net_stats().https_connections_out;*/
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
        ARQMA_LOG(err, "Swarm data missing");
        return false;
    }
    return swarm_->is_pubkey_for_us(pk);
}

std::vector<sn_record_t>
ServiceNode::get_snodes_by_pk(const user_pubkey_t& pk)
{
    std::lock_guard guard(sn_mutex_);

    if (!swarm_) {
        ARQMA_LOG(err, "Swarm data missing");
        return {};
    }

    return get_swarm_by_pk(swarm_->all_valid_swarms(), pk).snodes;
}

} // namespace arqma
