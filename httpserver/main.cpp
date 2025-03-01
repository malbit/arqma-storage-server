#include "arqma_logger.h"
#include "arqmad_key.h"
#include "arqmad_rpc.h"
#include "channel_encryption.hpp"
#include "command_line.h"
#include "http_connection.h"
#include "rate_limiter.h"
#include "security.h"
#include "service_node.h"
#include "swarm.h"
#include "utils.hpp"
#include "version.h"

#include "arqmq_server.h"
#include "request_handler.h"

#include <sodium.h>
#include <arqmamq/arqmamq.h>
#include <arqmamq/hex.h>

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <vector>

extern "C" {
#include <sys/types.h>
#include <pwd.h>

#ifdef ENABLE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif
}
namespace fs = std::filesystem;

constexpr int EXIT_INVALID_PORT = 2;

int main(int argc, char* argv[]) {

    arqma::command_line_parser parser;

    try {
        parser.parse_args(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        parser.print_usage();
        return EXIT_FAILURE;
    }

    auto options = parser.get_options();

    if (options.print_help) {
        parser.print_usage();
        return EXIT_SUCCESS;
    }

    if (options.print_version)
    {
      std::cout << arqma::STORAGE_SERVER_VERSION_INFO;
      return EXIT_SUCCESS;
    }

    if (options.data_dir.empty()) {
        if (auto home_dir = util::get_home_dir()) {
          if (options.stagenet) {
            options.data_dir = (*home_dir / ".arqma" / "stagenet" / "storage").u8string();
          } else {
            options.data_dir = (*home_dir / ".arqma" / "storage").u8string();
          }
        }
    }

    if (!fs::exists(options.data_dir)) {
        fs::create_directories(options.data_dir);
    }

    arqma::LogLevel log_level;
    if (!arqma::parse_log_level(options.log_level, log_level)) {
        std::cerr << "Incorrect log level: " << options.log_level << std::endl;
        arqma::print_log_levels();
        return EXIT_FAILURE;
    }

    arqma::init_logging(options.data_dir, log_level);

    if (options.stagenet) {
      arqma::is_mainnet = false;
      ARQMA_LOG(warn, "Starting in stagenet mode, make sure it is intentional");
    }

    // Always print version for the logs
    ARQMA_LOG(info, "{}", arqma::STORAGE_SERVER_VERSION_INFO);

    if (options.ip == "127.0.0.1") {
        ARQMA_LOG(critical,
                  "Tried to bind arqma-storage to localhost, please bind "
                  "to outward facing address");
        return EXIT_FAILURE;
    }

    ARQMA_LOG(info, "Setting log level to {}", options.log_level);
    ARQMA_LOG(info, "Setting database location to {}", options.data_dir);
    ARQMA_LOG(info, "Connecting to arqmad @ {}", options.arqmad__amq_rpc);
    ARQMA_LOG(info, "Https server is listening at {}:{}", options.ip, options.port);
    ARQMA_LOG(info, "ArqmaMQ is listening at {}:{}", options.ip, options.arqmq_port);

    boost::asio::io_context ioc{1};

    if (sodium_init() != 0) {
        ARQMA_LOG(error, "Could not initialize libsodium");
        return EXIT_FAILURE;
    }

    if (crypto_aead_aes256gcm_is_available() == 0)
    {
      ARQMA_LOG(error, "AES-256-GCM is not available on this CPU");
      return EXIT_FAILURE;
    }

    {
      const auto fd_limit = util::get_fd_limit();
      if (fd_limit != -1) {
        ARQMA_LOG(debug, "Open file descriptor limit: {}", fd_limit);
      } else {
        ARQMA_LOG(debug, "Open file descriptor limit: N/A");
      }
    }

    try {
        using namespace arqma;

        std::vector<x25519_pubkey> stats_access_keys;
        for (const auto& key : options.stats_access_keys)
        {
          stats_access_keys.push_back(x25519_pubkey::from_hex(key));
          ARQMA_LOG(info, "Stats access key: {}", key);
        }

        const auto [private_key, private_key_ed25519, private_key_x25519] = get_sn_privkeys(options.arqmad_arqmq_port);

        sn_record_t me{"0.0.0.0", options.port, options.arqmq_port, private_key.pubkey(), private_key_ed25519.pubkey(), private_key_x25519.pubkey()};

        ARQMA_LOG(info, "Retrieved keys from arqmad. Our SN pubkeys are:");
        ARQMA_LOG(info, "- legacy: {}", me.pubkey_legacy);
        ARQMA_LOG(info, "- ed25519: {}", me.pubkey_ed25519);
        ARQMA_LOG(info, "- x25519: {}", me.pubkey_x25519);

        ChannelEncryption channel_encryption{private_key_x25519};

        ArqmamqServer arqmamq_server{me, private_key_x25519, stats_access_keys};

        ServiceNode service_node(ioc, me, private_key, arqmamq_server,
                                 options.data_dir, options.force_start);

        RequestHandler request_handler(ioc, service_node, channel_encryption);

        arqmamq_server.init(&service_node, &request_handler, arqmamq::address{options.arqmad_amq_rpc});

        RateLimiter rate_limiter;

        Security security(legacy_keypair{me.pubkey_legacy, private_key}, options.data_dir);

#ifdef ENABLE_SYSTEMD
  sn_notify(0, "READY=1");
  arqmamq_server->add_timer([&service_node] {
    sd_notify(0, ("WATCHDOG=1\nSTATUS=" + service_node.get_status_line()).c_str());
  }, 10s);
#endif

        http_server::run(ioc, options.ip, options.port, options.data_dir,
                                service_node, request_handler, rate_limiter,
                                security);
    } catch (const std::exception& e) {
        // It seems possible for logging to throw its own exception,
        // in which case it will be propagated to libc...
        std::cerr << "Exception caught in main: " << e.what() << std::endl;
        return EXIT_FAILURE;
    } catch (...) {
        std::cerr << "Unknown exception caught in main." << std::endl;
        return EXIT_FAILURE;
    }
}
