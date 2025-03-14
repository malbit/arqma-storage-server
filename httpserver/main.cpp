#include "arqma_logger.h"
#include "arqmad_key.h"
#include "arqmad_rpc.h"
#include "channel_encryption.hpp"
#include "command_line.h"
#include "https_server.h"
#include "server_certificates.h"
#include "service_node.h"
#include "swarm.h"
#include "utils.hpp"
#include "version.h"

#include "arqmq_server.h"
#include "request_handler.h"

#include <sodium/core.h>
#include <arqmamq/arqmamq.h>
#include <arqmamq/hex.h>

#include <csignal>
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

std::atomic<int> signalled = 0;
extern "C" void handle_signal(int sig)
{
  signalled = sig;
}

int main(int argc, char* argv[])
{
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

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

    std::filesystem::path data_dir;
    if (options.data_dir.empty())
    {
      if (auto home_dir = util::get_home_dir())
      {
        data_dir = options.stagenet ? *home_dir / ".arqma" / "stagenet" / "storage" : *home_dir / ".arqma" / "storage";
      }
      else
      {
        std::cerr << "Could not determine your home directory. Please use --data-dir to specify a data directry\n";
        return EXIT_FAILURE;
      }
    }
    else
    {
      data_dir = std::filesystem::u8path(options.data_dir);
    }

    if (!fs::exists(data_dir))
      fs::create_directories(data_dir);

    arqma::LogLevel log_level;
    if (!arqma::parse_log_level(options.log_level, log_level)) {
        std::cerr << "Incorrect log level: " << options.log_level << std::endl;
        arqma::print_log_levels();
        return EXIT_FAILURE;
    }

    arqma::init_logging(data_dir, log_level);

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
    ARQMA_LOG(info, "Setting database location to {}", data_dir);
    ARQMA_LOG(info, "Connecting to arqmad @ {}", options.arqmad_arqmq_rpc);
    ARQMA_LOG(info, "Https server is listening at {}:{}", options.ip, options.port);
    ARQMA_LOG(info, "ArqmaMQ is listening at {}:{}", options.ip, options.arqmq_port);

    if (sodium_init() != 0) {
        ARQMA_LOG(err, "Could not initialize libsodium");
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

        const auto [private_key, private_key_ed25519, private_key_x25519] = get_sn_privkeys(options.arqmad_arqmq_rpc);

        sn_record_t me{"0.0.0.0", options.port, options.arqmq_port, private_key.pubkey(), private_key_ed25519.pubkey(), private_key_x25519.pubkey()};

        ARQMA_LOG(info, "Retrieved keys from arqmad. Our SN pubkeys are:");
        ARQMA_LOG(info, "- legacy: {}", me.pubkey_legacy);
        ARQMA_LOG(info, "- ed25519: {}", me.pubkey_ed25519);
        ARQMA_LOG(info, "- x25519: {}", me.pubkey_x25519);

        ChannelEncryption channel_encryption{private_key_x25519};

        auto ssl_cert = data_dir / "cert.pem";
        auto ssl_key = data_dir / "key.pem";
        auto ssl_dh = data_dir / "dh.pem";
        if (!exists(ssl_cert) || !exists(ssl_key))
          generate_cert(ssl_cert, ssl_key);
        if (!exists(ssl_dh))
          generate_dh_pem(ssl_dh);

        auto arqmamq_server_ptr = std::make_unique<ArqmamqServer>(me, private_key_x25519, stats_access_keys);
        auto& arqmamq_server = *arqmamq_server_ptr;

        ServiceNode service_node{me, private_key, arqmamq_server, data_dir, options.force_start};

        RequestHandler request_handler{service_node, channel_encryption};

        HTTPSServer https_server{service_node, request_handler, {{options.ip, options.port, true}}, ssl_cert, ssl_key, ssl_dh, {me.pubkey_legacy, private_key}};

        arqmamq_server.init(&service_node, &request_handler, arqmamq::address{options.arqmad_arqmq_rpc});

        https_server.start();

#ifdef ENABLE_SYSTEMD
  sn_notify(0, "READY=1");
  arqmamq_server->add_timer([&service_node] {
    sd_notify(0, ("WATCHDOG=1\nSTATUS=" + service_node.get_status_line()).c_str());
  }, 10s);
#endif

        while (signalled.load() == 0)
          std::this_thread::sleep_for(100ms);

        ARQMA_LOG(warn, "Received signal {}. Shutting down...", signalled.load());
        service_node.shutdown();
        ARQMA_LOG(info, "Stopping https server");
        https_server.shutdown(true);
        ARQMA_LOG(info, "Stopping ArqmaMQ server");
        arqmamq_server_ptr.reset();
        ARQMA_LOG(info, "Shutting down");
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
