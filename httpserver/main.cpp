#include "channel_encryption.hpp"
#include "command_line.h"
#include "http_connection.h"
#include "arqma_logger.h"
#include "arqmad_key.h"
#include "rate_limiter.h"
#include "security.h"
#include "service_node.h"
#include "swarm.h"
#include "version.h"

#include <boost/filesystem.hpp>
#include <sodium.h>

#include <cstdlib>
#include <iostream>
#include <vector>

namespace fs = boost::filesystem;

static boost::optional<fs::path> get_home_dir() {

    /// TODO: support default dir for Windows
#ifdef WIN32
    return boost::none;
#endif

    char* pszHome = getenv("HOME");
    if (pszHome == NULL || strlen(pszHome) == 0)
        return boost::none;

    return fs::path(pszHome);
}

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

    if (options.data_dir.empty()) {
        if (auto home_dir = get_home_dir()) {
            options.data_dir = (home_dir.get() / ".arqma" / "storage").string();
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

    // Always print version for the logs
    print_version();
    if (options.print_version) {
        return EXIT_SUCCESS;
    }

    if (options.ip == "127.0.0.1") {
        ARQMA_LOG(critical, "Tried to bind arqma-storage to localhost, please bind "
                        "to outward facing address");
        return EXIT_FAILURE;
    }

    if (options.port == options.arqmad_rpc_port) {
        ARQMA_LOG(error, "Storage server port must be different from that of "
                        "Arqmad! Terminating.");
        exit(EXIT_INVALID_PORT);
    }

    ARQMA_LOG(info, "Setting log level to {}", options.log_level);
    ARQMA_LOG(info, "Setting database location to {}", options.data_dir);
    ARQMA_LOG(info, "Setting Arqmad key path to {}", options.arqmad_key_path);
    ARQMA_LOG(info, "Setting Arqmad RPC port to {}", options.arqmad_rpc_port);
    ARQMA_LOG(info, "Listening at address {} port {}", options.ip, options.port);

#ifdef DISABLE_SNODE_SIGNATURE
    ARQMA_LOG(warn, "IMPORTANT: This binary is compiled with Service Node "
                   "signatures disabled, make sure this is intentional!");
#endif

    boost::asio::io_context ioc{1};
    boost::asio::io_context worker_ioc{1};

    if (sodium_init() != 0) {
        ARQMA_LOG(error, "Could not initialize libsodium");
        return EXIT_FAILURE;
    }

    try {

        // ed25519 key
        const auto private_key = arqma::parseArqmadKey(options.arqmad_key_path);
        const auto public_key = arqma::calcPublicKey(private_key);

        // TODO: avoid conversion to vector
        const std::vector<uint8_t> priv(private_key.begin(), private_key.end());
        ChannelEncryption<std::string> channel_encryption(priv);

        arqma::arqmad_key_pair_t arqmad_key_pair{private_key, public_key};

        auto arqmad_client = arqma::ArqmadClient(ioc, options.arqmad_rpc_port);

        arqma::ServiceNode service_node(ioc, worker_ioc, options.port,
                                       arqmad_key_pair, options.data_dir,
                                       arqmad_client, options.force_start);
        RateLimiter rate_limiter;

        arqma::Security security(arqmad_key_pair, options.data_dir);

        /// Should run http server
        arqma::http_server::run(ioc, options.ip, options.port, options.data_dir,
                               service_node, channel_encryption, rate_limiter,
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
