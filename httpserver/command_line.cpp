#include "command_line.h"
#include "arqma_logger.h"
#include "utils.hpp"

#include <filesystem>
#include <iostream>

namespace arqma {

namespace po = boost::program_options;
namespace fs = std::filesystem;

const command_line_options& command_line_parser::get_options() const {
    return options_;
}

void command_line_parser::parse_args(std::vector<const char*> args)
{
  parse_args(args.size(), const_cast<char**>(args.data()));
}

void command_line_parser::parse_args(int argc, char* argv[]) {
    std::string config_file;
    po::options_description all, hidden;
    auto home = util::get_home_dir().value_or(".");
    auto arqma_sock = home;
    if (home == fs::path{"/var/lib/arqma"})
      arqma_sock /= "arqmad.sock";
    else
      arqma_sock = arqma_sock / ".arqma" / "arqmad.sock";

    options_.arqmad_arqmq_rpc = "ipc://" + arqma_sock.u8string();
    // clang-format off
    desc_.add_options()
        ("data-dir", po::value(&options_.data_dir), "Path to persistent data (defaults to ~/.arqma/storage)")
        ("config-file", po::value(&config_file), "Path to custom config file (defaults to `storage-server.conf' inside --data-dir)")
        ("log-level", po::value(&options_.log_level), "Log verbosity level, see Log Levels below for accepted values")
        ("arqmad-rpc", po::value(&options_.arqmad_arqmq_rpc), "ZMQ RPC address on which arqmad is available; typically ipc:///path/to/arqmad.sock or tcp://localhost:19995")
        ("arqmq-port", po::value(&options_.arqmq_port), "Public port to listen on for ArqmaMQ connections")
        ("stagenet", po::bool_switch(&options_.stagenet), "Start storage server in stagenet mode")
        ("force-start", po::bool_switch(&options_.force_start), "Ignore the initialisation ready check")
        ("bind-ip", po::value(&options_.ip)->default_value("0.0.0.0"), "IP to which to bind the server")
        ("version,v", po::bool_switch(&options_.print_version), "Print the version of this binary")
        ("help", po::bool_switch(&options_.print_help),"Shows this help message")
        ("stats-access-key", po::value(&options_.stats_access_keys)->multitoken(), "A public key (x25519) that will have access to the 'get_stats' arqmq endpoint");
        // Add hidden ip and port options.  You technically can use the `--ip=` and `--port=` with
        // these here, but they are meant to be positional.  More usefully, you can specify `ip=`
        // and `port=` in the config file to specify them.
    hidden.add_options()
        ("ip", po::value<std::string>(), "(unused)")
        ("port", po::value(&options_.port), "Port to listen on");
    // clang-format on

    all.add(desc_).add(hidden);
    po::positional_options_description pos_desc;
    pos_desc.add("ip", 1);
    pos_desc.add("port", 1);

    binary_name_ = fs::u8path(argv[0]).filename().u8string();

    po::variables_map vm;

    po::store(po::command_line_parser(argc, argv)
                  .options(all)
                  .positional(pos_desc)
                  .run(),
              vm);
    po::notify(vm);

    fs::path config_path{!config_file.empty() ? fs::u8path(config_file) : fs::u8path(options_.data_dir) / "storage-server.conf"};

    if (fs::exists(config_path)) {
        po::store(po::parse_config_file<char>(config_path.u8string().c_str(), all), vm);
        po::notify(vm);
    } else if (vm.count("config-file")) {
        throw std::runtime_error(
            "path provided in --config-file does not exist");
    }

    if (options_.print_version || options_.print_help) {
        return;
    }

    if (options_.stagenet && !vm.count("arqmad-rpc"))
    {
      arqma_sock = arqma_sock.parent_path() / "stagenet" / "arqmad.sock";
      options_.arqmad_arqmq_rpc = "ipc://" + arqma_sock.u8string();
    }

    if (!vm.count("arqmq-port"))
    {
      throw std::runtime_error("arqmq-port command line option is not specified");
    }

    if (!vm.count("ip") || !vm.count("port")) {
        throw std::runtime_error(
            "Invalid option: address and/or port missing.");
    }
}

void command_line_parser::print_usage() const {
    std::cerr << "Usage: " << binary_name_ << " <address> <port> [...]\n\n";

    desc_.print(std::cerr);

    std::cerr << std::endl;

    print_log_levels();
}
} // namespace arqma
