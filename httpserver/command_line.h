#pragma once

#include <boost/program_options.hpp>
#include <string>

namespace arqma {

struct command_line_options {
    uint16_t port;
    std::string arqmad_rpc_ip = "127.0.0.1";
    uint16_t arqmad_rpc_port = 19994; // or 39994 if `stagenet`
    bool force_start = false;
    bool print_version = false;
    bool print_help = false;
    bool stagenet = false;
    std::string ip;
    std::string log_level = "info";
    std::string data_dir;
    std::string arqmad_key; // test only
    std::string arqmad_x25519_key; // test only
    std::string arqmad_ed25519_key; // test only
};

class command_line_parser {
  public:
    void parse_args(int argc, char* argv[]);
    bool early_exit() const;

    const command_line_options& get_options() const;
    void print_usage() const;

  private:
    boost::program_options::options_description desc_;
    command_line_options options_;
    std::string binary_name_;
};

} // namespace arqma
