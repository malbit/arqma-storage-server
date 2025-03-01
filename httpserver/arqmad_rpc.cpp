#include "arqma_logger.h"
#include "arqmad_rpc.h"
#include "arqmq_server.h"
#include <chrono>
#include <exception>
#include <future>
#include <string_view>
#include <nlohmann/json.hpp>

namespace arqma {

arqmad_seckeys get_sn_privkeys(std::string_view arqmad_rpc_address)
{
  arqmamq::ArqmaMQ amq{arqmq_logger, arqmamq::LogLevel::info};
  amq.start();
  constexpr auto retry_interval = 5s;
  auto last_try = std::chrono::steady_clock::now() - retry_interval;
  ARQMA_LOG(info, "Retrieving SN keys from arqmad");

  while (true)
  {
    auto next_try = last_try + retry_interval;
    auto now = std::chrono::steady_clock::now();
    if (now < next_try)
      std::this_thread::sleep_until(next_try);
    last_try = now;

    std::promise<arqmad_seckeys> prom;
    auto fut = prom.get_future();
    auto conn = amq.connect_remote(arqmamq::address{arqmad_rpc_address}, [&amq, &prom](auto conn)
    {
      ARQMA_LOG(info, "Connected to arqmad, retrieving SN keys");
      amq.request(conn, "admin.get_service_node_privkey", [&prom](bool success, std::vector<std::string> data)
      {
        try
        {
          if (!success || data.size() < 2)
          {
            throw std::runtime_error{"arqmad SN keys request failed: " + (data.empty() ? "no data received" : data[0])};
          }
          auto r = nlohmann::json::parse(data[1]);

          auto pk = r.at("service_node_privkey").get<std::string>();
          if (pk.empty())
            throw std::runtime_error{"main service node private key is empty. perhaps arqmad is not running in service-node mode?"};
          prom.set_value(arqmad_seckeys{
                         legacy_seckey::from_hex(pk),
                         ed25519_seckey::from_hex(r.at("service_node_ed25519_privkey").get<std::string>()),
                         x25519_seckey::from_hex(r.at("service_node_x25519_privkey").get<std::string>())});
        }
        catch (...)
        {
          prom.set_exception(std::current_exception());
        }
      });
    },
    [&prom](auto&&, std::string_view fail_reason)
    {
      try
      {
        throw std::runtime_error{"Failed to connect to arqmad: " + std::string{fail_reason}};
      }
      catch (...)
      {
        prom.set_exception(std::current_exception());
      }
    });

    try
    {
      return fut.get();
    }
    catch (std::exception& e)
    {
      ARQMA_LOG(critical, "Error retrieving private keys from arqmad: {}; retrying", e.what());
    }
  }
}

}
