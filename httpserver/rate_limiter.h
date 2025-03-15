#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <unordered_map>
#include "arqmad_key.h"

namespace arqmamq { class ArqmaMQ; }

/// https://en.wikipedia.org/wiki/Token_bucket

namespace arqma {

class RateLimiter {
  public:
    // TODO: make those two constants command line parameters?
    inline constexpr static uint32_t BUCKET_SIZE = 600;
    inline constexpr static uint32_t TOKEN_RATE = 300;
    inline constexpr static uint32_t TOKEN_RATE_US = 600;
    inline constexpr static uint32_t MAX_CLIENTS = 10000;

    RateLimiter() = delete;
    RateLimiter(arqmamq::ArqmaMQ& arqmq);

    bool should_rate_limit(const legacy_pubkey& pubkey, std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
    bool should_rate_limit_client(uint32_t ip, std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
    bool should_rate_limit_client(const std::string& ip_dotted_quad, std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

  private:
    struct TokenBucket {
        uint32_t num_tokens;
        std::chrono::steady_clock::time_point last_time_point;
    };

    std::mutex mutex_;

    std::unordered_map<legacy_pubkey, TokenBucket> snode_buckets_;
    std::unordered_map<uint32_t, TokenBucket> client_buckets_;

    void clean_buckets(std::chrono::steady_clock::time_point now);
};

}