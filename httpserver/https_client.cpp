#include "https_client.h"
#include "net_stats.h"
#include "arqma_logger.h"
#include "signature.h"
#include "sn_record.h"

#include <openssl/x509.h>
#include <arqmamq/base64.h>
#include <arqmamq/base32z.h>

namespace sp = std::placeholders;

namespace arqma {

using error_code = boost::system::error_code;

static ssl::context ctx{ssl::context::tlsv12_client};

void make_https_request_to_sn(boost::asio::io_context& ioc, const sn_record_t& sn,
                              const std::shared_ptr<request_t>& req, http_callback_t&& cb)
{
    error_code ec;
    boost::asio::ip::tcp::resolver resolver(ioc);
    if (sn.ip == "0.0.0.0" || sn.port == 0) {
        ARQMA_LOG(debug, "Could not initiate request to snode (we don't know their IP/port yet).");

        cb(sn_response_t{SNodeError::NO_REACH, nullptr});
        return;
    }

    const auto resolve_results =
        resolver.resolve(sn.ip, std::to_string(sn.port), ec);

    if (ec) {
        ARQMA_LOG(error, "https: Failed to parse the IP address. Error code = {}. Message: {}",
                  ec.value(), ec.message());
        return;
    }

    std::string hostname = sn.pubkey_ed25519 ? arqmamq::to_base32z(sn.pubkey_ed25519.view()) + ".snode" : "service-node.snode";
    auto session = std::make_shared<HttpsClientSession>(
        ioc, ctx, std::move(resolve_results), hostname.c_str(), std::move(req), std::move(cb),
        sn.pubkey_legacy);

    session->start();
}

void make_https_request(boost::asio::io_context& ioc, const std::string& host, uint16_t port, std::shared_ptr<request_t> req, http_callback_t&& cb)
{
  static boost::asio::ip::tcp::resolver resolver(ioc);

  constexpr char prefix[] = "https://";
  std::string query = host;

  if (host.find(prefix) == 0)
  {
    query.erase(0, sizeof(prefix) - 1);
  }

  auto resolve_handler = [&ioc, req = std::move(req), query, host, cb = std::move(cb)](const boost::system::error_code& ec, boost::asio::ip::tcp::resolver::result_type resolve_results) mutable
  {
    if (ec)
    {
      ARQMA_LOG(error, "DNS resolution error for {}: {}", query, ec.message());
      cb({SNodeError::ERROR_OTHER});
      return;
    }

    static ssl::context ctx{ssl::context::tlsv12_client};

    auto session = std::make_shared<HttpsClientSession>(ioc, ctx, std::move(resolve_results), host.c_str(), std::move(req), std::move(cb), std::nullptr);

    session->start();
  };

  resolver.async_resolve(query, std::to_string(port), boost::asio::ip::tcp::resolver::query::numeric_service, resolve_handler);
}

static std::string x509_to_string(X509* x509) {
    BIO* bio_out = BIO_new(BIO_s_mem());
    if (!bio_out) {
        ARQMA_LOG(critical, "Could not allocate openssl BIO");
        return "";
    }
    if (!PEM_write_bio_X509(bio_out, x509)) {
        ARQMA_LOG(critical, "Could not write x509 cert to openssl BIO");
        return "";
    }
    BUF_MEM* bio_buf;
    BIO_get_mem_ptr(bio_out, &bio_buf);
    std::string pem = std::string(bio_buf->data, bio_buf->length);
    if (!BIO_free(bio_out)) {
        ARQMA_LOG(critical, "Could not free openssl BIO");
    }
    return pem;
}

HttpsClientSession::HttpsClientSession(
    boost::asio::io_context& ioc, ssl::context& ssl_ctx,
    tcp::resolver::results_type resolve_results, const char* host,
    std::shared_ptr<request_t> req, http_callback_t&& cb,
    std::optional<legacy_pubkey> sn_pubkey)
    : ioc_(ioc), ssl_ctx_(ssl_ctx), resolve_results_(resolve_results),
      callback_(cb), deadline_timer_(ioc), stream_(ioc, ssl_ctx_), req_(std::move(req)),
      server_pubkey_(std::move(sn_pubkey)) {

    get_net_stats().https_connections_out++;

    response_.body_limit(1024 * 1024 * 10);

    // Set SNI Hostname (many hosts need this to handshake successfully)
    if (!SSL_set_tlsext_host_name(stream_.native_handle(), host)) {
        boost::beast::error_code ec{static_cast<int>(::ERR_get_error()),
                                    boost::asio::error::get_ssl_category()};
        ARQMA_LOG(critical, "{}", ec.message());
        return;
    }

    static uint64_t connection_count = 0;
    this->connection_idx = connection_count++;
}

void HttpsClientSession::start() {
    boost::asio::async_connect(
        stream_.next_layer(), resolve_results_,
        [this, self = shared_from_this()](boost::system::error_code ec,
                                          const tcp::endpoint& endpoint) {
            /// TODO: I think I should just call again if ec ==
            /// EINTR
            if (ec) {
                /// Don't forget to print the error from where we call this!
                /// (similar to http)
                ARQMA_LOG(
                    debug,
                    "[https client]: could not connect to {}:{}, message: "
                    "{} ({})",
                    endpoint.address().to_string(), endpoint.port(),
                    ec.message(), ec.value());
                trigger_callback(SNodeError::NO_REACH, nullptr);
                return;
            }

            self->on_connect();
        });

    deadline_timer_.expires_after(SESSION_TIME_LIMIT);
    deadline_timer_.async_wait(
        [self = shared_from_this()](const error_code& ec) {
            if (ec) {
                if (ec != boost::asio::error::operation_aborted) {
                    ARQMA_LOG(error,
                              "Deadline timer failed in https client session "
                              "[{}: {}]",
                              ec.value(), ec.message());
                }
            } else {
                ARQMA_LOG(debug, "client socket timed out");
                self->do_close();
            }
        });
}

void HttpsClientSession::on_connect()
{
  ARQMA_LOG(trace, "on connect, connection idx: {}", this->connection_idx);

  const auto sockfd = stream_.lowest_layer().native_handle();
  ARQMA_LOG(trace, "Open https socket: {}", sockfd);
  get_net_stats().record_socket_open(sockfd);

  stream_.set_verify_mode(ssl::verify_none);
  stream_.set_verify_callback([this](bool preverified, ssl::verify_context& ctx) -> bool {
    if (!preverified) {
      X509_STORE_CTX* handle = ctx.native_handle();
      X509* x509 = X509_STORE_CTX_get0_cert(handle);
      server_cert_ = x509_to_string(x509);
    }
    return true;
  });
  stream_.async_handshake(ssl::stream_base::client, std::bind(&HttpsClientSession::on_handshake,
                          shared_from_this(), sp::_1));
}

void HttpsClientSession::on_handshake(boost::system::error_code ec)
{
  if (ec)
  {
    ARQMA_LOG(error, "Failed to perform a handshake with {}: {}", server_pubkey_ ? server_pubkey_->view() : "(not snode)"), ec.message());
    return;
  }

  http::async_write(stream_, *req_, std::bind(&HttpsClientSession::on_write, shared_from_this(), sp::_1, sp::_2));
}

void HttpsClientSession::on_write(error_code ec, size_t bytes_transferred) {

    ARQMA_LOG(trace, "on write");
    if (ec) {
        ARQMA_LOG(error, "Https error on write, ec: {}. Message: {}", ec.value(),
                  ec.message());
        trigger_callback(SNodeError::ERROR_OTHER, nullptr);
        return;
    }

    ARQMA_LOG(trace, "Successfully transferred {} bytes.", bytes_transferred);

    // Receive the HTTP response
    http::async_read(stream_, buffer_, response_, std::bind(&HttpsClientSession::on_read,
                     shared_from_this(), sp::_1, sp::_2));
}

bool HttpsClientSession::verify_signature() {

    if (!server_pubkey_)
      return true;

    const auto& response = response_.get();

    const auto it = response.find(ARQMA_SNODE_SIGNATURE_HEADER);
    if (it == response.end())
    {
        ARQMA_LOG(warn, "no signature found in header from {}",
                  server_pubkey_);
        return false;
    }

    signature sig;
    try {
      sig = signature::from_base64(it->value().to_string());
    } catch (const std::exception&) {
      ARQMA_LOG(warn, "Invalid signature (not base64) found in header from {}", *server_pubkey_);
      return false;
    }

    return check_signature(sig, hash_data(server_cert_), *server_pubkey_);
}

void HttpsClientSession::on_read(error_code ec, size_t bytes_transferred) {

    ARQMA_LOG(trace, "Successfully received {} bytes", bytes_transferred);

    const auto& response = response_.get();

    if (!ec || (ec == http::error::end_of_stream)) {

        if (http::to_status_class(response.result_int()) ==
            http::status_class::successful) {

            if (server_pubkey_ && !verify_signature()) {
                ARQMA_LOG(debug, "Bad signature from {}", *server_pubkey_);
                trigger_callback(SNodeError::ERROR_OTHER, nullptr, response);
            } else {
                auto body = std::make_shared<std::string>(response.body());
                trigger_callback(SNodeError::NO_ERROR, std::move(body), response);
            }
        } else {
            ARQMA_LOG(debug, "ERROR OTHER: [{}] {}", response.result_int(), response.body());
            trigger_callback(SNodeError::ERROR_OTHER, nullptr, response);
        }

    } else {

        /// Do we need to handle `operation aborted` separately here (due to
        /// deadline timer)?
        ARQMA_LOG(error, "Error on read: {}. Message: {}", ec.value(),
                  ec.message());
        trigger_callback(SNodeError::ERROR_OTHER, nullptr, response);
    }

    // Gracefully close the socket
    do_close();

    // not_connected happens sometimes so don't bother reporting it.
    if (ec && ec != boost::system::errc::not_connected) {

        ARQMA_LOG(error, "ec: {}. Message: {}", ec.value(), ec.message());
        return;
    }

    // If we get here then the connection is closed gracefully
}

void HttpsClientSession::trigger_callback(SNodeError error,
                                          std::shared_ptr<std::string>&& body,
                                          std::optional<response_t> raw_response) {
    ioc_.post(std::bind(callback_, sn_response_t{error, body, raw_response}));
    used_callback_ = true;
    deadline_timer_.cancel();
}

void HttpsClientSession::do_close() {
    // Gracefully close the stream
    stream_.async_shutdown(std::bind(&HttpsClientSession::on_shutdown,
                                     shared_from_this(), sp::_1));
}

void HttpsClientSession::on_shutdown(boost::system::error_code ec)
{
  if (ec == boost::asio::error::eof) {
    // Rationale:
    // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
    ec.assign(0, ec.category());
  } else if (ec) {
    ARQMA_LOG(trace, "could not shutdown stream gracefully: {} ({})", ec.message(), ec.value());
  }

  const auto sockfd = stream_.lowest_layer().native_handle();
  ARQMA_LOG(trace, "Close https socket: {}", sockfd);
  get_net_stats().record_socket_close(sockfd);

  stream_.lowest_layer().close();

  // If we get here then the connection is closed gracefully
}

/// We execute callback (if haven't already) here to make sure it is called
HttpsClientSession::~HttpsClientSession() {

    if (!used_callback_) {
        // If we destroy the session before posting the callback,
        // it must be due to some error
        ioc_.post(std::bind(callback_,
                            sn_response_t{SNodeError::ERROR_OTHER, nullptr}));
    }

    get_net_stats().https_connections_out--;
}
} // namespace arqma
