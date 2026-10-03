#include "detect/tls_session.hpp"

#include <algorithm>
#include <cerrno>
#include <sys/socket.h>
#include <vector>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#if OPENSSL_VERSION_MAJOR < 3
#error "Skan TLS sessions require OpenSSL 3.0 or newer"
#endif

namespace skan::detect {
namespace {

constexpr std::size_t kMaximumWireBytes = 512U << 10U;
constexpr long kMaximumChainBytes = 64L << 10U;
constexpr int kMaximumLeafBytes = 48 << 10;

struct SocketState final {
    int descriptor{-1};
    int error{0};
    std::size_t received{0U};
};

int socket_read(BIO *bio, char *buffer, int length)
{
    auto *socket = static_cast<SocketState *>(BIO_get_data(bio));
    BIO_clear_retry_flags(bio);
    if (socket == nullptr || buffer == nullptr || length <= 0) return 0;
    if (socket->received >= kMaximumWireBytes) {
        socket->error = EMSGSIZE;
        return -1;
    }
    const auto capacity = std::min(static_cast<std::size_t>(length), kMaximumWireBytes - socket->received);
    ssize_t count;
    do { count = ::recv(socket->descriptor, buffer, capacity, MSG_DONTWAIT); } while (count < 0 && errno == EINTR);
    if (count > 0) socket->received += static_cast<std::size_t>(count);
    if (count < 0) {
        socket->error = errno;
        if (errno == EAGAIN || errno == EWOULDBLOCK) BIO_set_retry_read(bio);
    }
    return static_cast<int>(count);
}

int socket_write(BIO *bio, const char *buffer, int length)
{
    auto *socket = static_cast<SocketState *>(BIO_get_data(bio));
    BIO_clear_retry_flags(bio);
    if (socket == nullptr || buffer == nullptr || length <= 0) return 0;
    ssize_t count;
    do {
        count = ::send(socket->descriptor, buffer, static_cast<std::size_t>(length), MSG_DONTWAIT | MSG_NOSIGNAL);
    } while (count < 0 && errno == EINTR);
    if (count < 0) {
        socket->error = errno;
        if (errno == EAGAIN || errno == EWOULDBLOCK) BIO_set_retry_write(bio);
    }
    return static_cast<int>(count);
}

const BIO_METHOD *socket_method()
{
    static const std::unique_ptr<BIO_METHOD, decltype(&BIO_meth_free)> method([] {
        BIO_METHOD *value = BIO_meth_new(BIO_TYPE_SOURCE_SINK | BIO_get_new_index(), "Skan nonblocking socket");
        if (value == nullptr) return value;
        if (BIO_meth_set_read(value, socket_read) != 1 || BIO_meth_set_write(value, socket_write) != 1 ||
            BIO_meth_set_ctrl(value, [](BIO *, int command, long, void *) -> long {
                return command == BIO_CTRL_FLUSH ? 1L : 0L;
            }) != 1 ||
            BIO_meth_set_create(value, [](BIO *bio) { BIO_set_init(bio, 1); return 1; }) != 1 ||
            BIO_meth_set_destroy(value, [](BIO *bio) { BIO_set_data(bio, nullptr); return 1; }) != 1) {
            BIO_meth_free(value);
            return static_cast<BIO_METHOD *>(nullptr);
        }
        return value;
    }(), BIO_meth_free);
    return method.get();
}

} // namespace

struct TlsSession::Impl final {
    SSL_CTX *context{nullptr};
    SSL *session{nullptr};
    SocketState socket;

    explicit Impl(int descriptor)
    {
        if (descriptor < 0) return;
        context = SSL_CTX_new(TLS_client_method());
        if (context == nullptr) return;
        if (SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION) != 1 ||
            SSL_CTX_set_max_proto_version(context, TLS1_3_VERSION) != 1) return;
        // Inventory observes a peer; it does not certify trust or authenticity.
        SSL_CTX_set_verify(context, SSL_VERIFY_NONE, nullptr);
        SSL_CTX_set_max_cert_list(context, kMaximumChainBytes);
        SSL_CTX_set_options(context, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
        session = SSL_new(context);
        if (session == nullptr) return;
        if (socket_method() == nullptr) { SSL_free(session); session = nullptr; return; }
        BIO *bio = BIO_new(socket_method());
        if (bio == nullptr) { SSL_free(session); session = nullptr; return; }
        socket.descriptor = descriptor;
        BIO_set_data(bio, &socket);
        SSL_set_bio(session, bio, bio);
        SSL_set_connect_state(session);
        static constexpr unsigned char offered[] = "\x08http/1.1";
        if (SSL_set_alpn_protos(session, offered, sizeof(offered) - 1U) != 0) {
            SSL_free(session);
            session = nullptr;
        }
    }

    ~Impl()
    {
        SSL_free(session);
        SSL_CTX_free(context);
    }

    TlsIoResult result(int returned, std::size_t bytes) noexcept
    {
        // No OpenSSL call may intervene between the operation and this query.
        const int error = SSL_get_error(session, returned);
        switch (error) {
        case SSL_ERROR_NONE: return {TlsIoState::Ready, bytes, 0};
        case SSL_ERROR_WANT_READ: return {TlsIoState::WantRead, 0U, 0};
        case SSL_ERROR_WANT_WRITE: return {TlsIoState::WantWrite, 0U, 0};
        case SSL_ERROR_ZERO_RETURN: return {TlsIoState::Closed, 0U, 0};
        default:
            return {TlsIoState::Error, 0U,
                socket.error != 0 && socket.error != EAGAIN && socket.error != EWOULDBLOCK ? socket.error : EPROTO};
        }
    }
};

TlsSession::TlsSession(int descriptor) : impl_(std::make_unique<Impl>(descriptor)) {}
TlsSession::~TlsSession() = default;
bool TlsSession::valid() const noexcept { return impl_->session != nullptr; }

TlsIoResult TlsSession::handshake() noexcept
{
    if (!valid()) return {TlsIoState::Error, 0U, EIO};
    ERR_clear_error();
    impl_->socket.error = 0;
    const int returned = SSL_connect(impl_->session);
    return impl_->result(returned, 0U);
}

TlsIoResult TlsSession::write(std::span<const std::uint8_t> data) noexcept
{
    if (!valid()) return {TlsIoState::Error, 0U, EIO};
    ERR_clear_error();
    impl_->socket.error = 0;
    std::size_t bytes = 0U;
    const int returned = SSL_write_ex(impl_->session, data.data(), data.size(), &bytes);
    return impl_->result(returned, bytes);
}

TlsIoResult TlsSession::read(std::span<std::uint8_t> data) noexcept
{
    if (!valid()) return {TlsIoState::Error, 0U, EIO};
    ERR_clear_error();
    impl_->socket.error = 0;
    std::size_t bytes = 0U;
    const int returned = SSL_read_ex(impl_->session, data.data(), data.size(), &bytes);
    return impl_->result(returned, bytes);
}

TlsMetadata TlsSession::metadata() const
{
    TlsMetadata metadata;
    if (!valid() || SSL_is_init_finished(impl_->session) != 1) return metadata;
    std::unique_ptr<X509, decltype(&X509_free)> certificate(SSL_get1_peer_certificate(impl_->session), X509_free);
    if (certificate) {
        const int length = i2d_X509(certificate.get(), nullptr);
        if (length > 0 && length <= kMaximumLeafBytes) {
            std::vector<std::uint8_t> der(static_cast<std::size_t>(length));
            unsigned char *cursor = der.data();
            if (i2d_X509(certificate.get(), &cursor) == length) metadata = parse_tls_certificate(der);
        }
    }
    metadata.detected = true;
    const int version = SSL_version(impl_->session);
    if (version == TLS1_2_VERSION) metadata.protocol_version = "TLS 1.2";
    else if (version == TLS1_3_VERSION) metadata.protocol_version = "TLS 1.3";
    const unsigned char *selected = nullptr;
    unsigned int length = 0U;
    SSL_get0_alpn_selected(impl_->session, &selected, &length);
    if (length > 0U && length <= 255U) metadata.alpn.emplace_back(reinterpret_cast<const char *>(selected), length);
    return metadata;
}

} // namespace skan::detect
