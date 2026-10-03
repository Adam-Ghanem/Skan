#include <cassert>
#include <chrono>
#include <csignal>
#include <fstream>
#include <iostream>
#include <utility>
#include <string>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "detect/service_detector.hpp"

namespace {

struct Fixture final {
    int version{TLS1_2_VERSION};
    int family{AF_INET};
    std::size_t probes{2U};
    std::size_t response_limit{8192U};
    std::size_t split{0U};
    bool abrupt_eof{false};
    std::string message{"HTTP/1.1 200 OK\r\nServer: nginx/1.26.2\r\nContent-Length: 26\r\n\r\nServer: BodyProduct/8.8.8\n"};
};

SSL_CTX *server_context(int version)
{
    SSL_CTX *context = SSL_CTX_new(TLS_server_method());
    assert(context != nullptr);
    assert(SSL_CTX_set_min_proto_version(context, version) == 1);
    assert(SSL_CTX_set_max_proto_version(context, version) == 1);
    EVP_PKEY_CTX *generator = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    assert(generator != nullptr && EVP_PKEY_keygen_init(generator) == 1);
    assert(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(generator, NID_X9_62_prime256v1) == 1);
    EVP_PKEY *key = nullptr;
    assert(EVP_PKEY_keygen(generator, &key) == 1);
    EVP_PKEY_CTX_free(generator);
    X509 *certificate = X509_new();
    assert(certificate != nullptr);
    assert(X509_set_version(certificate, 2L) == 1);
    assert(ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1L) == 1);
    assert(X509_gmtime_adj(X509_getm_notBefore(certificate), -60L) != nullptr);
    assert(X509_gmtime_adj(X509_getm_notAfter(certificate), 86400L) != nullptr);
    assert(X509_set_pubkey(certificate, key) == 1);
    auto *name = X509_get_subject_name(certificate);
    // A certificate product/version lookalike must never become software identity.
    assert(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char *>("CertificateProduct/9.9.9"), -1, -1, 0) == 1);
    assert(X509_set_issuer_name(certificate, name) == 1);
    X509_EXTENSION *san = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name,
        const_cast<char *>("DNS:fixture.test"));
    assert(san != nullptr && X509_add_ext(certificate, san, -1) == 1);
    X509_EXTENSION_free(san);
    assert(X509_sign(certificate, key, EVP_sha256()) > 0);
    assert(SSL_CTX_use_certificate(context, certificate) == 1);
    assert(SSL_CTX_use_PrivateKey(context, key) == 1);
    X509_free(certificate);
    EVP_PKEY_free(key);
    SSL_CTX_set_alpn_select_cb(context, [](SSL *, const unsigned char **out, unsigned char *length,
        const unsigned char *offered, unsigned int offered_length, void *) {
        static constexpr unsigned char supported[] = "\x08http/1.1";
        unsigned char *selected = nullptr;
        if (SSL_select_next_proto(&selected, length, supported, sizeof(supported) - 1U,
                                  offered, offered_length) != OPENSSL_NPN_NEGOTIATED) {
            return SSL_TLSEXT_ERR_NOACK;
        }
        *out = selected;
        return SSL_TLSEXT_ERR_OK;
    }, nullptr);
    return context;
}

int listener(std::uint16_t &port, int family)
{
    const int descriptor = ::socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (family == AF_INET6 && descriptor < 0) return -1;
    assert(descriptor >= 0);
    if (family == AF_INET6) {
        sockaddr_in6 address{};
        address.sin6_family = AF_INET6;
        address.sin6_addr = in6addr_loopback;
        if (::bind(descriptor, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0) {
            (void)::close(descriptor);
            return -1;
        }
        assert(::listen(descriptor, 4) == 0);
        socklen_t size = sizeof(address);
        assert(::getsockname(descriptor, reinterpret_cast<sockaddr *>(&address), &size) == 0);
        port = ntohs(address.sin6_port);
        return descriptor;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(::bind(descriptor, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) == 0);
    assert(::listen(descriptor, 4) == 0);
    socklen_t size = sizeof(address);
    assert(::getsockname(descriptor, reinterpret_cast<sockaddr *>(&address), &size) == 0);
    port = ntohs(address.sin_port);
    return descriptor;
}

skan::detect::ServiceProbeDatabase database(std::uint16_t port)
{
    std::ifstream input("data/service-probes.db");
    assert(input.is_open());
    std::string text{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    const auto probe = text.find("Probe TCP TLSClientHello");
    assert(probe != std::string::npos);
    const auto hints = text.find("ports=", probe);
    text.insert(hints + 6U, std::to_string(port) + ',');
    // Session activation must depend on request/rule semantics, not probe name.
    text.replace(probe, std::string("Probe TCP TLSClientHello").size(), "Probe TCP RenamedHandshake");
    skan::core::StatusCode status{};
    auto result = skan::detect::ServiceProbeDatabase::parse(text, status);
    assert(status == skan::core::StatusCode::Ok);
    return result;
}

void serve(int descriptor, const Fixture &fixture)
{
    ::alarm(6U);
    // Test fixture only: OpenSSL's stock server socket BIO can otherwise SIGPIPE.
    std::signal(SIGPIPE, SIG_IGN);
    SSL_CTX *context = server_context(fixture.version);
    bool application_seen = false;
    bool established = false;
    for (std::size_t attempt = 0U; attempt < fixture.probes; ++attempt) {
        const int client = ::accept4(descriptor, nullptr, nullptr, SOCK_CLOEXEC);
        if (client < 0) break;
        const timeval deadline{1, 0};
        (void)::setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline));
        (void)::setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &deadline, sizeof(deadline));
        SSL *session = SSL_new(context);
        assert(session != nullptr && SSL_set_fd(session, client) == 1);
        const bool current = SSL_accept(session) == 1;
        established = established || current;
        if (current && attempt == 1U) {
            char request[1024];
            const int count = SSL_read(session, request, sizeof(request));
            application_seen = count > 0 && std::string_view{request, static_cast<std::size_t>(count)}.starts_with("GET / HTTP/1.0\r\n");
            if (application_seen) {
                const auto send = [session](std::string_view bytes) {
                    assert(SSL_write(session, bytes.data(), static_cast<int>(bytes.size())) == static_cast<int>(bytes.size()));
                };
                if (fixture.split > 0U) {
                    send(std::string_view{fixture.message}.substr(0U, fixture.split));
                    send(std::string_view{fixture.message}.substr(fixture.split));
                } else {
                    send(fixture.message);
                }
                if (!fixture.abrupt_eof) (void)SSL_shutdown(session);
            }
        }
        SSL_free(session);
        (void)::close(client);
    }
    SSL_CTX_free(context);
    (void)::close(descriptor);
    ::_exit(established && (fixture.probes == 1U || application_seen) ? 0 : 1);
}

skan::detect::ServiceResult scan(const Fixture &fixture)
{
    using namespace skan;
    std::uint16_t port = 0U;
    const int descriptor = listener(port, fixture.family);
    if (descriptor < 0) {
        std::cerr << "SKIPPED: IPv6 TLS fixture unavailable\n";
        return {};
    }
    const pid_t child = ::fork();
    assert(child >= 0);
    if (child == 0) serve(descriptor, fixture);
    (void)::close(descriptor);
    io::IOEngine engine;
    detect::ServiceTransportRouter transport(engine);
    detect::ServiceDetectionConfig configuration;
    configuration.max_outstanding = 1U;
    configuration.timeout = std::chrono::milliseconds{1000};
    configuration.max_probes_per_port = fixture.probes;
    configuration.max_response_bytes = fixture.response_limit;
    detect::ServiceDetector detector(engine, transport, configuration, database(port));
    portscan::PortResult open;
    open.target = fixture.family == AF_INET6 ? "::1" : "127.0.0.1";
    open.port = {port, portscan::Protocol::Tcp};
    open.state = portscan::PortState::Open;
    assert(detector.submit({open}) == core::StatusCode::Ok);
    assert(detector.run() == core::StatusCode::Ok && detector.complete());
    int child_status = 0;
    assert(::waitpid(child, &child_status, 0) == child);
    assert(detector.results().size() == 1U);
    const auto result = detector.results().front();
    assert(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return result;
}

void https_requires_encrypted_application_evidence()
{
    using namespace skan;
    for (int version : {TLS1_2_VERSION, TLS1_3_VERSION}) {
      for (int family : {AF_INET, AF_INET6}) {
        Fixture fixture;
        fixture.version = version;
        fixture.family = family;
        // Separate TLS records cut through the HTTP status/header boundary.
        fixture.split = 17U;
        const auto result = scan(fixture);
        if (result.target.empty()) continue;
    assert(result.state == detect::DetectionState::Detected && result.service == "https");
    assert(result.product == "nginx" && result.version == "1.26.2");
    assert(result.tunnel == "tls" && result.tls_detected);
    assert(result.tls_version == (version == TLS1_2_VERSION ? "TLS 1.2" : "TLS 1.3"));
    assert(result.certificate_subject.find("CertificateProduct/9.9.9") != std::string::npos);
    assert(result.certificate_san_names == std::vector<std::string>{"fixture.test"});
    assert(result.alpn == std::vector<std::string>{"http/1.1"});
    assert(result.evidence && result.evidence->validator == "http-1x-v1");
    assert(result.evidence->body_complete);
      }
    }
}

void certificate_and_malformed_data_do_not_supply_application_identity()
{
    Fixture fixture;
    fixture.version = TLS1_3_VERSION;
    fixture.probes = 1U;
    const auto certificate_only = scan(fixture);
    assert(certificate_only.service == "tls" && certificate_only.tls_detected);
    assert(certificate_only.product.empty() && certificate_only.version.empty());
    assert(certificate_only.evidence && certificate_only.evidence->validator == "tls-session-v1");
    assert(certificate_only.certificate_subject.find("CertificateProduct/9.9.9") != std::string::npos);

    fixture.probes = 2U;
    fixture.message = "HTTP/1.1 200 OK\r\nServer: nginx/9.9.9\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx!\r\n0\r\n\r\n";
    fixture.split = fixture.message.find("1\r\nx!");
    const auto malformed = scan(fixture);
    assert(malformed.service == "tls" && malformed.tls_detected);
    assert(malformed.product.empty() && malformed.version.empty());

    fixture.split = 0U;
    fixture.message = "CertificateProduct/9.9.9 Server: Fake/8.8.8\n";
    const auto opaque = scan(fixture);
    assert(opaque.service == "tls" && opaque.tls_detected);
    assert(opaque.product.empty() && opaque.version.empty());
}

void buffered_records_are_drained_and_abrupt_eof_is_not_http_completion()
{
    Fixture fixture;
    fixture.version = TLS1_3_VERSION;
    fixture.message = "HTTP/1.1 200 OK\r\nServer: nginx/1.26.2\r\nContent-Length: 6000\r\n\r\n" + std::string(6000U, 'x');
    const auto buffered = scan(fixture);
    assert(buffered.service == "https" && buffered.evidence && buffered.evidence->body_complete);

    fixture.message = "HTTP/1.1 200 OK\r\nServer: nginx/9.9.9\r\n\r\nunfinished close-delimited body";
    fixture.abrupt_eof = true;
    const auto abrupt = scan(fixture);
    assert(abrupt.service == "tls" && abrupt.tls_detected);
    assert(abrupt.product.empty() && abrupt.version.empty());
}

} // namespace

int main()
{
    https_requires_encrypted_application_evidence();
    certificate_and_malformed_data_do_not_supply_application_identity();
    buffered_records_are_drained_and_abrupt_eof_is_not_http_completion();
}
