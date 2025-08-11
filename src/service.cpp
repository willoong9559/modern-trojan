#include "service.h"

#include "boost/asio.hpp"
#include <boost/system/error_code.hpp>
#include "boost/asio/as_tuple.hpp"
#include "boost/asio/experimental/awaitable_operators.hpp"

// WebSocket support
#include "boost/beast/core.hpp"
#include "boost/beast/http.hpp"
#include "boost/beast/websocket.hpp"

#include "fmt/core.h"

#include "ec.h"
#include "buf.h"
#include "hash.h"
#include "proto.h"

using boost::asio::ip::tcp;
using boost::asio::ip::udp;

using boost::asio::co_spawn;
using boost::asio::detached;
using boost::asio::awaitable;
using boost::asio::as_tuple_t;
using boost::system::error_code;
constexpr auto use_await = boost::asio::as_tuple(boost::asio::use_awaitable);
namespace this_coro = boost::asio::this_coro;
using namespace boost::asio::experimental::awaitable_operators;

// Beast aliases
namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;

using ec::EC;
using buffer::Slice;
using buffer::Buffer;

namespace common {
    // Read until "Request" is parsed, return <parsed, read> bytes.
    template<typename _Stream, typename _Request>
    awaitable<std::pair<int, int>> read_until_parsed(
        _Stream& stream,
        Slice<uint8_t> buf,
        _Request *request,
        int read_times = -1
    ) noexcept {
        size_t read_n = 0;
        
        while (read_times-- != 0) {
            auto [ec, n] = co_await stream.async_read_some(
                boost::asio::buffer(buf.data() + read_n, buf.size() - read_n),
                use_await);
            
            // read err or eof
            if (ec || n <= 0) [[unlikely]] {
                co_return std::pair{-EC::ErrRead, -1};
            }
            read_n += n;

            auto decode_n = request->decode(buf.slice_until(read_n));

            if (decode_n == -EC::MoreData) [[unlikely]] {
                continue;
            }
            co_return std::pair{decode_n, read_n};
        }        
    }

    // Read until buffer is filled.
    template<typename _Stream>
    awaitable<int> read_exact(_Stream& stream, Slice<uint8_t> buf) noexcept {
        while (buf.size() > 0) {
            auto [ec, n] = co_await stream.async_read_some(
                boost::asio::buffer(buf.data(), buf.size()),
                use_await);
            
            // read error
            if (ec || n <= 0) [[unlikely]] { co_return -EC::ErrRead; }

            buf.advance(n);
        }
        co_return EC::Ok;
    }

    // Write all data to stream.
    template<typename _Stream> 
    awaitable<int> write_all(_Stream& stream, Slice<const uint8_t> buf) noexcept {
        while (buf.size() > 0) {
            auto [ec, n] = co_await stream.async_write_some(
                boost::asio::buffer(buf.data(), buf.size()),
                use_await);

            // write err
            if (ec || n <=0) [[unlikely]] { co_return -EC::ErrWrite; }

            buf.advance(n);
        }
        co_return EC::Ok;
    }

    // WebSocket write function
    template<typename _WebSocket>
    awaitable<int> websocket_write_all(_WebSocket& ws, Slice<const uint8_t> buf) noexcept {
        auto [ec, n] = co_await ws.async_write(
            boost::asio::buffer(buf.data(), buf.size()),
            use_await);
        
        if (ec) [[unlikely]] { co_return -EC::ErrWrite; }
        co_return EC::Ok;
    }

    // WebSocket read function
    template<typename _WebSocket>
    awaitable<int> websocket_read_some(_WebSocket& ws, Slice<uint8_t> buf) noexcept {
        beast::flat_buffer buffer;
        auto [ec, bytes_read] = co_await ws.async_read(buffer, use_await);
        
        if (ec) [[unlikely]] { co_return -EC::ErrRead; }
        
        auto data = buffer.data();
        size_t copy_size = std::min(buf.size(), data.size());
        std::memcpy(buf.data(), data.data(), copy_size);
        
        co_return copy_size;
    }

    // Shutdown socket.
    template<typename Stream>
    awaitable<void> async_shutdown(Stream& socket) noexcept { co_return; }

    template<>
    awaitable<void> async_shutdown(tcp::socket& socket) noexcept {
        boost::system::error_code ec;
        socket.cancel(ec);
        socket.shutdown(tcp::socket::shutdown_send, ec);
        co_return;
    }

    // WebSocket shutdown
    template<typename WebSocket>
    awaitable<void> websocket_shutdown(WebSocket& ws) noexcept {
        boost::system::error_code ec;
	co_await ws.async_close(websocket::close_code::normal, use_await);
        co_return;
    }

    // Copy from stream1 to stream2.
    template<typename _Stream1, typename _Stream2>
    awaitable<void> forward(_Stream1& a, _Stream2& b, Slice<uint8_t> buf) noexcept {
        while(true) {
            auto [ec, n] = co_await a.async_read_some(
                boost::asio::buffer(buf.data(), buf.size()),
                use_await);

            // read err or eof
            if (ec || n <= 0) [[unlikely]] {
                co_await async_shutdown(b);
                co_return; 
            }

            if (co_await write_all(b, buf.slice_until(n)) < 0) [[unlikely]] { co_return; }
        }
    }

    // Forward from WebSocket to TCP
    template<typename _WebSocket, typename _Stream>
    awaitable<void> websocket_to_tcp(_WebSocket& ws, _Stream& tcp, Slice<uint8_t> buf) noexcept {
        while(true) {
            auto n = co_await websocket_read_some(ws, buf);
            if (n <= 0) [[unlikely]] {
                co_await async_shutdown(tcp);
                co_return;
            }

            if (co_await write_all(tcp, buf.slice_until(n)) < 0) [[unlikely]] { co_return; }
        }
    }

    // Forward from TCP to WebSocket
    template<typename _Stream, typename _WebSocket>
    awaitable<void> tcp_to_websocket(_Stream& tcp, _WebSocket& ws, Slice<uint8_t> buf) noexcept {
        while(true) {
            auto [ec, n] = co_await tcp.async_read_some(
                boost::asio::buffer(buf.data(), buf.size()),
                use_await);

            if (ec || n <= 0) [[unlikely]] {
                co_await websocket_shutdown(ws);
                co_return;
            }

            if (co_await websocket_write_all(ws, buf.slice_until(n)) < 0) [[unlikely]] { co_return; }
        }
    }

    // Resolve address to tcp/udp endpoint.
    template<typename _Resolver, typename _Endpoint>
    awaitable<int> resolve_addr(
        _Resolver& resolver,
        const socks5::Address& addr,
        _Endpoint *endpoint
    ) noexcept {
        using socks5::helper::overloaded;

        auto port = addr.port;        
        auto ret = co_await std::visit(overloaded {
            [port, endpoint](address ip) -> awaitable<int> {
                *endpoint = _Endpoint(ip, port);
                co_return EC::Ok;
            },
            [port, endpoint, &resolver](const string& addr) -> awaitable<int> {
                auto [ec, result] = co_await resolver.async_resolve(addr, "", use_await);
                if (ec) { co_return -EC::ErrResolve; }
                *endpoint = *result.begin();
                endpoint->port(port);
                co_return EC::Ok;
            }
        }, addr.host);

        co_return ret;
    }
}

namespace websocket_server_impl {
    using trojan::Request;
    using service::Server;
    using common::read_exact;
    using common::read_until_parsed;
    using common::write_all;
    using common::websocket_write_all;
    using common::websocket_read_some;
    using common::websocket_to_tcp;
    using common::tcp_to_websocket;
    using common::resolve_addr;

    awaitable<void> handle_websocket(Server& server, tcp::socket stream) noexcept {

        // Create WebSocket stream and accept handshake
        websocket::stream<tcp::socket> ws(std::move(stream));
        
        // Accept WebSocket handshake
        auto [ec] = co_await ws.async_accept(use_await);
        if (ec) {
            fmt::print("WebSocket handshake failed: {}\n", ec.message());
            co_return;
        }

        fmt::print("WebSocket connection established\n");

        // Set binary mode for data transfer
        ws.binary(true);

        tcp::socket remote_stream(ws.get_executor());
        boost::system::error_code sock_ec;

        Request request;
        Buffer<uint8_t> buffer1;
        Buffer<uint8_t> buffer2;

        // Read trojan request from WebSocket
        auto n = co_await websocket_read_some(ws, buffer1.slice());
        if (n <= 0) {
            fmt::print("Failed to read trojan request from WebSocket\n");
            co_return;
        }

        auto decode_n = request.decode(buffer1.slice_until(n));
        if (decode_n < 0) {
            fmt::print("Invalid trojan request from WebSocket\n");
            co_return;
        }

        // Check password
        if (std::memcmp(request.password.data(), server.password.data(), server.password.size())) {
            fmt::print("Incorrect password from WebSocket client\n");
            co_return;
        }

        // Handle TCP connection (UDP not supported over WebSocket in this example)
        if (request.cmd != trojan::CMD::CONNECT) {
            fmt::print("Only TCP CONNECT supported over WebSocket\n");
            co_return;
        }

        // Connect to remote
        tcp::endpoint remote_addr;
        if (co_await resolve_addr(server.tcp_resolver, request.addr, &remote_addr) < 0) {
            fmt::print("Resolve error for WebSocket request\n");
            co_return;
        }

        auto [econn] = co_await remote_stream.async_connect(remote_addr, use_await);
        if (econn) {
            fmt::print("Connect to remote error from WebSocket: {}\n", econn.message());
            co_return;
        }

        // Write any remaining data from initial request
        if (decode_n < n) {
            if (co_await write_all(remote_stream, buffer1.slice(decode_n, n)) < 0) {
                co_return;
            }
        }

        fmt::print("Starting WebSocket bidirectional forwarding\n");

        // Bidirectional forwarding between WebSocket and remote TCP
        co_await(
            websocket_to_tcp(ws, remote_stream, buffer1.slice()) ||
            tcp_to_websocket(remote_stream, ws, buffer2.slice())
        );
    }
}

namespace trojan_server_impl {
    using trojan::Request;
    using service::Server;
    using common::read_exact;
    using common::read_until_parsed;
    using common::write_all;
    using common::forward;
    using common::resolve_addr;

#if defined(TROJAN_USE_UDP)
    awaitable<void> handle_udp(
        Server& server,
        tcp::socket& tcp_stream,
        Slice<uint8_t> buf1, Slice<uint8_t> buf2,
        int offset
    ) noexcept {
        udp::socket udp_socket(tcp_stream.get_executor());
        // first packet
        {
            boost::system::error_code ec;
            trojan::UdpPacket pkt_hdr;
            udp::endpoint remote_addr;
            // atyp + addr[0]
            if (offset < 2) {
                if (co_await read_exact(tcp_stream, buf1.slice(offset, 2)) < 0) { co_return; }
            }

            // port + length + crlf
            auto more_required = 2 + 2 + 2;
            switch (buf1[0]) {
                case socks5::ATYP::IPV4: { more_required += 4 - 1; break; }
                case socks5::ATYP::IPV6: { more_required += 16 - 1; break;}
                case socks5::ATYP::FQDN: { more_required += buf1[1]; break; }
                default: { co_return; }
            }

            // read left bytes of packet header
            if (offset < more_required + 2) {
                if (co_await read_exact(tcp_stream, buf1.slice(std::max(offset, 2), more_required)) < 0) {
                    co_return;
                }
            }

            // parse packet header
            if (pkt_hdr.decode(buf1.slice_until(more_required + 2)) < 0) { co_return; }

            if (pkt_hdr.length > buffer::BUF_SIZE) { co_return; }

            // read payload data
            if (co_await read_exact(tcp_stream, buf1.slice_until(pkt_hdr.length)) < 0) { co_return; }

            // resolve remote addr
            if (co_await resolve_addr(server.udp_resolver, pkt_hdr.addr, &remote_addr) < 0){ co_return; }

            // open and bind udp socket
            udp_socket.open(remote_addr.protocol(), ec);
            if (ec) { co_return; }
            udp_socket.bind(udp::endpoint(remote_addr.protocol(), 0), ec);
            if (ec) { co_return; }
            udp_socket.set_option(udp::socket::reuse_address(true), ec);

            // send udp packet
            auto [ec2, send_n] = co_await udp_socket.async_send_to(
                boost::asio::buffer(buf1.data(), pkt_hdr.length),
                remote_addr, use_await);
            if (ec2) { co_return; }
        }

        auto udp_to_tcp = [&tcp_stream, &udp_socket, buf2]() -> awaitable<void> {
            udp::endpoint addr;
            array<uint8_t, 256> hdr_buf; 

            while (true) {
                // read from remote
                auto [ec, recv_n] = co_await udp_socket.async_receive_from(
                    boost::asio::buffer(buf2.data(), buf2.size()),
                    addr, use_await);
                if (ec) { co_return; }

                // BUF_SIZE < u16::MAX
                trojan::UdpPacket pkt_hdr{addr.address(), uint16_t(recv_n)};
                size_t hdr_len = pkt_hdr.encode({ hdr_buf.data(), hdr_buf.size() });

                // write udp header
                if (co_await write_all(tcp_stream, { hdr_buf.data(), hdr_len }) < 0) {
                    co_return;
                }

                // write udp payload
                if (co_await write_all(tcp_stream, buf2.slice_until(recv_n)) < 0) {
                    co_return;
                }
            }
        };

        auto tcp_to_udp = [&server, &tcp_stream, &udp_socket, buf1, offset]() -> awaitable<void> {
            udp::endpoint remote_addr;
            trojan::UdpPacket pkt_hdr;
            while(true) {
                // read atyp + addr[0]
                if (co_await read_exact(tcp_stream, buf1.slice_until(2)) < 0) { co_return; }
                // port + length + crlf
                auto more_required = 2 + 2 + 2;
                switch (buf1[0]) {
                    case socks5::ATYP::IPV4: { more_required += 4 - 1; break; }
                    case socks5::ATYP::IPV6: { more_required += 16 - 1; break;}
                    case socks5::ATYP::FQDN: { more_required += buf1[1]; break; }
                    default: { co_return; }
                }
                // read left bytes of packet header
                if (co_await read_exact(tcp_stream, buf1.slice(2, more_required)) < 0) {
                    co_return;
                }
                // parse packet header
                if (pkt_hdr.decode(buf1.slice_until(more_required + 2)) < 0) { co_return; }

                if (pkt_hdr.length > buffer::BUF_SIZE) { co_return; }

                // read payload data
                if (co_await read_exact(tcp_stream, buf1.slice_until(pkt_hdr.length)) < 0) { co_return; }

                // resolve remote addr
                if (co_await resolve_addr(server.udp_resolver, pkt_hdr.addr, &remote_addr) < 0){ co_return; }

                // send udp packet
                auto [ec, send_n] = co_await udp_socket.async_send_to(
                    boost::asio::buffer(buf1.data(), pkt_hdr.length),
                    remote_addr, use_await);
                if (ec) { co_return; }
            }
        };

        co_await(tcp_to_udp() || udp_to_tcp());
    }
#endif

    awaitable<void> handle(Server& server, tcp::socket stream) noexcept {
        // Directly handle as WebSocket connection
        co_await websocket_server_impl::handle_websocket(server, std::move(stream));
    }
}

namespace service_impl {
    template<typename _Provider, typename _Handler>
    awaitable<void> run_service(_Provider provider, _Handler handle) noexcept {
        auto ctx = provider.listen.get_executor();

        while(true) {
            auto [ec, stream] = co_await provider.listen.async_accept(use_await);

            if (ec) {
                fmt::print("Failed to accept: {}\n", ec.message());
                break;
            }

            co_spawn(ctx, handle(provider, std::move(stream)), detached);
        }
    }
}

namespace service {
    // Launch a server with WebSocket support.
    awaitable<void> run_server(Server server) noexcept {
        using service_impl::run_service;
        using trojan_server_impl::handle;
        co_await run_service(std::move(server), handle);
    }

    // Setup a server
    Server build_server(io_context& ctx, ServerConfig config) {
        tcp::resolver resolver(ctx);
	auto results = resolver.resolve(config.host, config.port);
        tcp::endpoint listen_addr = *results.begin();
        tcp::acceptor listener(ctx, listen_addr);

        listener.set_option(tcp::acceptor::reuse_address(true));

        auto password = hash::sha224((uint8_t*)config.password.data(), config.password.size());

        return Server {
            std::move(listener),
            std::move(resolver),
            udp::resolver(ctx),
            password
        };
    }
}
