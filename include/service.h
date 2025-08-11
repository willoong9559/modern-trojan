#pragma once

#include <cstdint>
#include <array>
#include "boost/asio.hpp"
#include "conf.h"

using std::array;
using boost::asio::ip::tcp;
using boost::asio::ip::udp;
using boost::asio::awaitable;
using boost::asio::io_context;
using conf::ServerConfig;

namespace service {
    struct Server {
        tcp::acceptor listen;
        tcp::resolver tcp_resolver;
        udp::resolver udp_resolver;
        array<uint8_t, 56> password;
    };

    // Setup a server, may throw exceptions.
    Server build_server(io_context& ctx, ServerConfig config);

    // Launch a server.
    awaitable<void> run_server(Server server) noexcept;
}
