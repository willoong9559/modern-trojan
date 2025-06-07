#pragma once

#include <cstdint>
#include <array>
#include "asio.hpp"
#include "conf.h"

using std::array;
using asio::ip::tcp;
using asio::ip::udp;
using asio::awaitable;
using asio::io_context;
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