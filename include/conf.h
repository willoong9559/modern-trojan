#pragma once

#include <string_view>
#include <fmt/core.h>

using std::string_view;

namespace conf {
    struct ServerConfig {
        inline void show() const noexcept {
            fmt::print("passwd={}\n", this->password);
            fmt::print("listen {}:{}..\n", this->host, this->port);
        };

        string_view host;
        string_view port;
        string_view password;
    };
}
