#pragma once

namespace webserver::app {

class Application final {
public:
    [[nodiscard]] int run(int argc, char* argv[]) const;
};

} // namespace webserver::app

