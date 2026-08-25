#include "app/Application.hpp"

#include <exception>
#include <iostream>

int main(int argc, char* argv[]) {
    try {
        return webserver::app::Application{}.run(argc, argv);
    } catch (const std::exception& error) {
        std::cerr << "fatal: " << error.what() << '\n';
        return 1;
    } catch (...) {
        std::cerr << "fatal: unknown exception\n";
        return 1;
    }
}

