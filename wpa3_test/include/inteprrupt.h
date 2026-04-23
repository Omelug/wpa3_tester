#pragma once
#pragma once
#include <csignal>
#include <stdexcept>
#include <unistd.h>
#include <fcntl.h>

struct InterruptPipe{
    int read_fd, write_fd;

    InterruptPipe(){
        int fds[2];
        if(pipe2(fds, O_NONBLOCK | O_CLOEXEC) < 0) throw std::runtime_error("pipe2 failed");
        read_fd = fds[0];
        write_fd = fds[1];
    }

    ~InterruptPipe(){
        close(read_fd);
        close(write_fd);
    }

    void trigger() const{
        constexpr char b = 1;
        write(write_fd, &b, 1);
    }
};

inline InterruptPipe g_interrupt_pipe;

inline void setup_signals(){
    struct sigaction sa{};
    sa.sa_handler = [](int){ g_interrupt_pipe.trigger(); };
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
}