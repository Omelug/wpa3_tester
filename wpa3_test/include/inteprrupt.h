#pragma once
#include <atomic>
#include <chrono>
#include <csignal>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>

#include "logger/error_log.h"

struct InterruptPipe{
	int read_fd, write_fd;

	InterruptPipe(){
		int fds[2];
		if(pipe2(fds, O_NONBLOCK | O_CLOEXEC) < 0) throw wpa3_tester::run_err("pipe2 failed");
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
inline std::atomic g_interrupted{false};

inline void interruptible_sleep(const std::chrono::milliseconds duration){
	if(g_interrupted.load()) return;
	pollfd pfd{g_interrupt_pipe.read_fd, POLLIN, 0};
	poll(&pfd, 1, static_cast<int>(duration.count()));
}

inline void setup_signals(){
	struct sigaction sa{};
	sa.sa_handler = [](int){
		g_interrupted.store(true, std::memory_order_relaxed);
		g_interrupt_pipe.trigger();
	};
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, nullptr);
	sigaction(SIGTERM, &sa, nullptr);
}