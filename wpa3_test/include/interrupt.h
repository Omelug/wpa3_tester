#pragma once
#include <atomic>
#include <chrono>
#include <csignal>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include "logger/error_log.h"

// Debug macro - only active in Debug builds
#ifdef DEBUG_FN
	#define IF_DEBUG(x)                                                                                                \
		do { x; } while(0);
#else
	#define IF_DEBUG(x)                                                                                                \
		do {                                                                                                           \
		} while(0);
#endif

struct InterruptPipe {
	int read_fd, write_fd;

	InterruptPipe() {
		int fds[2];
		if(pipe2(fds, O_NONBLOCK | O_CLOEXEC) < 0) throw wpa3_tester::run_err("pipe2 failed");
		read_fd = fds[0];
		write_fd = fds[1];
	}

	~InterruptPipe() {
		close(read_fd);
		close(write_fd);
	}

	void trigger() const {
		constexpr char b = 1;
		write(write_fd, &b, 1);
	}
};

inline InterruptPipe g_interrupt_pipe;
inline std::atomic g_interrupted{ false };

inline void interruptible_sleep(const std::chrono::microseconds duration, bool error = true) {
	if(g_interrupted) {
		if(error) throw wpa3_tester::interrupted_err("interruptible_sleep");
		return;
	}
	pollfd pfd{ g_interrupt_pipe.read_fd, POLLIN, 0 };
	poll(&pfd, 1, static_cast<int>(duration.count() / 1000));
	if(g_interrupted && error) throw wpa3_tester::interrupted_err("interruptible_sleep");
}

inline void setup_signals() {
	struct sigaction sa{};
	sa.sa_handler = [](int) {
		g_interrupted.store(true, std::memory_order_relaxed);
		g_interrupt_pipe.trigger();
	};
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, nullptr);
	sigaction(SIGTERM, &sa, nullptr);
}
