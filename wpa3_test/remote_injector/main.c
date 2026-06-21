/*
 * Remote frame injector for OpenWrt.
 * Reads frames from stdin as: [2-byte BE length][frame bytes] and injects them
 * via a PF_PACKET raw socket on a monitor-mode interface.
 *
 * Cross-compile for OpenWrt target arch:
 *   mipsel:   mipsel-linux-musl-gcc -O2 -static -o remote_injector main.c
 *   arm:      arm-linux-musleabi-gcc -O2 -static -o remote_injector main.c
 *   aarch64:  aarch64-linux-musl-gcc -O2 -static -o remote_injector main.c
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

static int read_exact(const int fd, void *buf, const size_t n){
	size_t got = 0;
	while(got < n){
		const ssize_t r = read(fd, (char*)buf + got, n - got);
		if(r <= 0) return -1;
		got += r;
	}
	return 0;
}

int main(const int argc, char *argv[]){
	if(argc < 2){
		fprintf(stderr, "Usage: %s <monitor-iface>\n", argv[0]);
		return 1;
	}
	const char *iface = argv[1];

	const int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(sock < 0){ perror("socket"); return 1; }

	struct ifreq ifr = {0};
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
	if(ioctl(sock, SIOCGIFINDEX, &ifr) < 0){ perror("SIOCGIFINDEX"); return 1; }

	struct sockaddr_ll sll = {0};
	sll.sll_family   = AF_PACKET;
	sll.sll_ifindex  = ifr.ifr_ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);
	if(bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0){ perror("bind"); return 1; }

	static unsigned char buf[65536];
	while(1){
		uint16_t len_be;
		if(read_exact(STDIN_FILENO, &len_be, 2) < 0) break;
		uint16_t len = ntohs(len_be);
		if(len == 0) break;
		if(read_exact(STDIN_FILENO, buf, len) < 0) break;
		const ssize_t sent = send(sock, buf, len, 0);
		if (sent < 0) {
			perror("Injector - send error");
		} else {
			fprintf(stderr, "Injector - sent %zd bytes.\n", sent);
		}
	}
	close(sock);
	return 0;
}
