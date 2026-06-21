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
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static int read_exact(int fd, void *buf, size_t n){
	size_t got = 0;
	while(got < n){
		ssize_t r = read(fd, (char*)buf + got, n - got);
		if(r <= 0) return -1;
		got += r;
	}
	return 0;
}

int main(int argc, char *argv[]){
	if(argc < 2){
		fprintf(stderr, "Usage: %s <monitor-iface>\n", argv[0]);
		return 1;
	}
	const char *iface = argv[1];

	int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(sock < 0){ perror("socket"); return 1; }

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
	if(ioctl(sock, SIOCGIFINDEX, &ifr) < 0){ perror("SIOCGIFINDEX"); return 1; }

	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof(sll));
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
		send(sock, buf, len, 0);
	}
	close(sock);
	return 0;
}
