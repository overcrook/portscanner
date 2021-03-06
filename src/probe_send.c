#include <netinet/in.h>
#include <assert.h>
#include "packet.h"
#include "probe_send.h"
#include "log.h"

int probe_send_one(int sock, struct route_info *route, in_port_t sport, in_port_t dport, uint32_t tcp_sn)
{
	uint8_t packet[500];
	struct tcp_setup tcp_setup = {
		.route = route,
		.src_port = sport,
		.dst_port = dport,
		.sn = tcp_sn,
	};

	socklen_t addrlen;
	union {
		struct sockaddr_in  in4;
		struct sockaddr_in6 in6;
	} addr = {
		.in4.sin_family = route->af, // одновременно задаем family для IPv4/IPv6 и зануляем все остальное
	};

	if (route->af == AF_INET6) {
		memcpy(&addr.in6.sin6_addr, &route->dst, sizeof(addr.in6.sin6_addr));
		addrlen = sizeof(struct sockaddr_in6);
	} else {
		memcpy(&addr.in4.sin_addr,  &route->dst, sizeof(addr.in4.sin_addr));
		addrlen = sizeof(struct sockaddr_in);
	}

	ssize_t packet_size = packet_craft(&tcp_setup, packet, sizeof(packet));

	assert(packet_size > 0);

	if (sendto(sock, packet, packet_size, 0, (struct sockaddr *) &addr, addrlen) < 0) {
		return -errno;
	}

	return 0;
}
