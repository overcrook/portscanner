#include <netdb.h>
#include <assert.h>
#include "packet.h"
#include "probe_send.h"
#include "log.h"

static int probe_send_one(int sock, struct route_info *route, in_port_t sport, in_port_t dport, uint32_t tcp_sn,
                          int retry_index)
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
		// TODO: стоит обработать errno и проверить причину ошибки отправки
		plog_err("Cannot send a packet on raw socket to dport %d (retry_index %d)", dport, retry_index);
		return -1;
	}

	return 0;
}

int probe_send(int sock, struct route_info *route, in_port_t sport, in_port_t dport_start, in_port_t dport_end,
               uint32_t tcp_sn, int retry_index)
{
	if (!dport_end)
		dport_end = dport_start;

	int ret = -1;

	for (in_port_t dport = dport_start; dport <=dport_end; dport++) {
		if (probe_send_one(sock, route, sport, dport, tcp_sn, retry_index) == 0)
			ret = 0;
	}

	// возвращаем успех, если хотя бы один пакет был успешно отправлен и есть смысл ожидать ответы
	return ret;
}
