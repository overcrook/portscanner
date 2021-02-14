#include <stdint.h>
#include <inttypes.h>
#include <poll.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <assert.h>
#include <time.h>

#include "portscan.h"
#include "route.h"
#include "probe_recv.h"
#include "log.h"

union sockaddr_in46 {
	struct sockaddr_in  in4;
	struct sockaddr_in6 in6;
};

static inline int compare_addr(const struct route_info *route, const union sockaddr_in46 *addr)
{
	if (route->af == AF_INET6)
		return memcmp(&route->dst, &addr->in6.sin6_addr, sizeof(addr->in6.sin6_addr));

	return memcmp(&route->dst, &addr->in4.sin_addr, sizeof(addr->in4.sin_addr));
}

static inline struct timespec timeget(void)
{
	struct timespec ts;

	int ret = clock_gettime(CLOCK_MONOTONIC, &ts);

	assert(ret == 0);
	return ts;
}

static inline long timediff(struct timespec *begin)
{
	struct timespec end = timeget();

	if (end.tv_sec > begin->tv_sec)
		return (end.tv_sec - begin->tv_sec) * 1000L + (end.tv_nsec + 1000000000L - begin->tv_nsec) / 1000000L;

	return (end.tv_nsec - begin->tv_nsec) / 1000000L;
}

static ssize_t recv_packet(int sock, union sockaddr_in46 *addr, uint8_t *buffer, size_t buffer_size)
{
	struct iovec iov = {
		.iov_base = buffer,
		.iov_len  = buffer_size,
	};

	struct msghdr msghdr = {
		.msg_iov     = &iov,
		.msg_iovlen  = 1,
		.msg_name    = addr,
		.msg_namelen = sizeof(*addr),
	};

	ssize_t nbytes = recvmsg(sock, &msghdr, 0);

	if (nbytes < 0) {
		plog_warning("Error reading answer from raw socket");
		return -1;
	}

	// Проверим, что получили не обрезанный пакет
	if (msghdr.msg_flags & MSG_TRUNC) {
		// не хватает буфера для одного TCP SYN-ACK?
		log_warning("Received a packet bigger than expected (max %zu bytes)", buffer_size);
		return -1;
	}

	log_debug("Received %zi bytes", nbytes);
	return nbytes;
}

static int filter_by_iphdr(const struct iphdr *hdr, struct route_info *route)
{
	if (hdr->protocol != IPPROTO_TCP) {
		log_warning("Received packet is not a TCP");
		return -1;
	}

	if (memcmp(&hdr->saddr, &route->dst, sizeof(hdr->saddr)) != 0) {
		log_warning("Received a packet from different host");
		return -1;
	}

	if (ntohs(hdr->tot_len) - hdr->ihl < sizeof(struct tcphdr)) {
		log_warning("Received packet is too small to contain a TCP header");
		return -1;
	}

	// Похоже, что это от нашей целевой машины
	return 0;
}

static const struct tcphdr *filter_by_ip(const uint8_t *packet, size_t packet_size, struct route_info *route)
{
	const struct tcphdr *tcphdr = NULL;

	if (route->af == AF_INET6) {
		// При работе с raw-socket AF_INET6 ядро не включает заголовок IPv6 в ответ
		tcphdr = (const struct tcphdr *) packet;
	} else {
		if (packet_size < sizeof(struct iphdr)) {
			log_warning("Received packet is too small to contain an IPv4 header");
			return NULL;
		}

		if (filter_by_iphdr((const struct iphdr *) packet, route))
			return NULL;

		tcphdr = (const struct tcphdr *) (packet + sizeof(struct iphdr));
	}

	// На всякий случай убедимся, что пакет действительно вмещает в себя заголовок TCP
	int expected_size = (((const uint8_t *) tcphdr) - packet) + sizeof(struct tcphdr);

	if (expected_size > packet_size) {
		log_warning("Received a truncated packet (got %d bytes, expected %d)", packet_size, expected_size);
		return NULL;
	}

	// Похоже, что это от нашей целевой машины
	return tcphdr;
}

static int filter_by_tcp(const struct tcphdr *hdr, in_port_t sport, in_port_t dport_start, in_port_t dport_end,
                         uint32_t tcp_sn)
{
	if (ntohs(hdr->th_dport) != sport) {
		log_warning("Received packet is for different destination port (got %d, expected %d)", ntohs(hdr->th_dport), sport);
		return -1;
	}

	if (ntohs(hdr->th_sport) < dport_start || ntohs(hdr->th_sport) > dport_end) {
		log_warning("Received packet is from different source port (got %d, expected %d-%d)", ntohs(hdr->th_sport), dport_start, dport_end);
		return -1;
	}

	if ((uint32_t) ntohl(hdr->th_ack) != (uint32_t) (tcp_sn + 1U)) {
		log_warning("TCP ACK sequence mismatch (got %" PRIu32 ", expected %" PRIu32")", ntohl(hdr->th_ack), tcp_sn + 1U);
		return -1;
	}

	// Проверим, что в пакете либо SYNACK, либо RST
	if (!(hdr->rst || (hdr->syn && hdr->ack))) {
		log_warning("TCP flags unexpected: %x)", hdr->th_flags);
		return -1;
	}

	// Похоже, что это нужный нам ответ
	return 0;
}

int probe_recv_one(int sock, struct route_info *route, in_port_t sport, in_port_t dport_start,
                   in_port_t dport_end, uint32_t tcp_sn, struct portscan_result *result)
{
	uint8_t buffer[2048]; // достаточный для получения с учетом MTU 1500
	union sockaddr_in46 addr;
	const struct tcphdr *tcphdr;

	ssize_t nbytes = recv_packet(sock, &addr, buffer, sizeof(buffer));

	if (nbytes < 0)
		return -1;

	// Сразу отсекаем по стеку IP
	if (route->af != addr.in4.sin_family) {
		log_debug("Received packet from different IP stack"); // такое вообще возможно в нашем случае?
		return -1;
	}

	// Проверим адрес получения на всякий случай
	if (compare_addr(route, &addr)) {
		log_debug("Received packet from different host");
		return -1;
	}

	tcphdr = filter_by_ip(buffer, nbytes, route);

	if (tcphdr == NULL)
		return -1; // пропускаем

	if (filter_by_tcp(tcphdr, sport, dport_start, dport_end, tcp_sn) < 0)
		return -1; // пропускаем

	// Нашли интересующий нас ответ
	result->port   = ntohs(tcphdr->th_sport);
	result->status = (tcphdr->rst) ? PORT_STATUS_CLOSED : PORT_STATUS_OPEN;
	log_debug("Determined port %d status: %s", result->port, portscan_strstatus(result->status));
	return 0;
}
