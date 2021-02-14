#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <unistd.h>

#include "log.h"
#include "route.h"

typedef int (*nl_cb_t)(struct nlmsghdr *nlh, void *arg);

static inline bool is_addr_empty(int af, const union in46_addr *addr)
{
	if (af == AF_INET6)
		return memcmp(&addr->v6, &in6addr_any, sizeof(in6addr_any)) == 0;

	return addr->v4.s_addr == INADDR_ANY;
}

static inline void *nlmsg_tail(const struct nlmsghdr *nlh)
{
	return ((uint8_t *) nlh) + NLMSG_ALIGN(nlh->nlmsg_len);
}

static inline void *nlmsg_extraheader(const struct nlmsghdr *nlh)
{
	return NLMSG_DATA(nlh);
}


static inline void nlattr_put(struct nlmsghdr *nlh, int type, const void *value, uint16_t size)
{
	struct nlattr *attr = nlmsg_tail(nlh);

	attr->nla_type = type;
	attr->nla_len  = NLA_HDRLEN + size;

	nlh->nlmsg_len += NLMSG_ALIGN(attr->nla_len);

	memcpy(((uint8_t *) attr) + NLA_HDRLEN, value, size);

	int pad = NLMSG_ALIGN(size) - size;

	if (pad)
		memset(attr + attr->nla_len, 0, pad);
}

static inline void nlattr_put_addr(struct nlmsghdr *nlh, int type, int af, const union in46_addr *addr)
{
	nlattr_put(nlh, type, addr, (af == AF_INET6) ? sizeof(addr->v6) : sizeof(addr->v4));
}

static inline void nlattr_put_u32(struct nlmsghdr *nlh, int type, uint32_t value)
{
	nlattr_put(nlh, type, &value, sizeof(value));
}

static void nl_prepare_request(struct nlmsghdr *nlh, const struct route_info *info)
{
	struct rtmsg *rtm = nlmsg_extraheader(nlh);

	nlh->nlmsg_type  = RTM_GETROUTE;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_len   = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct rtmsg));

	rtm->rtm_family = info->af;
	rtm->rtm_dst_len = (info->af == AF_INET6) ? 128 : 32;

	nlattr_put_addr(nlh, RTA_DST, info->af, &info->dst);

	if (!is_addr_empty(info->af, &info->src))
		nlattr_put_addr(nlh, RTA_SRC, info->af, &info->src);

	if (info->ifindex)
		nlattr_put_u32(nlh, RTA_OIF, info->ifindex);
}

static int nl_send(int sock, const struct nlmsghdr *nlh)
{
	struct sockaddr_nl nl_addr = {
		.nl_family = AF_NETLINK,
	};

	if (sendto(sock, nlh, nlh->nlmsg_len, 0, (struct sockaddr *) &nl_addr, sizeof(nl_addr)) < 0) {
		plog_err("Cannot send a request(RTM_GETROUTE) to Netlink");
		return -1;
	}

	return 0;
}

static int nl_recv(int sock, uint8_t *buffer, size_t size, nl_cb_t callback, void *arg)
{
	struct sockaddr_nl nl_addr = {
		.nl_family = AF_NETLINK,
	};
	socklen_t nl_addrlen = sizeof(nl_addr);

	do {
		ssize_t nbytes = recvfrom(sock, buffer, size, 0, (struct sockaddr *) &nl_addr, &nl_addrlen);

		if (nbytes < 0) {
			plog_err("Cannot recv a response(RTM_GETROUTE) from Netlink");
			return -1;
		}

		if (nbytes == 0) {
			return 0;
		}

		struct nlmsghdr *nlh = (struct nlmsghdr *) buffer;

		while (NLMSG_OK(nlh, nbytes)) {
			// TODO: проверка на portid и seq, но в условиях, когда сокет создан ровно под 1 запрос, это можно опустить.

			if (nlh->nlmsg_flags & NLM_F_DUMP_INTR) {
				errno = EINTR;
				plog_err("Cannot recv a response(RTM_GETROUTE) from Netlink");
				return -1;
			}

			switch (nlh->nlmsg_type) {
				case NLMSG_ERROR: {
					const struct nlmsgerr *err = nlmsg_extraheader(nlh);
					errno = (err->error < 0) ? -err->error : err->error; // в общем случае может быть любой знак.

					if (err->error) {
						plog_err("Netlink received error");
						return -1;
					}

					return 0;
				}

				case NLMSG_DONE:
					// FIXME: в соответствии с man 7 netlink этот тип ставится только на multipart-сообщениях
					// Поэтому цикл обработки вообще говоря должен быть другим - надо отдельно держать флаг приема
					// multipart-сообщения и отлавливать NLMSG_DONE только в этом случае. И тогда весь цикл do/while
					// переписывается и становится проще.
					// Но на это забили даже в libnl/libmnl.
					return 0;

				case NLMSG_NOOP:
				case NLMSG_OVERRUN:
					break;

				default:
					if (callback(nlh, arg))
						return -1;

					break;
			}

			nbytes -= NLMSG_ALIGN(nlh->nlmsg_len);
			nlh = (struct nlmsghdr *) (((uint8_t *) nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
		}

		if ((nlh->nlmsg_flags & NLM_F_MULTI) == 0) {
			// Сообщение пришло цельным куском, дальше нечего обрабатывать
			return 0;
		}

		// FIXME: чтобы корректно обрабатывать multipart сообщения, стоит предполагать, что сообщение может быть
		// фрагментировано между двумя recvfrom. Соответственно, нужно после полной обработки последнего сообщения
		// проверить, не осталось ли данных в хвосте буфера. Если осталось, то их нужно переместить (memmove) в начало
		// буфера, затем продолжить recvfrom, но с учетом остаточных данных в его начале (т.е.
		// recvfrom(nl_sock, buffer + offset, size - offset, ...)).
		// А еще по-хорошему стоит комбинировать MSG_TRUNC + MSG_PEEK, чтобы гарантировать, что датаграмма не будет
		// порезана.
		// Но судя по всему, здесь такая ситуация невозможна в принципе, особенно при условии буфера размером в 8К.
	} while (1);
}


static int parse_rtm_getroute(struct nlmsghdr *nlh, void *arg)
{
	struct route_info *info = arg;
	struct rtmsg *rtm = nlmsg_extraheader(nlh);
	int len = RTM_PAYLOAD(nlh);

	assert(rtm->rtm_family == info->af);

	for (struct rtattr *rta = (struct rtattr *) RTM_RTA(rtm); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		const void *data = RTA_DATA(rta);

		switch (rta->rta_type) {
			case RTA_SRC:
			case RTA_PREFSRC:
				memcpy(&info->src, data, RTA_PAYLOAD(rta));
				break;

			case RTA_OIF:
				info->ifindex = *(int32_t *) data;
				break;
		}
	}

	return 0;
}

int fetch_route_info(struct route_info *info)
{
	assert(info);
	assert(info->af == AF_INET || info->af == AF_INET6);
	assert(!is_addr_empty(info->af, &info->dst));

	struct sockaddr_nl nl_addr = {
		.nl_family = AF_NETLINK,
	};

	int ret = -1;
	int nl_sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);

	if (nl_sock < 0) {
		plog_err("Cannot open a socket to Netlink");
		return -1;
	}

	if (bind(nl_sock, (struct sockaddr *) &nl_addr, sizeof(nl_addr)) < 0) {
		plog_err("Cannot bind a socket to Netlink");
		goto out;
	}

	uint8_t buffer[8192]; // Netlink оперирует сообщениями максимум в 8К
	struct nlmsghdr *nlh = (struct nlmsghdr *) buffer;

	memset(buffer, 0, sizeof(buffer));
	nl_prepare_request(nlh, info);

	if (nl_send(nl_sock, nlh) < 0)
		goto out;

	if (nl_recv(nl_sock, buffer, sizeof(buffer), parse_rtm_getroute, info))
		goto out;

	ret = 0;

out:
	close(nl_sock);
	return ret;
}
